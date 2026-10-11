"""Never imports model code, loads tensors, unpickles, renders templates or executes tools."""
import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .formats import check_gguf, check_safetensors, sniff
from .pickle_scan import scan_file
from .textscan import MAX_PY, check_python, check_template

LIMIT = 2 * 1024 * 1024
HASH_CHUNK = 1024 * 1024
SEVERITY_ORDER = {'review': 1, 'high': 2}
EXECUTABLE_SERIALIZATION = {'.pkl', '.pickle', '.pt', '.pth', '.bin', '.ckpt', '.joblib', '.npy', '.npz', '.h5',
                            '.keras', '.mar', '.nemo'}
PICKLE_CANDIDATES = {'.pkl', '.pickle', '.pt', '.pth', '.bin', '.ckpt', '.joblib', '.npy', '.npz', '.mar', '.nemo'}
CODE_SUFFIXES = {'.py', '.pyc', '.pyo', '.pyd', '.sh', '.bash', '.bat', '.cmd', '.ps1', '.so', '.dll', '.dylib',
                 '.exe', '.js', '.jar'}
ARCHIVE_SUFFIXES = {'.7z', '.rar', '.tar', '.tgz', '.gz', '.bz2', '.xz', '.zst', '.lz4'}
EXPECTED = {'.safetensors': 'safetensors', '.gguf': 'gguf', '.npy': 'npy', '.npz': 'zip', '.pt': None}
AUTO_MAP_FILES = {'config.json', 'tokenizer_config.json', 'preprocessor_config.json', 'processor_config.json',
                  'feature_extractor_config.json', 'image_processor_config.json', 'video_preprocessor_config.json'}
TEMPLATE_FILES = {'chat_template.jinja', 'chat_template.json'}
SKIP_DIRS = {'.git', '__pycache__', '.no_exist'}  # .no_exist: empty HF cache markers for absent files
HF_META_DIR = ('.cache', 'huggingface')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')


def finding(rule, severity, file, message):
    return {'rule': rule, 'severity': severity, 'file': file, 'message': message}


def findings(names):
    """Extension-only review signals, used for local files and Hub listings alike."""
    result = []
    for name in names:
        suffix = Path(name).suffix.lower()
        if suffix in EXECUTABLE_SERIALIZATION:
            result.append(finding('MG001', 'review', name, 'Potential executable serialization; extension alone '
                                  'cannot identify malicious content.'))
        if suffix in ARCHIVE_SUFFIXES:
            result.append(finding('MG016', 'review', name, 'Archive format not inspected; extract it and scan the '
                                  'contents.'))
        if suffix in CODE_SUFFIXES:
            result.append(finding('MG002', 'review', name, 'Code or native executable present; it is never executed '
                                  'by ModelGuard.'))
    return result


def _pickle_findings(result, name):
    out = []
    high, review = {}, {}
    for module, attr, sev in result.found:
        if sev == 'high':
            high.setdefault(f'{module}.{attr}', None)
        elif sev:
            review.setdefault(module.split('.')[0], {})[f'{module}.{attr}'] = None
    for target in high:
        out.append(finding('MG006', 'high', name, f'Dangerous global in {result.kind} stream: {target} '
                           '(static opcode scan, not executed)'))
    for package, names in review.items():
        shown = ', '.join(list(names)[:4]) + (f' (+{len(names) - 4} more)' if len(names) > 4 else '')
        out.append(finding('MG006', 'review', name, f'{result.kind} stream imports {len(names)} non-allowlisted '
                           f"global(s) from package '{package}': {shown}. Loading would run code from that package."))
    for note in dict.fromkeys(result.notes):
        out.append(finding('MG007', 'review', name, note))
    for rule, sev, message in result.flags:
        out.append(finding(rule, sev, name, message))
    return out


def _template_findings(text, name, where):
    return [finding('MG015', sev, name, f'Chat template ({where}): {reason}. Templates are rendered by the '
                    'inference runtime; unsandboxed Jinja can execute code.') for sev, reason in check_template(text)]


def _read_small(path, size):
    if size > LIMIT:
        return None
    return path.read_bytes()


def content_findings(path, name, size):
    """Static checks chosen by content signature first, extension second. Never executes content."""
    out = []
    suffix = path.suffix.lower()
    base_name = path.name
    kind = sniff(path, size) if size else None
    expected = EXPECTED.get(suffix)
    if expected and kind != expected:
        out.append(finding('MG010', 'high' if kind in ('pickle', 'zip') else 'review', name,
                           f'Extension {suffix} but content signature is {kind or "unknown"}'))
    if kind == 'safetensors' or (suffix == '.safetensors' and kind is None and size):
        out += [finding('MG008', 'review', name, 'safetensors: ' + i) for i in check_safetensors(path, size)]
    elif kind == 'gguf' or (suffix == '.gguf' and kind is None and size):
        issues, info = check_gguf(path, size)
        out += [finding('MG009', 'review', name, 'GGUF: ' + i) for i in issues]
        for key, text in info.get('chat_templates', {}).items():
            out += _template_findings(text, name, key)
    elif kind in ('pickle', 'zip', 'npy') or (suffix in PICKLE_CANDIDATES and size):
        result = scan_file(path, strict=None if kind else False)
        if result is not None:
            out += _pickle_findings(result, name)
    if suffix == '.py' and size:
        if size > MAX_PY:
            out.append(finding('MG013', 'review', name, 'Python file larger than 1 MiB; not parsed'))
        else:
            verdict = check_python(path.read_bytes())
            if verdict:
                out.append(finding('MG013', verdict[0], name, 'Python code uses: ' + verdict[1]))
    if base_name in AUTO_MAP_FILES or base_name in TEMPLATE_FILES:
        out += _config_findings(path, name, size)
    return out


def _config_findings(path, name, size):
    raw = _read_small(path, size)
    if raw is None:
        return [finding('MG005', 'review', name, 'Config larger than 2 MiB; not inspected')]
    if path.name == 'chat_template.jinja':
        return _template_findings(raw.decode('utf-8', 'replace'), name, path.name)
    try:
        config = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        return [finding('MG005', 'review', name, 'Invalid JSON')]
    out = []
    if not isinstance(config, dict):
        return out
    if config.get('auto_map'):
        out.append(finding('MG004', 'review', name, 'auto_map references custom code; review the referenced '
                           'Python files before enabling trust_remote_code.'))
    if config.get('custom_pipelines'):
        out.append(finding('MG004', 'review', name, 'custom_pipelines references custom code.'))
    templates = config.get('chat_template')
    if isinstance(templates, str):
        out += _template_findings(templates, name, 'chat_template')
    elif isinstance(templates, list):
        for item in templates:
            if isinstance(item, dict) and isinstance(item.get('template'), str):
                out += _template_findings(item['template'], name, f"chat_template:{item.get('name', '?')}")
    return out


def base(target):
    return {'schema_version': '1.0', 'scanner_version': __version__,
            'created_at': datetime.now(timezone.utc).isoformat(), 'target': target,
            'status': 'insufficient_evidence', 'files': [], 'findings': [],
            'coverage': {'inventory': False, 'static_formats': False, 'content': False, 'behavior': False,
                         'weights': False},
            'limitations': ['No malware certification.', 'No backdoor detection or inference performed.',
                            'Hashes identify bytes; they do not establish trust.']}


def sha256_file(path):
    """Stream SHA-256 with one reusable buffer and drop the pages behind us so the page cache is not flooded."""
    h = hashlib.sha256()
    buf = bytearray(HASH_CHUNK)
    view = memoryview(buf)
    advise = getattr(os, 'posix_fadvise', None)
    with open(path, 'rb', buffering=0) as stream:
        fd, done, dropped = stream.fileno(), 0, 0
        if advise:
            try:
                advise(fd, 0, 0, os.POSIX_FADV_SEQUENTIAL)
            except OSError:
                advise = None
        while True:
            n = stream.readinto(buf)
            if not n:
                break
            h.update(view[:n])
            done += n
            if advise and done - dropped >= 64 * 1024 * 1024:
                advise(fd, dropped, done - dropped, os.POSIX_FADV_DONTNEED)
                dropped = done
        if advise and done > dropped:
            advise(fd, dropped, done - dropped, os.POSIX_FADV_DONTNEED)
    return h.hexdigest()


HF_REPO_PREFIXES = ('models--', 'datasets--', 'spaces--')


def _hf_hub_root(path):
    """Return the Hugging Face hub cache root if path lies inside a cached repo (…/hub/models--org--name/…)."""
    for parent in path.parents:
        if parent.name.startswith(HF_REPO_PREFIXES):
            return parent.parent
    return None


def _resolve(path, limit=40):
    """Follow a symlink chain without trusting it. Returns (final_path, hops) or (None, hops) if broken/looping."""
    hops, current = [path], path
    for _ in range(limit):
        if not current.is_symlink():
            return current, hops
        current = Path(os.path.normpath(current.parent / os.readlink(current)))
        hops.append(current)
    return None, hops


def _expected_blob_sha(hops):
    """In the HF cache, <repo>/blobs/<sha256> names LFS content by its SHA-256 (xet stores keep other names)."""
    for hop in hops:
        if hop.parent.name == 'blobs' and hop.parent.parent.name.startswith(HF_REPO_PREFIXES) and HEX64.match(hop.name):
            return hop.name
    return None


def _iter_files(root, follow, report):
    """Yield (path, relative_name, real_path, hops) in sorted order without following directory symlinks."""
    if root.is_file():
        yield root, root.name, root, [root]
        return
    skipped = set()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        rel_dir = here.relative_to(root)
        keep = []
        for d in sorted(dirnames):
            full = here / d
            if d in SKIP_DIRS:
                skipped.add(d)
            elif full.is_symlink():
                report['findings'].append(finding('MG003', 'review', (rel_dir / d).as_posix(),
                                                  'Directory symlink not followed'))
            else:
                keep.append(d)
        dirnames[:] = keep
        for f in sorted(filenames):
            full = here / f
            rel = (rel_dir / f).as_posix()
            if not full.is_symlink():
                yield full, rel, full, [full]
                continue
            real, hops = _resolve(full)
            if real is None or not real.exists():
                report['findings'].append(finding('MG003', 'review', rel, 'Broken or looping symlink skipped'))
                continue
            hub = _hf_hub_root(full)
            inside_hub = hub is not None and hub in real.parents
            if (follow or inside_hub) and real.is_file():
                yield full, rel, real, hops
            else:
                report['findings'].append(finding('MG003', 'review', rel, 'Symlink skipped (use --follow-symlinks '
                                                  'to inspect its target)'))
    if skipped:
        report['limitations'].append('Skipped directories: ' + ', '.join(sorted(skipped)) +
                                     ' (git objects duplicate tracked files; scan a clean checkout or export).')


def local_scan(target, hashes=False, follow=False, jobs=1):
    root = Path(target)
    if root.is_symlink() or not root.exists():
        raise ValueError('Target must exist and cannot be a symlink')
    started = time.monotonic()
    report = base(str(root))
    entries, seen = [], {}
    for path, name, real, hops in _iter_files(root, follow, report):
        try:
            st = real.stat()
        except OSError as exc:
            report['findings'].append(finding('MG007', 'review', name, f'File not inspected: {exc.strerror or exc}'))
            continue
        if not os.path.isfile(real):          # FIFOs, devices: never opened
            continue
        item = {'path': name, 'size': st.st_size}
        if real != path:
            item['symlink_target'] = str(real)
        key = (st.st_dev, st.st_ino)
        first = seen.setdefault(key, item)    # same bytes via symlink/hardlink: inspect once
        if first is not item:
            item['same_as'] = first['path']
        report['files'].append(item)
        entries.append((item, real, hops, first))
    unique = [(item, real, hops) for item, real, hops, first in entries if first is item]
    if hashes:
        _hash_all(unique, jobs, report)
        for item, _, _, first in entries:
            if first is not item and 'sha256' in first:
                item['sha256'] = first['sha256']
    total = 0
    for item, real, _ in unique:
        total += item['size']
        try:
            report['findings'] += content_findings(real, item['path'], item['size'])
        except OSError as exc:
            report['limitations'].append(f"Could not read {item['path']}: {type(exc).__name__}")
            report['findings'].append(finding('MG007', 'review', item['path'],
                                              f'File not inspected: {exc.strerror or exc}'))
        except Exception as exc:          # a parser bug on one hostile file must never abort the whole scan
            report['findings'].append(finding('MG007', 'review', item['path'],
                                              f'Inspection error ({type(exc).__name__}); file not fully inspected'))
    report['findings'] += findings(x['path'] for x in report['files'] if 'same_as' not in x)
    report['coverage']['inventory'] = True
    report['coverage']['static_formats'] = True
    report['limitations'].append('Static checks only: pickle opcodes (raw, PyTorch zip, npy/npz), safetensors/GGUF '
                                 'structure, chat templates, config auto_map and Python AST. Pickle allowlist may '
                                 'miss novel gadgets; no tensor or behavior analysis. Symlink races are outside this '
                                 'threat model; scan immutable copies.')
    report['summary'] = _summary(report, total, started)
    return report


def _hash_all(unique, jobs, report):
    """Hash files sequentially (default, lightest) or with a small thread pool; hashlib releases the GIL."""
    def work(entry):
        item, real, hops = entry
        try:
            return entry, sha256_file(real), None
        except OSError as exc:
            return entry, None, exc

    if jobs > 1 and len(unique) > 1:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            results = list(pool.map(work, unique))
    else:
        results = map(work, unique)
    for (item, real, hops), digest, exc in results:
        if exc is not None:
            report['findings'].append(finding('MG007', 'review', item['path'],
                                              f'File not hashed: {exc.strerror or exc}'))
            continue
        item['sha256'] = digest
        expected = _expected_blob_sha(hops)
        if expected and expected != digest:
            report['findings'].append(finding('MG011', 'high', item['path'], 'Hugging Face cache blob content does '
                                              'not match its SHA-256 name'))


def _summary(report, total_bytes, started):
    counts = {'high': 0, 'review': 0}
    for f in report['findings']:
        counts[f['severity']] = counts.get(f['severity'], 0) + 1
    return {'files': len(report['files']), 'bytes': total_bytes, 'findings_high': counts['high'],
            'findings_review': counts['review'], 'elapsed_seconds': round(time.monotonic() - started, 3)}


def _redirect_handler():
    """urllib is imported lazily: it pulls in ssl/http/email, which local scans never need."""
    from urllib.error import HTTPError
    from urllib.parse import urlsplit
    from urllib.request import HTTPRedirectHandler

    class HubOnlyRedirects(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            parts = urlsplit(newurl)
            if parts.scheme != 'https' or parts.hostname != 'huggingface.co':
                raise HTTPError(newurl, code, 'Redirect away from https://huggingface.co refused', headers, fp)
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    return HubOnlyRedirects()


def _fetch(url):
    """GET a Hub API URL with a 2 MiB cap; redirects may only stay on https://huggingface.co."""
    from urllib.request import Request, build_opener
    req = Request(url, headers={'User-Agent': f'modelguard/{__version__}'})
    with build_opener(_redirect_handler()).open(req, timeout=30) as response:
        raw = response.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError('Metadata exceeds 2 MiB limit; incomplete scan')
    return raw


def hub_scan(repo, revision='main'):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo) or '..' in repo:
        raise ValueError('Expected owner/model, not an arbitrary URL')
    started = time.monotonic()
    from urllib.parse import quote
    raw = _fetch('https://huggingface.co/api/models/' + repo + '/revision/' + quote(revision, safe='') + '?blobs=true')
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError('Unexpected Hub response')
    sha = data.get('sha')
    if not isinstance(sha, str) or not re.fullmatch(r'[0-9a-f]{40}', sha):
        raise ValueError('Hub did not return an immutable commit SHA')
    siblings = data.get('siblings')
    if not isinstance(siblings, list):
        raise ValueError('Hub response has no file list')
    report = base(repo)
    report['revision'] = sha
    for f in siblings:
        if not isinstance(f, dict) or not isinstance(f.get('rfilename'), str):
            continue
        size = f.get('size')
        lfs = f.get('lfs') if isinstance(f.get('lfs'), dict) else {}
        digest = lfs.get('sha256')
        report['files'].append({'path': f['rfilename'], 'size': size if isinstance(size, int) and size >= 0 else None,
                                'declared_lfs_sha256': digest if isinstance(digest, str) and HEX64.match(digest)
                                else None})
    report['findings'] = findings(x['path'] for x in report['files'])
    report['coverage']['inventory'] = True
    report['limitations'].append('Hub metadata only. Declared hashes are not locally verified. No weights or '
                                 'repository code downloaded. No private tokens supported.')
    report['summary'] = _summary(report, sum(x['size'] or 0 for x in report['files']), started)
    return report


def verify(target, repo, revision='main', partial=False, follow=False, jobs=1):
    """Compare locally computed SHA-256 with Hub-declared LFS hashes. Non-LFS files cannot be compared by SHA-256."""
    remote = hub_scan(repo, revision)          # cheap and may fail: do it before hours of hashing
    started = time.monotonic()
    local = local_scan(target, True, follow, jobs)
    local['revision'] = remote['revision']
    declared = {f['path']: f for f in remote['files']}
    present = {f['path']: f for f in local['files'] if not f['path'].startswith('/'.join(HF_META_DIR) + '/')}
    compared = 0
    for path, item in present.items():
        ref = declared.get(path)
        if ref is None:
            local['findings'].append(finding('MG012', 'review', path, 'File not present in the Hub revision'))
        elif ref.get('declared_lfs_sha256'):
            compared += 1
            if ref['declared_lfs_sha256'] != item.get('sha256'):
                local['findings'].append(finding('MG011', 'high', path, 'SHA-256 differs from the hash declared by '
                                                 'the Hub'))
        elif ref.get('size') is not None and ref['size'] != item['size']:
            local['findings'].append(finding('MG011', 'high', path, 'Size differs from the size declared by the Hub'))
    if not partial:
        for path in declared:
            if path not in present:
                local['findings'].append(finding('MG012', 'review', path, 'Hub file missing locally'))
    local['limitations'].append(f'Compared against Hub {repo} at {remote["revision"]}: {compared} file(s) by '
                                'SHA-256; non-LFS files by size only.')
    local['summary'] = _summary(local, local['summary']['bytes'], started)
    return local


def _lower_priority():
    """Lowest CPU priority; on Linux the I/O priority follows the nice value (best-effort class, level 7)."""
    try:
        os.nice(19 - os.nice(0))
    except (OSError, AttributeError):
        pass


def _text(report):
    lines = [f"ModelGuard {report['scanner_version']} · {report['target']}" +
             (f" @ {report['revision'][:12]}" if report.get('revision') else '')]
    order = sorted(report['findings'], key=lambda f: (-SEVERITY_ORDER.get(f['severity'], 0), f['file'], f['rule']))
    for f in order:
        lines.append(f"  {f['severity'].upper():6} {f['rule']}  {f['file']}: {f['message']}")
    s = report.get('summary', {})
    lines.append(f"{s.get('files', len(report['files']))} files, {s.get('findings_high', 0)} high, "
                 f"{s.get('findings_review', 0)} review, {s.get('elapsed_seconds', 0)} s. "
                 'Status: insufficient_evidence (no finding is not proof of safety).')
    return '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(prog='modelguard', description=__doc__)
    parser.add_argument('--version', action='version', version=f'modelguard {__version__}')
    sub = parser.add_subparsers(dest='mode', required=True)
    local = sub.add_parser('scan', help='Inspect a local file or directory')
    local.add_argument('target')
    local.add_argument('--hash', action='store_true', help='Stream SHA-256 over all local files (reads every byte)')
    ver = sub.add_parser('verify', help='Compare a local copy with the Hub revision (LFS SHA-256)')
    ver.add_argument('target')
    ver.add_argument('repo')
    ver.add_argument('--revision', default='main')
    ver.add_argument('--partial', action='store_true', help='Do not report Hub files missing locally')
    sub.add_parser('mcp', help='Run the Model Context Protocol server on stdio (for Claude Code, IDEs)')
    hub = sub.add_parser('hub', help='Inspect public Hub metadata without downloading weights')
    hub.add_argument('target')
    hub.add_argument('--revision', default='main')
    for p in (local, ver):
        p.add_argument('--jobs', type=int, default=1, metavar='N', help='Hash N files in parallel (default 1: '
                       'lightest; SHA-256 is CPU-bound)')
        p.add_argument('--follow-symlinks', action='store_true', help='Inspect symlinked files (HF cache blobs are '
                       'always followed)')
    for p in (local, hub, ver):
        p.add_argument('--output', type=Path, help='Write the JSON report to this file')
        p.add_argument('--format', choices=('json', 'text'), default='json', help='stdout format')
        p.add_argument('--fail-on', choices=('review', 'high'), help='Exit 1 if a finding of this severity or '
                       'higher exists (for CI)')
    args = parser.parse_args(argv)
    if args.mode == 'mcp':
        from .mcp import main as mcp_main
        return mcp_main()
    _lower_priority()
    try:
        if args.mode == 'scan':
            result = local_scan(args.target, args.hash, args.follow_symlinks, max(1, args.jobs))
        elif args.mode == 'verify':
            result = verify(args.target, args.repo, args.revision, args.partial, args.follow_symlinks,
                            max(1, args.jobs))
        else:
            result = hub_scan(args.target, args.revision)
        text = json.dumps(result, ensure_ascii=False, indent=2)
        if args.output:
            args.output.write_text(text + '\n', encoding='utf-8')
        if args.format == 'text':
            print(_text(result))
        elif not args.output:
            print(text)
    except (OSError, ValueError) as exc:
        parser.exit(2, f'Incomplete scan: {exc}\n')
    except KeyboardInterrupt:
        parser.exit(130, 'Interrupted\n')
    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER.get(f['severity'], 0) >= threshold for f in result['findings']):
            sys.exit(1)


if __name__ == '__main__':
    main()
