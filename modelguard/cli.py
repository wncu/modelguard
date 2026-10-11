"""Never imports model code, loads tensors, unpickles or executes tools."""
import argparse
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen

from .formats import check_gguf, check_safetensors, sniff
from .pickle_scan import scan_file, scan_npy

LIMIT = 2 * 1024 * 1024

def findings(names):
    result = []
    for name in names:
        suffix = Path(name).suffix.lower()
        if suffix in {'.pkl', '.pickle', '.pt', '.pth', '.bin'}:
            result.append({'rule': 'MG001', 'severity': 'review', 'file': name,
                           'message': 'Potential executable serialization; extension alone cannot identify malicious content.'})
        if suffix in {'.py', '.sh', '.so', '.dll', '.exe'}:
            result.append({'rule': 'MG002', 'severity': 'review', 'file': name,
                           'message': 'Code or native executable present; not executed or inspected by this rule.'})
    return result

EXPECTED = {'.safetensors': 'safetensors', '.gguf': 'gguf', '.npy': 'npy'}


def content_findings(path, name, size):
    """Static checks chosen by content signature, not extension. Never executes content."""
    out = []
    suffix = path.suffix.lower()
    kind = sniff(path, size)
    expected = EXPECTED.get(suffix)
    if expected and kind != expected:
        out.append({'rule': 'MG010', 'severity': 'high' if kind in ('pickle', 'zip') else 'review', 'file': name,
                    'message': f'Extension {suffix} but content signature is {kind or "unknown"}'})
    if kind == 'safetensors' or (suffix == '.safetensors' and kind is None):
        for issue in check_safetensors(path, size):
            out.append({'rule': 'MG008', 'severity': 'review', 'file': name, 'message': 'safetensors: ' + issue})
    elif kind == 'gguf' or (suffix == '.gguf' and kind is None):
        for issue in check_gguf(path, size)[0]:
            out.append({'rule': 'MG009', 'severity': 'review', 'file': name, 'message': 'GGUF: ' + issue})
    elif kind in ('pickle', 'zip', 'npy'):
        result = scan_npy(path) if kind == 'npy' else scan_file(path)
        if result:
            found, notes, label_kind = result
            high, review = {}, {}
            for module, attr, sev in found:
                if sev == 'high':
                    high.setdefault(f'{module}.{attr}', None)
                elif sev:
                    review.setdefault(module.split('.')[0], {})[f'{module}.{attr}'] = None
            for target in high:
                out.append({'rule': 'MG006', 'severity': 'high', 'file': name,
                            'message': f'Dangerous global in {label_kind} stream: {target} (static opcode scan, not executed)'})
            for package, names in review.items():
                shown = ', '.join(list(names)[:4]) + (f' (+{len(names) - 4} more)' if len(names) > 4 else '')
                out.append({'rule': 'MG006', 'severity': 'review', 'file': name,
                            'message': f'{label_kind} stream imports {len(names)} non-allowlisted global(s) from package {package!r}: {shown}. Loading would run code from that package.'})
            for note in dict.fromkeys(notes):
                out.append({'rule': 'MG007', 'severity': 'review', 'file': name, 'message': note})
    return out


def base(target):
    return {'schema_version': '1.0', 'scanner_version': '0.1.0',
            'created_at': datetime.now(timezone.utc).isoformat(), 'target': target,
            'status': 'insufficient_evidence', 'files': [], 'findings': [],
            'coverage': {'inventory': False, 'static_formats': False, 'content': False, 'behavior': False, 'weights': False},
            'limitations': ['No malware certification.', 'No backdoor detection or inference performed.',
                            'Hashes identify bytes; they do not establish trust.']}

def sha256_file(path):
    """Stream SHA-256 with one reusable 1 MiB buffer and without filling the page cache."""
    h = hashlib.sha256()
    buf = bytearray(1024 * 1024)
    view = memoryview(buf)
    with open(path, 'rb', buffering=0) as stream:
        while True:
            n = stream.readinto(buf)
            if not n:
                break
            h.update(view[:n])
            if hasattr(os, 'posix_fadvise'):
                try:
                    os.posix_fadvise(stream.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
                except OSError:
                    pass
    return h.hexdigest()


def local_scan(target, hashes=False):
    root = Path(target)
    if root.is_symlink() or not root.exists():
        raise ValueError('Target must exist and cannot be a symlink')
    report = base(str(root))
    paths = [root] if root.is_file() else sorted(root.rglob('*'))
    for path in paths:
        if path.is_symlink():
            report['findings'].append({'rule': 'MG003', 'severity': 'review', 'file': str(path), 'message': 'Symlink skipped'})
            continue
        if not path.is_file():
            continue
        name = path.name if root.is_file() else path.relative_to(root).as_posix()
        item = {'path': name, 'size': path.stat().st_size}
        if hashes:
            item['sha256'] = sha256_file(path)
        report['files'].append(item)
        try:
            report['findings'] += content_findings(path, name, item['size'])
        except OSError as exc:
            report['limitations'].append(f'Could not read {name}: {type(exc).__name__}')
        if path.name == 'config.json':
            if item['size'] > LIMIT:
                report['limitations'].append('Oversized config skipped: ' + name)
            else:
                try:
                    config = json.loads(path.read_text(encoding='utf-8'))
                    if isinstance(config, dict) and config.get('auto_map'):
                        report['findings'].append({'rule': 'MG004', 'severity': 'review', 'file': name,
                                                  'message': 'auto_map references custom code; review before enabling trust_remote_code.'})
                except (ValueError, UnicodeError):
                    report['findings'].append({'rule': 'MG005', 'severity': 'review', 'file': name, 'message': 'Invalid config JSON'})
    report['findings'] += findings(x['path'] for x in report['files'])
    report['coverage']['inventory'] = True
    report['coverage']['static_formats'] = True
    report['limitations'].append('Static checks only: config.json, pickle opcodes, safetensors/GGUF headers. Pickle allowlist may miss novel gadgets; no tensor or behavior analysis. Symlink races are outside this MVP threat model; scan immutable copies.')
    return report

def hub_scan(repo, revision='main'):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo):
        raise ValueError('Expected owner/model, not an arbitrary URL')
    url = 'https://huggingface.co/api/models/' + repo + '/revision/' + quote(revision, safe='')
    req = Request(url + '?blobs=true', headers={'User-Agent': 'modelguard/0.1.0'})
    with urlopen(req, timeout=30) as response:
        raw = response.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError('Metadata exceeds 2 MiB limit; incomplete scan')
    data = json.loads(raw)
    sha = data.get('sha')
    if not isinstance(sha, str) or not re.fullmatch(r'[0-9a-f]{40}', sha):
        raise ValueError('Hub did not return an immutable commit SHA')
    report = base(repo)
    report['revision'] = sha
    report['files'] = [{'path': f['rfilename'], 'size': f.get('size'),
                        'declared_lfs_sha256': (f.get('lfs') or {}).get('sha256')}
                       for f in data.get('siblings', [])]
    report['findings'] = findings(x['path'] for x in report['files'])
    report['coverage']['inventory'] = True
    report['limitations'].append('Hub metadata only. Declared hashes are not locally verified. No weights or repository code downloaded. No private tokens supported.')
    return report

def verify(target, repo, revision='main', partial=False):
    """Compare locally computed SHA-256 with Hub-declared LFS hashes. Non-LFS files cannot be compared by SHA-256."""
    local = local_scan(target, True)
    remote = hub_scan(repo, revision)
    local['revision'] = remote['revision']
    local['limitations'].append(f'Compared against Hub {repo} at {remote["revision"]}; only LFS files carry a SHA-256 to compare.')
    declared = {f['path']: f for f in remote['files']}
    present = {f['path']: f for f in local['files']}
    compared = 0
    for path, item in present.items():
        ref = declared.get(path)
        if ref is None:
            local['findings'].append({'rule': 'MG012', 'severity': 'review', 'file': path,
                                      'message': 'File not present in the Hub revision'})
        elif ref.get('declared_lfs_sha256'):
            compared += 1
            if ref['declared_lfs_sha256'] != item.get('sha256'):
                local['findings'].append({'rule': 'MG011', 'severity': 'high', 'file': path,
                                          'message': 'SHA-256 differs from the hash declared by the Hub'})
    for path in declared:
        if path not in present and not partial:
            local['findings'].append({'rule': 'MG012', 'severity': 'review', 'file': path,
                                      'message': 'Hub file missing locally'})
    local['limitations'].append(f'{compared} file(s) compared by SHA-256; others unverifiable by this method.')
    return local


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    local = sub.add_parser('scan', help='Inspect a local file or directory')
    local.add_argument('target')
    local.add_argument('--hash', action='store_true', help='Stream SHA-256 over all local files; may take hours')
    ver = sub.add_parser('verify', help='Compare a local copy with the Hub revision (LFS SHA-256)')
    ver.add_argument('target')
    ver.add_argument('repo')
    ver.add_argument('--revision', default='main')
    ver.add_argument('--partial', action='store_true', help='Do not report Hub files missing locally')
    hub = sub.add_parser('hub', help='Inspect public Hub metadata without downloading weights')
    hub.add_argument('target')
    hub.add_argument('--revision', default='main')
    for p in (local, hub, ver):
        p.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:  # be a polite background citizen: lowest CPU priority, idle I/O class where available
        os.nice(15)
    except (OSError, AttributeError):
        pass
    try:
        if args.mode == 'scan':
            result = local_scan(args.target, args.hash)
        elif args.mode == 'verify':
            result = verify(args.target, args.repo, args.revision, args.partial)
        else:
            result = hub_scan(args.target, args.revision)
        text = json.dumps(result, ensure_ascii=False, indent=2)
        if args.output:
            args.output.write_text(text + '\n', encoding='utf-8')
        else:
            print(text)
    except (OSError, ValueError) as exc:
        parser.exit(2, f'Incomplete scan: {exc}\n')

if __name__ == '__main__':
    main()
