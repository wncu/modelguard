import contextlib
import hashlib
import io
import json
import os
import pickle
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from modelguard import cli
from modelguard.cli import LIMIT, hub_scan, local_scan, main, verify


class Evil:
    def __reduce__(self):
        return (os.system, ('echo no',))


def rules(report):
    return {(f['rule'], f['severity']) for f in report['findings']}


def fake_hub(payload):
    """Patch the Hub fetch to return payload (dict or raw bytes)."""
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    ctx = patch.object(cli, '_fetch', return_value=body)
    ctx.start()
    return ctx


class ScanTests(unittest.TestCase):
    def test_inventory_hash_and_custom_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'config.json').write_text(json.dumps({'auto_map': {'AutoModel': 'evil.Model'}}))
            (p / 'tokenizer_config.json').write_text(json.dumps({'auto_map': {'AutoTokenizer': ['t.T', None]}}))
            (p / 'weights.pkl').write_bytes(b'not executed')
            (p / 'remote.py').write_text("raise RuntimeError('must never execute')")
            report = local_scan(tmp, True)
            self.assertEqual(report['status'], 'insufficient_evidence')
            self.assertFalse(report['coverage']['behavior'])
            self.assertTrue({('MG001', 'review'), ('MG002', 'review'), ('MG004', 'review')} <= rules(report))
            self.assertEqual(sum(f['rule'] == 'MG004' for f in report['findings']), 2)
            item = next(x for x in report['files'] if x['path'] == 'weights.pkl')
            self.assertEqual(item['sha256'], hashlib.sha256(b'not executed').hexdigest())
            self.assertEqual(report['summary']['files'], 4)

    def test_symlinks_skipped_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'link').symlink_to('/etc/passwd')
            (p / 'dirlink').symlink_to('/etc')
            r = local_scan(tmp, True)
            self.assertEqual(r['files'], [])
            self.assertEqual({f['file'] for f in r['findings'] if f['rule'] == 'MG003'}, {'link', 'dirlink'})

    def test_follow_symlinks_flag(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as other:
            target = Path(other) / 'model.pkl'
            target.write_bytes(pickle.dumps(Evil()))
            (Path(tmp) / 'model.pkl').symlink_to(target)
            r = local_scan(tmp, follow=True)
            self.assertIn(('MG006', 'high'), rules(r))
            self.assertEqual(r['files'][0]['symlink_target'], str(target.resolve()))

    def test_huggingface_cache_layout_followed_and_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / 'models--org--name'
            blobs, snap = repo / 'blobs', repo / 'snapshots' / ('a' * 40)
            blobs.mkdir(parents=True)
            snap.mkdir(parents=True)
            good = b'weights'
            (blobs / hashlib.sha256(good).hexdigest()).write_bytes(good)
            (blobs / ('0' * 64)).write_bytes(b'tampered')
            (snap / 'model.bin').symlink_to(blobs / hashlib.sha256(good).hexdigest())
            (snap / 'other.bin').symlink_to(blobs / ('0' * 64))
            r = local_scan(str(snap), True)
            self.assertEqual(sorted(f['path'] for f in r['files']), ['model.bin', 'other.bin'])
            self.assertEqual([f['file'] for f in r['findings'] if f['rule'] == 'MG011'], ['other.bin'])

    def test_huggingface_xet_store_layout(self):
        """Repo blobs may themselves link into hub/blobs/<xx>/<xet hash>; the repo-level name is the SHA-256."""
        with tempfile.TemporaryDirectory() as tmp:
            hub = Path(tmp) / 'hub'
            store = hub / 'blobs' / 'ab'
            store.mkdir(parents=True)
            (store / ('ab' + 'c' * 62)).write_bytes(b'data')
            repo = hub / 'datasets--org--set'
            (repo / 'blobs').mkdir(parents=True)
            snap = repo / 'snapshots' / ('d' * 40)
            snap.mkdir(parents=True)
            digest = hashlib.sha256(b'data').hexdigest()
            (repo / 'blobs' / digest).symlink_to(Path('../../blobs/ab') / ('ab' + 'c' * 62))
            (snap / 'train.parquet').symlink_to(Path('../../blobs') / digest)
            r = local_scan(str(repo), True)
            self.assertFalse([f for f in r['findings'] if f['rule'] in ('MG003', 'MG011')])
            files = {f['path']: f for f in r['files']}
            self.assertEqual(len(files), 2)
            self.assertEqual(sum('same_as' in f for f in files.values()), 1)   # inspected once

    def test_invalid_and_oversized_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'config.json'
            p.write_text('{')
            self.assertIn(('MG005', 'review'), rules(local_scan(tmp)))
            p.write_bytes(b' ' * (LIMIT + 1))
            self.assertTrue(any('larger than 2 MiB' in f['message'] for f in local_scan(tmp)['findings']))

    def test_unreadable_file_does_not_abort(self):
        if os.geteuid() == 0:
            self.skipTest('root can read everything')
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'locked.pkl').write_bytes(pickle.dumps(1))
            (p / 'locked.pkl').chmod(0)
            (p / 'ok.pkl').write_bytes(pickle.dumps(Evil()))
            try:
                r = local_scan(tmp, True)
            finally:
                (p / 'locked.pkl').chmod(0o600)
            self.assertIn(('MG006', 'high'), rules(r))
            self.assertTrue(any(f['file'] == 'locked.pkl' and f['rule'] == 'MG007' for f in r['findings']))

    def test_fifo_and_git_dir_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            os.mkfifo(p / 'pipe')
            (p / '.git' / 'lfs').mkdir(parents=True)
            (p / '.git' / 'lfs' / 'blob.bin').write_bytes(pickle.dumps(Evil()))
            r = local_scan(tmp)
            self.assertEqual(r['files'], [])
            self.assertTrue(any('.git' in x for x in r['limitations']))

    def test_parallel_hashing_matches_sequential(self):
        with tempfile.TemporaryDirectory() as tmp:
            for i in range(6):
                (Path(tmp) / f'f{i}.bin').write_bytes(os.urandom(70_000))
            os.link(Path(tmp) / 'f0.bin', Path(tmp) / 'hard.bin')
            seq = {f['path']: f['sha256'] for f in local_scan(tmp, True)['files']}
            par = {f['path']: f['sha256'] for f in local_scan(tmp, True, jobs=4)['files']}
            self.assertEqual(seq, par)
            self.assertEqual(seq['hard.bin'], seq['f0.bin'])

    def test_no_arbitrary_remote_urls(self):
        for bad in ('https://example.com/model', 'a/..', '../x'):
            with self.assertRaises(ValueError):
                hub_scan(bad)


class ContentIntegrationTests(unittest.TestCase):
    def test_signature_extension_and_content_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'model.pkl').write_bytes(pickle.dumps(Evil()))
            (p / 'bad.safetensors').write_bytes(struct.pack('<Q', 1 << 40))
            (p / 'notes.txt').write_bytes(b"cos\nsystem\n(S'id'\ntR.")
            (p / 'weights.safetensors').write_bytes(pickle.dumps(Evil()))
            (p / 'chat_template.jinja').write_text("{{ cycler.__init__.__globals__.os.popen('id') }}")
            (p / 'modeling.py').write_text('import base64\nexec(base64.b64decode(b"eA=="))\n')
            report = local_scan(tmp)
        by_file = {(f['file'], f['rule'], f['severity']) for f in report['findings']}
        for expected in [('model.pkl', 'MG006', 'high'), ('bad.safetensors', 'MG008', 'review'),
                         ('notes.txt', 'MG006', 'high'), ('weights.safetensors', 'MG010', 'high'),
                         ('weights.safetensors', 'MG006', 'high'), ('chat_template.jinja', 'MG015', 'high'),
                         ('modeling.py', 'MG013', 'high')]:
            self.assertIn(expected, by_file)
        self.assertTrue(report['coverage']['static_formats'])
        self.assertFalse(report['coverage']['content'])
        self.assertEqual(report['summary']['findings_high'], sum(f['severity'] == 'high' for f in report['findings']))

    def test_raw_bin_not_misreported(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'vectors.bin').write_bytes(os.urandom(4096).replace(b'\x80', b'\x00'))
            report = local_scan(tmp)
        self.assertEqual({f['rule'] for f in report['findings']}, {'MG001'})

    def test_tokenizer_config_template(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'tokenizer_config.json').write_text(json.dumps(
                {'chat_template': [{'name': 'default', 'template': "{{ ''.__class__ }}"}]}))
            self.assertIn(('MG015', 'high'), rules(local_scan(tmp)))


class HubTests(unittest.TestCase):
    def test_hub_revision_and_inventory(self):
        ctx = fake_hub({'sha': 'a' * 40, 'siblings': [{'rfilename': 'model.bin', 'size': 42}, 'junk', {'size': 1}]})
        try:
            r = hub_scan('org/model')
        finally:
            ctx.stop()
        self.assertEqual(r['revision'], 'a' * 40)
        self.assertEqual([f['path'] for f in r['files']], ['model.bin'])
        self.assertEqual(r['findings'][0]['rule'], 'MG001')

    def test_hub_bad_responses_rejected(self):
        for body in (b'{}', b'[]', b'{"sha": "' + b'a' * 40 + b'"}', b'not json'):
            ctx = fake_hub(body)
            try:
                with self.assertRaises(ValueError):
                    hub_scan('org/model')
            finally:
                ctx.stop()

    def test_redirect_to_other_host_refused(self):
        handler = cli._redirect_handler()
        with self.assertRaises(Exception):
            handler.redirect_request(None, None, 302, 'Found', {}, 'https://evil.example/api')


class VerifyTests(unittest.TestCase):
    def run_verify(self, declared, partial=False, extra_local=None):
        payload = {'sha': 'b' * 40, 'siblings': [
            {'rfilename': 'w.safetensors', 'size': 3, 'lfs': {'sha256': declared}},
            {'rfilename': 'extra.json', 'size': 2}]}
        ctx = fake_hub(payload)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                (Path(tmp) / 'w.safetensors').write_bytes(b'abc')
                for name, data in (extra_local or {}).items():
                    (Path(tmp) / name).parent.mkdir(parents=True, exist_ok=True)
                    (Path(tmp) / name).write_bytes(data)
                return verify(tmp, 'org/model', partial=partial)
        finally:
            ctx.stop()

    def test_match_and_mismatch(self):
        good = hashlib.sha256(b'abc').hexdigest()
        report = self.run_verify(good)
        self.assertNotIn('MG011', [f['rule'] for f in report['findings']])
        self.assertIn('MG012', [f['rule'] for f in report['findings']])
        bad = self.run_verify('0' * 64)
        self.assertIn(('MG011', 'high'), rules(bad))
        self.assertEqual(bad['revision'], 'b' * 40)

    def test_partial_size_mismatch_and_hf_metadata_ignored(self):
        good = hashlib.sha256(b'abc').hexdigest()
        r = self.run_verify(good, True, {'extra.json': b'toolong', '.cache/huggingface/download/w.metadata': b'x'})
        self.assertEqual([(f['rule'], f['file']) for f in r['findings'] if f['rule'] in ('MG011', 'MG012')],
                         [('MG011', 'extra.json')])

    def test_hub_failure_happens_before_hashing(self):
        with patch.object(cli, 'hub_scan', side_effect=ValueError('down')), \
                patch.object(cli, 'local_scan') as scan:
            with self.assertRaises(ValueError):
                verify('.', 'org/model')
            scan.assert_not_called()


class MainTests(unittest.TestCase):
    def run_main(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), patch.object(cli, '_lower_priority'):
            try:
                main(list(argv))
                code = 0
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue()

    def test_exit_codes_and_formats(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'model.pkl').write_bytes(pickle.dumps(Evil()))
            code, out = self.run_main('scan', tmp)
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out)['summary']['findings_high'], 1)
            code, out = self.run_main('scan', tmp, '--format', 'text', '--fail-on', 'high')
            self.assertEqual(code, 1)
            self.assertIn('HIGH', out)
            report = Path(tmp) / 'out' / 'r.json'
            code, _ = self.run_main('scan', str(Path(tmp) / 'model.pkl'), '--output', str(report))
            self.assertEqual(code, 2)  # output directory missing: incomplete, never a silent success
            code, _ = self.run_main('scan', str(Path(tmp) / 'missing'))
            self.assertEqual(code, 2)


if __name__ == '__main__':
    unittest.main()
