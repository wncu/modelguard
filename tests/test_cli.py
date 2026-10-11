import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from modelguard.cli import local_scan, hub_scan, LIMIT

class ScanTests(unittest.TestCase):
    def test_inventory_hash_and_custom_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p/'config.json').write_text(json.dumps({'auto_map': {'AutoModel': 'evil.Model'}}))
            (p/'weights.pkl').write_bytes(b'not executed')
            (p/'remote.py').write_text("raise RuntimeError('must never execute')")
            report = local_scan(tmp, True)
            self.assertEqual(report['status'], 'insufficient_evidence')
            self.assertFalse(report['coverage']['behavior'])
            self.assertEqual({f['rule'] for f in report['findings']}, {'MG001','MG002','MG004'})
            item = next(x for x in report['files'] if x['path']=='weights.pkl')
            self.assertEqual(item['sha256'], hashlib.sha256(b'not executed').hexdigest())
    def test_symlink_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp); (p/'link').symlink_to('/etc/passwd')
            r=local_scan(tmp,True)
            self.assertEqual(r['files'],[])
            self.assertEqual(r['findings'][0]['rule'],'MG003')
    def test_invalid_and_oversized_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'config.json';p.write_text('{')
            self.assertEqual(local_scan(tmp)['findings'][0]['rule'],'MG005')
            p.write_bytes(b' '*(LIMIT+1))
            self.assertTrue(any('Oversized' in x for x in local_scan(tmp)['limitations']))
    def test_no_arbitrary_remote_urls(self):
        with self.assertRaises(ValueError): hub_scan('https://example.com/model')
    def test_hub_revision_and_inventory(self):
        payload={'sha':'a'*40,'siblings':[{'rfilename':'model.bin','size':42}]}
        with patch('modelguard.cli.urlopen') as fetch:
            fetch.return_value.__enter__.return_value.read.return_value=json.dumps(payload).encode()
            r=hub_scan('org/model')
        self.assertEqual(r['revision'],'a'*40)
        self.assertEqual(r['findings'][0]['rule'],'MG001')
    def test_hub_missing_revision_rejected(self):
        with patch('modelguard.cli.urlopen') as fetch:
            fetch.return_value.__enter__.return_value.read.return_value=b'{}'
            with self.assertRaises(ValueError):hub_scan('org/model')

class ContentIntegrationTests(unittest.TestCase):
    def test_malicious_pickle_and_bad_safetensors_flagged(self):
        import os, pickle, struct
        class Evil:
            def __reduce__(self): return (os.system, ('echo no',))
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p/'model.pkl').write_bytes(pickle.dumps(Evil()))
            (p/'bad.safetensors').write_bytes(struct.pack('<Q', 1 << 40))
            report = local_scan(tmp)
        rules = {(f['rule'], f['severity']) for f in report['findings']}
        self.assertIn(('MG006', 'high'), rules)
        self.assertIn(('MG008', 'review'), rules)
        self.assertTrue(report['coverage']['static_formats'])
        self.assertFalse(report['coverage']['content'])
        self.assertEqual(report['status'], 'insufficient_evidence')

class VerifyTests(unittest.TestCase):
    def run_verify(self, declared, partial=False):
        from modelguard.cli import verify
        payload = {'sha': 'b' * 40, 'siblings': [
            {'rfilename': 'w.safetensors', 'size': 3, 'lfs': {'sha256': declared}},
            {'rfilename': 'extra.json', 'size': 2}]}
        with tempfile.TemporaryDirectory() as tmp, patch('modelguard.cli.urlopen') as fetch:
            (Path(tmp) / 'w.safetensors').write_bytes(b'abc')
            fetch.return_value.__enter__.return_value.read.return_value = json.dumps(payload).encode()
            return verify(tmp, 'org/model', partial=partial)

    def test_match_and_mismatch(self):
        good = hashlib.sha256(b'abc').hexdigest()
        rules = [f['rule'] for f in self.run_verify(good)['findings']]
        self.assertNotIn('MG011', rules)
        self.assertIn('MG012', rules)
        bad = self.run_verify('0' * 64)
        self.assertIn(('MG011', 'high'), {(f['rule'], f['severity']) for f in bad['findings']})
        self.assertEqual(bad['revision'], 'b' * 40)

    def test_partial_hides_missing(self):
        good = hashlib.sha256(b'abc').hexdigest()
        self.assertNotIn('MG012', [f['rule'] for f in self.run_verify(good, True)['findings']])

if __name__=='__main__': unittest.main()
