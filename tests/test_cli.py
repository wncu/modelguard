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

if __name__=='__main__': unittest.main()
