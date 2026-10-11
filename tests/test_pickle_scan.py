import collections
import os
import pickle
import tempfile
import unittest
import zipfile
from pathlib import Path
from modelguard.pickle_scan import scan_pickle, scan_file


class Evil:
    def __reduce__(self):
        return (os.system, ('echo must-not-run',))


class PickleTests(unittest.TestCase):
    def test_detects_os_system_in_all_protocols(self):
        for proto in (0, 2, 4, 5):
            found, _ = scan_pickle(pickle.dumps(Evil(), protocol=proto))
            self.assertTrue(any(sev == 'high' for _, _, sev in found), proto)

    def test_benign_allowlisted(self):
        found, notes = scan_pickle(pickle.dumps(collections.OrderedDict(a=1)))
        self.assertEqual([sev for *_, sev in found], [None])
        self.assertEqual(notes, [])

    def test_unknown_global_is_review(self):
        found, _ = scan_pickle(pickle.dumps(__import__('fractions').Fraction(1, 3)))
        self.assertTrue(found and all(sev == 'review' for *_, sev in found))

    def test_malformed_pickle_noted(self):
        _, notes = scan_pickle(b'\x80\x05\x95\xff\xff')
        self.assertTrue(notes)

    def test_zip_member_and_non_pickle(self):
        with tempfile.TemporaryDirectory() as tmp:
            z = Path(tmp) / 'm.pt'
            with zipfile.ZipFile(z, 'w') as zf:
                zf.writestr('archive/data.pkl', pickle.dumps(Evil()))
            found, _, kind = scan_file(z)
            self.assertEqual(kind, 'torch-zip')
            self.assertEqual(found[0][2], 'high')
            other = Path(tmp) / 'x.bin'
            other.write_bytes(b'GGUF....')
            self.assertIsNone(scan_file(other))


class EvasionTests(unittest.TestCase):
    def test_evil_in_second_chained_stream(self):
        found, _ = scan_pickle(pickle.dumps({'a': 1}) + pickle.dumps(Evil()))
        self.assertTrue(any(sev == 'high' for *_, sev in found))

    def test_gadget_modules_are_high(self):
        import operator, functools
        for obj in (operator.attrgetter('x'), functools.partial(print)):
            found, _ = scan_pickle(pickle.dumps(obj))
            self.assertTrue(any(sev == 'high' for *_, sev in found), obj)

    def test_renamed_files_detected_by_signature(self):
        from modelguard.cli import local_scan
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'notes.txt').write_bytes(pickle.dumps(Evil()))
            (p / 'weights.safetensors').write_bytes(pickle.dumps(Evil()))
            header = b"{'descr': '|O', 'fortran_order': False, 'shape': (1,), }"
            header += b' ' * (-(10 + len(header) + 1) % 64) + b'\n'
            (p / 'obj.npy').write_bytes(b'\x93NUMPY\x01\x00' + len(header).to_bytes(2, 'little') + header + pickle.dumps([Evil()]))
            report = local_scan(tmp)
        by_file = {(f['file'], f['rule'], f['severity']) for f in report['findings']}
        self.assertIn(('notes.txt', 'MG006', 'high'), by_file)
        self.assertIn(('weights.safetensors', 'MG010', 'high'), by_file)
        self.assertIn(('obj.npy', 'MG006', 'high'), by_file)
