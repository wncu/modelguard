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
        found, _ = scan_pickle(pickle.dumps(Path('x')))
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
