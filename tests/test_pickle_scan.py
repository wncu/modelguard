import collections
import io
import os
import pickle
import random
import tempfile
import unittest
import zipfile
from pathlib import Path

from modelguard import pickle_scan
from modelguard.pickle_scan import classify, scan_buffer, scan_file


class Evil:
    def __reduce__(self):
        return (os.system, ('echo must-not-run',))


def severities(data):
    found, _ = scan_buffer(data)
    return {sev for *_, sev in found}


class Recorder(pickle.Unpickler):
    def __init__(self, data):
        super().__init__(io.BytesIO(data))
        self.calls = []

    def find_class(self, module, name):
        self.calls.append((module, name))
        return super().find_class(module, name)


class DetectionTests(unittest.TestCase):
    def test_os_system_all_protocols(self):
        for proto in range(6):
            self.assertIn('high', severities(pickle.dumps(Evil(), protocol=proto)), proto)

    def test_benign_allowlisted(self):
        found, notes = scan_buffer(pickle.dumps(collections.OrderedDict(a=[1, 'x', b'y', 2.5])))
        self.assertEqual({sev for *_, sev in found}, {None})
        self.assertEqual(notes, [])

    def test_unknown_global_is_review(self):
        self.assertEqual(severities(pickle.dumps(__import__('fractions').Fraction(1, 3))), {'review'})

    def test_gadget_modules_are_high(self):
        import functools
        import operator
        for obj in (operator.attrgetter('x'), functools.partial(print)):
            self.assertIn('high', severities(pickle.dumps(obj)), obj)

    def test_classify_rules(self):
        self.assertEqual(classify('numpy.testing._private.utils', 'runstring'), 'high')   # prefix match
        self.assertEqual(classify('collections', 'OrderedDict.__init__.__globals__'), 'high')  # dunder chain
        self.assertEqual(classify('collections', 'OrderedDict.fromkeys'), 'review')       # attribute chain
        self.assertEqual(classify('builtins', 'print'), 'high')
        self.assertIsNone(classify('builtins', 'set'))
        self.assertIsNone(classify('torch', 'bfloat16'))
        self.assertIsNone(classify('torch.nn.modules.linear', 'Linear'))
        self.assertEqual(classify('torch.storage', '_load_from_bytes'), 'high')


class EvasionTests(unittest.TestCase):
    def test_pop_between_operands_does_not_downgrade(self):
        # 'os' 'system' 'x' POP STACK_GLOBAL: the real stack resolves os.system
        data = b'\x80\x04\x8c\x02os\x8c\x06system\x8c\x01x0\x93\x8c\x04echo\x85R.'
        found, _ = scan_buffer(data)
        self.assertEqual(found, [('os', 'system', 'high')])

    def test_memoized_operands(self):
        data = b'\x80\x04\x8c\x02os\x94\x8c\x06system\x94h\x00h\x01\x93.'
        self.assertEqual(scan_buffer(data)[0], [('os', 'system', 'high')])

    def test_non_string_operand_is_unresolved_high(self):
        data = b'\x80\x04K\x01\x8c\x06system\x93.'   # int as module name
        self.assertEqual(scan_buffer(data)[0][0][2], 'high')

    def test_protocol0_global_first_detected(self):
        data = b"cos\nsystem\n(S'echo hi'\ntR."
        self.assertEqual(scan_buffer(data)[0], [('os', 'system', 'high')])
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'payload.txt'
            p.write_bytes(data)
            self.assertEqual(scan_file(p).found[0][2], 'high')

    def test_evil_in_second_chained_stream(self):
        self.assertIn('high', severities(pickle.dumps({'a': 1}) + pickle.dumps(Evil())))

    def test_trailing_binary_data_is_not_malformed(self):
        found, notes = scan_buffer(pickle.dumps([1, 2]) + b'\x80\xff\x00garbage-array-bytes')
        self.assertEqual(notes, [])

    def test_extension_opcode_reported(self):
        self.assertEqual(scan_buffer(b'\x80\x02\x82\x01.')[0][0][2], 'review')


class FileTests(unittest.TestCase):
    def test_torch_zip_stored_and_deflated(self):
        with tempfile.TemporaryDirectory() as tmp:
            for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                z = Path(tmp) / f'm{compression}.pt'
                with zipfile.ZipFile(z, 'w', compression) as zf:
                    zf.writestr('archive/data.pkl', pickle.dumps(Evil(), protocol=2))
                    zf.writestr('archive/data/0', b'\x80' * 64)
                result = scan_file(z)
                self.assertEqual(result.kind, 'torch-zip')
                self.assertEqual(result.found[0][2], 'high')
                self.assertEqual(result.notes, [])

    def test_text_opcode_pickle_in_small_zip_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            z = Path(tmp) / 'm.pt'
            with zipfile.ZipFile(z, 'w') as zf:
                zf.writestr('a/data.pkl', pickle.dumps(Evil(), protocol=0))
            result = scan_file(z)
            self.assertEqual((result.notes, result.found[0][2]), ([], 'high'))

    def test_zip_member_detected_by_signature_not_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            z = Path(tmp) / 'm.zip'
            with zipfile.ZipFile(z, 'w') as zf:
                zf.writestr('data.txt', pickle.dumps(Evil()))
                zf.writestr('readme.txt', b'hello')
            result = scan_file(z)
            self.assertEqual(result.found[0][2], 'high')
            self.assertTrue(any('non-pickle name' in n for n in result.notes))

    def test_encryption_flag_on_plaintext_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            z = Path(tmp) / 'm.zip'
            info = zipfile.ZipInfo('model/config.pkl')
            with zipfile.ZipFile(z, 'w') as zf:
                zf.writestr(info, pickle.dumps(Evil()))
            data = bytearray(z.read_bytes())
            for sig, flag_at in ((b'PK\x03\x04', 6), (b'PK\x01\x02', 8)):   # set bit 0 in both headers
                i = data.find(sig)
                data[i + flag_at] |= 1
            z.write_bytes(bytes(data))
            result = scan_file(z)
            self.assertEqual(result.found[0][2], 'high')
            self.assertTrue(any('Encryption flag' in n for n in result.notes))

    def test_torch_storages_not_parsed(self):
        with tempfile.TemporaryDirectory() as tmp:
            z = Path(tmp) / 'm.pt'
            with zipfile.ZipFile(z, 'w') as zf:
                zf.writestr('archive/data.pkl', pickle.dumps({'w': 1}))
                zf.writestr('archive/data/0', b'\x80\x02cgarbage\nname\n' + os.urandom(64))
            result = scan_file(z)
            self.assertEqual((result.found, result.notes), ([], []))

    def test_torchscript_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            z = Path(tmp) / 'ts.pt'
            with zipfile.ZipFile(z, 'w') as zf:
                zf.writestr('m/data.pkl', pickle.dumps({}))
                zf.writestr('m/code/__torch__/m.py', 'def forward(self): pass')
            self.assertEqual(scan_file(z).flags[0][0], 'MG014')

    def npy(self, payload, version=1, pad=0):
        header = b"{'descr': '|O', 'fortran_order': False, 'shape': (1,), }" + b' ' * pad
        header += b' ' * (-(10 + len(header) + 1) % 64) + b'\n'
        size = len(header).to_bytes(2 if version == 1 else 4, 'little')
        return b'\x93NUMPY' + bytes([version, 0]) + size + header + payload

    def test_npy_object_arrays_and_large_header(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'obj.npy'
            p.write_bytes(self.npy(pickle.dumps([Evil()])))
            self.assertEqual(scan_file(p).found[0][2], 'high')
            p.write_bytes(self.npy(pickle.dumps([Evil()]), version=2, pad=70000))
            result = scan_file(p)
            self.assertEqual((result.found[0][2], result.notes), ('high', []))
            p.write_bytes(self.npy(b'\x00' * 16).replace(b'|O', b'<f'))
            self.assertIsNone(scan_file(p))

    def test_npz_with_object_array(self):
        with tempfile.TemporaryDirectory() as tmp:
            z = Path(tmp) / 'arrays.npz'
            with zipfile.ZipFile(z, 'w') as zf:
                zf.writestr('a.npy', self.npy(pickle.dumps([Evil()])))
            result = scan_file(z)
            self.assertEqual((result.kind, result.found[0][2]), ('npz', 'high'))

    def test_non_pickle_and_empty_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'x.bin'
            p.write_bytes(b'GGUF....')
            self.assertIsNone(scan_file(p))
            self.assertIsNone(scan_file(p, strict=False))
            p.write_bytes(b'')
            self.assertIsNone(scan_file(p))


class BoundsTests(unittest.TestCase):
    def test_limits_report_incomplete_not_crash(self):
        old = pickle_scan.MAX_OPS
        pickle_scan.MAX_OPS = 0x10000
        try:
            _, notes = scan_buffer(pickle.dumps(list(range(200_000))))
        finally:
            pickle_scan.MAX_OPS = old
        self.assertTrue(any('limit' in n for n in notes))

    def test_huge_declared_length_is_malformed(self):
        _, notes = scan_buffer(b'\x80\x04\x8e' + (1 << 60).to_bytes(8, 'little') + b'x.')
        self.assertTrue(notes and 'past end' in notes[0])

    def test_matches_real_unpickler(self):
        """Differential check: the globals found equal what pickle.Unpickler actually resolves."""
        rnd = random.Random(3)
        samples = [collections.OrderedDict(a=1), {1, 2}, frozenset('ab'), bytearray(b'x'), 10 ** 40,
                   __import__('datetime').date(2020, 1, 2), __import__('decimal').Decimal('1.5'),
                   collections.deque([1]), collections.defaultdict(list), 'é' * 700, b'z' * 300]
        for _ in range(300):
            obj = [rnd.choice(samples) for _ in range(rnd.randrange(1, 6))]
            shared = 'shared'
            obj = [obj, shared, shared, obj]
            for proto in range(6):
                data = pickle.dumps(obj, protocol=proto)
                rec = Recorder(data)
                rec.load()
                found, notes = scan_buffer(data)
                self.assertEqual(set(rec.calls), {(m, n) for m, n, _ in found})
                self.assertEqual(notes, [])


if __name__ == '__main__':
    unittest.main()
