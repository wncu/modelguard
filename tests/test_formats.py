import json
import struct
import tempfile
import unittest
from pathlib import Path
from modelguard.formats import check_safetensors, check_gguf


def st_file(tmp, header, body=b''):
    raw = json.dumps(header).encode()
    p = Path(tmp) / 'm.safetensors'
    p.write_bytes(struct.pack('<Q', len(raw)) + raw + body)
    return p, p.stat().st_size


def gguf_string(s):
    return struct.pack('<Q', len(s)) + s.encode()


class SafetensorsTests(unittest.TestCase):
    def test_valid(self):
        with tempfile.TemporaryDirectory() as t:
            p, n = st_file(t, {'a': {'dtype': 'F32', 'shape': [2], 'data_offsets': [0, 8]}}, b'\0' * 8)
            self.assertEqual(check_safetensors(p, n), [])

    def test_bad_span_gap_and_trailing(self):
        with tempfile.TemporaryDirectory() as t:
            p, n = st_file(t, {'a': {'dtype': 'F32', 'shape': [2], 'data_offsets': [0, 4]}}, b'\0' * 12)
            self.assertTrue(check_safetensors(p, n))
            p, n = st_file(t, {'a': {'dtype': 'U8', 'shape': [2], 'data_offsets': [1, 3]}}, b'\0' * 3)
            self.assertTrue(any('Gap' in i for i in check_safetensors(p, n)))

    def test_huge_header_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / 'x'
            p.write_bytes(struct.pack('<Q', 1 << 40) + b'{}')
            self.assertTrue(check_safetensors(p, p.stat().st_size))


class GgufTests(unittest.TestCase):
    def build(self, tmp, tensors=1, kv=None):
        data = b'GGUF' + struct.pack('<IQQ', 3, tensors, 1)
        data += gguf_string('general.name') + struct.pack('<I', 8) + gguf_string('x')
        for i in range(tensors):
            data += gguf_string(f't{i}') + struct.pack('<I', 1) + struct.pack('<Q', 4) + struct.pack('<IQ', 0, 0)
        data += b'\0' * ((-len(data)) % 32) + b'\0' * 16
        p = Path(tmp) / 'm.gguf'
        p.write_bytes(data)
        return p, len(data)

    def test_valid(self):
        with tempfile.TemporaryDirectory() as t:
            p, n = self.build(t)
            issues, info = check_gguf(p, n)
            self.assertEqual(issues, [])
            self.assertEqual(info['tensor_count'], 1)

    def test_bad_magic_and_truncated(self):
        with tempfile.TemporaryDirectory() as t:
            p, n = self.build(t)
            data = p.read_bytes()
            p.write_bytes(b'XXXX' + data[4:])
            self.assertEqual(check_gguf(p, n)[0], ['Missing GGUF magic'])
            p.write_bytes(data[:30])
            self.assertTrue(check_gguf(p, 30)[0])

    def test_absurd_counts(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / 'x.gguf'
            p.write_bytes(b'GGUF' + struct.pack('<IQQ', 3, 1 << 50, 1))
            self.assertTrue(check_gguf(p, p.stat().st_size)[0])
