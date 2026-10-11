import json
import struct
import tempfile
import unittest
from pathlib import Path

from modelguard.formats import check_gguf, check_safetensors, sniff


def st_file(tmp, header, body=b'', raw=None):
    raw = raw if raw is not None else json.dumps(header).encode()
    p = Path(tmp) / 'm.safetensors'
    p.write_bytes(struct.pack('<Q', len(raw)) + raw + body)
    return p, p.stat().st_size


def gstr(s):
    return struct.pack('<Q', len(s)) + s.encode()


def gguf(tmp, tensors=((b'F32', 4, 0),), kv=(('general.name', 8, gstr('x')),), tail=0, data=None):
    """Build a GGUF v3 file. tensors: (unused, elements, offset) for F32 tensors."""
    out = b'GGUF' + struct.pack('<IQQ', 3, len(tensors), len(kv))
    for key, kind, value in kv:
        out += gstr(key) + struct.pack('<I', kind) + value
    for i, (_, elements, offset) in enumerate(tensors):
        out += gstr(f't{i}') + struct.pack('<I', 1) + struct.pack('<Q', elements) + struct.pack('<IQ', 0, offset)
    out += b'\0' * ((-len(out)) % 32)
    if data is None:
        data = max((o + e * 4 for _, e, o in tensors), default=0)
    out += b'\0' * (data + tail)
    p = Path(tmp) / 'm.gguf'
    p.write_bytes(out)
    return p, len(out)


class SafetensorsTests(unittest.TestCase):
    def test_valid(self):
        with tempfile.TemporaryDirectory() as t:
            p, n = st_file(t, {'a': {'dtype': 'F32', 'shape': [2], 'data_offsets': [0, 8]},
                               '__metadata__': {'format': 'pt'}}, b'\0' * 8)
            self.assertEqual(check_safetensors(p, n), [])
            self.assertEqual(sniff(p, n), 'safetensors')

    def test_bad_span_gap_overlap_and_trailing(self):
        with tempfile.TemporaryDirectory() as t:
            p, n = st_file(t, {'a': {'dtype': 'F32', 'shape': [2], 'data_offsets': [0, 4]}}, b'\0' * 12)
            self.assertTrue(check_safetensors(p, n))
            p, n = st_file(t, {'a': {'dtype': 'U8', 'shape': [2], 'data_offsets': [1, 3]}}, b'\0' * 3)
            self.assertTrue(any('Gap' in i for i in check_safetensors(p, n)))
            p, n = st_file(t, {'a': {'dtype': 'U8', 'shape': [4], 'data_offsets': [0, 4]},
                               'b': {'dtype': 'U8', 'shape': [2], 'data_offsets': [2, 4]}}, b'\0' * 4)
            self.assertTrue(any('Overlap' in i for i in check_safetensors(p, n)))

    def test_duplicate_keys_and_bad_types(self):
        with tempfile.TemporaryDirectory() as t:
            raw = b'{"a": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}, "a": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}}'
            p, n = st_file(t, None, b'\0', raw=raw)
            self.assertEqual(check_safetensors(p, n), ['Duplicate keys in header JSON'])
            p, n = st_file(t, {'a': {'dtype': 'U8', 'shape': [True], 'data_offsets': [0, 1]}}, b'\0')
            self.assertTrue(any('Malformed' in i for i in check_safetensors(p, n)))
            p, n = st_file(t, {'a': {'dtype': 'F4', 'shape': [3], 'data_offsets': [0, 2]}}, b'\0' * 2)
            self.assertEqual(check_safetensors(p, n), [])   # sub-byte dtype: 3 x 4 bits = 2 bytes

    def test_huge_header_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / 'x'
            p.write_bytes(struct.pack('<Q', 1 << 40) + b'{}')
            self.assertTrue(check_safetensors(p, p.stat().st_size))
            self.assertIsNone(sniff(p, p.stat().st_size))


class GgufTests(unittest.TestCase):
    def test_valid(self):
        with tempfile.TemporaryDirectory() as t:
            p, n = gguf(t, tensors=((None, 4, 0), (None, 8, 32)))
            issues, info = check_gguf(p, n)
            self.assertEqual(issues, [])
            self.assertEqual(info['tensor_count'], 2)

    def test_size_checks(self):
        with tempfile.TemporaryDirectory() as t:
            p, n = gguf(t, tensors=((None, 16, 0), (None, 8, 32)))     # 64-byte tensor overlaps the next
            self.assertTrue(any('overlaps' in i for i in check_gguf(p, n)[0]))
            p, n = gguf(t, tensors=((None, 4, 0),), data=8)             # declares 16 bytes, has 8
            self.assertTrue(any('beyond end' in i for i in check_gguf(p, n)[0]))
            p, n = gguf(t, tail=4096)
            self.assertTrue(any('trailing' in i for i in check_gguf(p, n)[0]))
            p, n = gguf(t, tensors=((None, 4, 0), (None, 4, 256)))
            self.assertTrue(any('gap' in i for i in check_gguf(p, n)[0]))

    def test_bad_magic_truncated_and_counts(self):
        with tempfile.TemporaryDirectory() as t:
            p, n = gguf(t)
            data = p.read_bytes()
            p.write_bytes(b'XXXX' + data[4:])
            self.assertEqual(check_gguf(p, n)[0], ['Missing GGUF magic'])
            p.write_bytes(data[:30])
            self.assertTrue(check_gguf(p, 30)[0])
            p.write_bytes(b'GGUF' + struct.pack('<IQQ', 3, 1 << 50, 1))
            self.assertTrue(check_gguf(p, p.stat().st_size)[0])

    def test_string_arrays_and_chat_template(self):
        with tempfile.TemporaryDirectory() as t:
            vocab = struct.pack('<IQ', 8, 3) + gstr('a') + gstr('bb') + gstr('ccc')
            kv = (('tokenizer.ggml.tokens', 9, vocab), ('tokenizer.chat_template', 8, gstr('{{ x.__class__ }}')),
                  ('general.alignment', 4, struct.pack('<I', 32)))
            p, n = gguf(t, kv=kv)
            issues, info = check_gguf(p, n)
            self.assertEqual(issues, [])
            self.assertEqual(info['chat_templates'], {'tokenizer.chat_template': '{{ x.__class__ }}'})

    def test_string_array_past_eof(self):
        with tempfile.TemporaryDirectory() as t:
            vocab = struct.pack('<IQ', 8, 1 << 20) + gstr('a')
            p, n = gguf(t, kv=(('tokenizer.ggml.tokens', 9, vocab),))
            self.assertTrue(any('past end' in i for i in check_gguf(p, n)[0]))


if __name__ == '__main__':
    unittest.main()
