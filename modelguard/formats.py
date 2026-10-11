"""Bounded structural validators for safetensors and GGUF. Read headers only; never load tensors."""
import json
import math
import struct

MAX_ST_HEADER = 100 * 1024 * 1024
ST_DTYPES = {'BOOL': 1, 'U8': 1, 'I8': 1, 'F8_E5M2': 1, 'F8_E4M3': 1, 'I16': 2, 'U16': 2, 'F16': 2, 'BF16': 2,
             'I32': 4, 'U32': 4, 'F32': 4, 'I64': 8, 'U64': 8, 'F64': 8}


def check_safetensors(path, size):
    """Return a list of structural problems; empty list means the header is consistent."""
    issues = []
    with open(path, 'rb') as stream:
        raw = stream.read(8)
        if len(raw) < 8:
            return ['File shorter than 8-byte header length']
        (n,) = struct.unpack('<Q', raw)
        if n > MAX_ST_HEADER or 8 + n > size:
            return [f'Header length {n} exceeds limit or file size']
        header = stream.read(n)
    if not header.startswith(b'{'):
        issues.append('Header does not start with "{"')
    try:
        meta = json.loads(header)
    except ValueError:
        return issues + ['Header is not valid JSON']
    if not isinstance(meta, dict):
        return issues + ['Header JSON is not an object']
    body = size - 8 - n
    spans = []
    for name, entry in meta.items():
        if name == '__metadata__':
            if not isinstance(entry, dict) or not all(isinstance(v, str) for v in entry.values()):
                issues.append('__metadata__ must map strings to strings')
            continue
        try:
            dtype, shape, (begin, end) = entry['dtype'], entry['shape'], entry['data_offsets']
            assert isinstance(begin, int) and isinstance(end, int) and 0 <= begin <= end
            assert all(isinstance(d, int) and d >= 0 for d in shape)
        except (KeyError, TypeError, ValueError, AssertionError):
            issues.append(f'Malformed tensor entry: {name[:80]}')
            continue
        if dtype not in ST_DTYPES:
            issues.append(f'Unknown dtype {dtype!r} for {name[:80]}')
        elif ST_DTYPES[dtype] * math.prod(shape) != end - begin:
            issues.append(f'Byte span does not match dtype/shape: {name[:80]}')
        spans.append((begin, end, name))
    spans.sort()
    cursor = 0
    for begin, end, name in spans:
        if begin != cursor:
            issues.append(f'Gap or overlap before tensor {name[:80]}')
        cursor = max(cursor, end)
    if cursor != body:
        issues.append(f'Tensor data covers {cursor} bytes but file body is {body}')
    return issues


GGUF_SCALARS = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}
MAX_KV, MAX_TENSORS, MAX_STR, MAX_ARRAY = 100_000, 1_000_000, 1 << 20, 1 << 24


class _Reader:
    def __init__(self, stream, size):
        self.s, self.size = stream, size

    def take(self, n):
        if n < 0 or self.s.tell() + n > self.size:
            raise ValueError('read past end of file')
        data = self.s.read(n)
        if len(data) != n:
            raise ValueError('truncated')
        return data

    def u(self, fmt):
        return struct.unpack('<' + fmt, self.take(struct.calcsize(fmt)))[0]

    def string(self):
        n = self.u('Q')
        if n > MAX_STR:
            raise ValueError('string too long')
        return self.take(n).decode('utf-8', 'replace')

    def skip_value(self, kind, depth=0):
        if kind in GGUF_SCALARS:
            self.take(GGUF_SCALARS[kind])
        elif kind == 8:
            self.string()
        elif kind == 9:
            if depth > 4:
                raise ValueError('array nesting too deep')
            inner, count = self.u('I'), self.u('Q')
            if count > MAX_ARRAY:
                raise ValueError('array too large')
            if inner in GGUF_SCALARS:
                self.take(GGUF_SCALARS[inner] * count)
            else:
                for _ in range(count):
                    self.skip_value(inner, depth + 1)
        else:
            raise ValueError(f'unknown value type {kind}')


def check_gguf(path, size):
    """Return (issues, info) after parsing header, metadata keys and tensor table."""
    issues, info = [], {}
    with open(path, 'rb') as stream:
        r = _Reader(stream, size)
        try:
            if r.take(4) != b'GGUF':
                return ['Missing GGUF magic'], info
            version = r.u('I')
            tensors, kvs = r.u('Q'), r.u('Q')
            info.update(version=version, tensor_count=tensors, kv_count=kvs)
            if version not in (2, 3):
                issues.append(f'Unsupported GGUF version {version}')
            if tensors > MAX_TENSORS or kvs > MAX_KV:
                return issues + ['Tensor or metadata count exceeds limit'], info
            alignment = 32
            for _ in range(kvs):
                key, kind = r.string(), r.u('I')
                if key == 'general.alignment' and kind == 4:
                    alignment = r.u('I')
                else:
                    r.skip_value(kind)
                if key == 'tokenizer.chat_template':
                    info['has_chat_template'] = True
            if alignment <= 0 or alignment & (alignment - 1):
                issues.append(f'Invalid alignment {alignment}')
                alignment = 32
            offsets = []
            for _ in range(tensors):
                name = r.string()
                dims = r.u('I')
                if dims > 8:
                    raise ValueError(f'tensor {name[:60]} has {dims} dims')
                for _ in range(dims):
                    r.u('Q')
                r.u('I')
                offsets.append((r.u('Q'), name))
            data_start = -(-stream.tell() // alignment) * alignment
            info['data_start'] = data_start
            if data_start > size:
                issues.append('Tensor data section starts past end of file')
            for off, name in offsets:
                if off % alignment:
                    issues.append(f'Misaligned offset for {name[:60]}')
                if data_start + off > size:
                    issues.append(f'Tensor offset beyond file end: {name[:60]}')
        except (ValueError, struct.error) as exc:
            issues.append(f'Malformed GGUF: {exc}')
    return issues, info


def sniff(path, size):
    """Identify a file by content signature. Returns one of gguf, safetensors, torch-zip, zip, npy, pickle, or None."""
    with open(path, 'rb') as stream:
        head = stream.read(16)
    if head[:4] == b'GGUF':
        return 'gguf'
    if head[:6] == b'\x93NUMPY':
        return 'npy'
    if head[:2] == b'PK':
        return 'zip'
    if head[:1] == b'\x80' and len(head) > 1 and head[1] in range(2, 6):
        return 'pickle'
    if len(head) >= 9:
        (n,) = struct.unpack('<Q', head[:8])
        if head[8:9] == b'{' and 8 < 8 + n <= size and n <= MAX_ST_HEADER:
            return 'safetensors'
    if head[:1] in (b'(', b']', b'}') and size > 2:
        return 'pickle'  # protocol 0/1 streams; heuristic
    return None
