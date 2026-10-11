"""Bounded structural validators for safetensors and GGUF. Read headers only; never load tensors."""
import json
import math
import mmap
import struct

MAX_ST_HEADER = 16 * 1024 * 1024  # real headers are KBs to a few MB; the format allows 100 MB
ST_DTYPES = {'BOOL': 1, 'U8': 1, 'I8': 1, 'F8_E5M2': 1, 'F8_E4M3': 1, 'F8_E4M3FN': 1, 'F8_E8M0': 1, 'I16': 2,
             'U16': 2, 'F16': 2, 'BF16': 2, 'I32': 4, 'U32': 4, 'F32': 4, 'I64': 8, 'U64': 8, 'F64': 8,
             'C64': 8, 'C128': 16}
# sub-byte dtypes: bits per element
ST_BITS = {'F4': 4, 'F6_E2M3': 6, 'F6_E3M2': 6, 'U4': 4, 'I4': 4}


def _no_duplicates(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError('duplicate keys')
    return dict(pairs)


def check_safetensors(path, size):
    """Return a list of structural problems; an empty list means the header is consistent."""
    with open(path, 'rb') as stream:
        raw = stream.read(8)
        if len(raw) < 8:
            return ['File shorter than 8-byte header length']
        (n,) = struct.unpack('<Q', raw)
        if n > MAX_ST_HEADER or 8 + n > size:
            return [f'Header length {n} exceeds limit or file size']
        header = stream.read(n)
    issues = []
    if not header.startswith(b'{'):
        issues.append('Header does not start with "{"')
    try:
        meta = json.loads(header, object_pairs_hook=_no_duplicates)
    except ValueError as exc:
        return issues + [('Duplicate keys in header JSON' if 'duplicate' in str(exc) else 'Header is not valid JSON')]
    except RecursionError:
        return issues + ['Header JSON nested too deeply']
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
            ok = (type(begin) is int and type(end) is int and 0 <= begin <= end and isinstance(shape, list)
                  and all(type(d) is int and d >= 0 for d in shape))
        except (KeyError, TypeError, ValueError):
            ok = False
        if not ok:
            issues.append(f'Malformed tensor entry: {name[:80]}')
            continue
        count = math.prod(shape)
        if dtype in ST_DTYPES:
            expected = ST_DTYPES[dtype] * count
        elif dtype in ST_BITS:
            expected = (ST_BITS[dtype] * count + 7) // 8
        else:
            expected = None
            issues.append(f'Unknown dtype {str(dtype)[:20]!r} for {name[:80]}')
        if expected is not None and expected != end - begin:
            issues.append(f'Byte span does not match dtype/shape: {name[:80]}')
        spans.append((begin, end, name))
    spans.sort()
    cursor = 0
    for begin, end, name in spans:
        if begin != cursor:
            issues.append(f'{"Gap" if begin > cursor else "Overlap"} before tensor {name[:80]}')
        cursor = max(cursor, end)
    if cursor != body:
        issues.append(f'Tensor data covers {cursor} bytes but file body is {body}')
    return issues


# ---- GGUF ------------------------------------------------------------------------------------------
GGUF_SCALARS = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}
MAX_KV, MAX_TENSORS, MAX_STR, MAX_ARRAY, MAX_TEMPLATE = 100_000, 1_000_000, 1 << 24, 1 << 26, 1 << 20
# ggml tensor types: (elements per block, bytes per block)
GGML_TYPES = {0: (1, 4), 1: (1, 2), 2: (32, 18), 3: (32, 20), 6: (32, 22), 7: (32, 24), 8: (32, 34),
              9: (32, 36), 10: (256, 84), 11: (256, 110), 12: (256, 144), 13: (256, 176), 14: (256, 210),
              15: (256, 292), 16: (256, 66), 17: (256, 74), 18: (256, 98), 19: (256, 50), 20: (32, 18),
              21: (256, 110), 22: (256, 82), 23: (256, 136), 24: (1, 1), 25: (1, 2), 26: (1, 4), 27: (1, 8),
              28: (1, 8), 29: (256, 56), 30: (1, 2), 34: (256, 54), 35: (256, 66), 39: (32, 17)}
_U4, _U8 = struct.Struct('<I'), struct.Struct('<Q')


class _Reader:
    """Cursor over a memory map; every access is bounds-checked against the file size."""

    def __init__(self, buf):
        self.b, self.p, self.size = buf, 0, len(buf)

    def need(self, n):
        if n < 0 or self.p + n > self.size:
            raise ValueError('read past end of file')

    def u32(self):
        self.need(4)
        v = _U4.unpack_from(self.b, self.p)[0]
        self.p += 4
        return v

    def u64(self):
        self.need(8)
        v = _U8.unpack_from(self.b, self.p)[0]
        self.p += 8
        return v

    def skip(self, n):
        self.need(n)
        self.p += n

    def string(self, keep=MAX_TEMPLATE):
        n = self.u64()
        if n > MAX_STR:
            raise ValueError('string too long')
        self.need(n)
        start = self.p
        self.p += n
        return self.b[start:start + n].decode('utf-8', 'replace') if n <= keep else None

    def skip_value(self, kind, depth=0):
        if kind in GGUF_SCALARS:
            self.skip(GGUF_SCALARS[kind])
        elif kind == 8:
            n = self.u64()
            if n > MAX_STR:
                raise ValueError('string too long')
            self.skip(n)
        elif kind == 9:
            if depth > 4:
                raise ValueError('array nesting too deep')
            inner, count = self.u32(), self.u64()
            if count > MAX_ARRAY:
                raise ValueError('array too large')
            if inner in GGUF_SCALARS:
                self.skip(GGUF_SCALARS[inner] * count)
            elif inner == 8:   # string arrays (tokenizer vocab): walk lengths only
                b, p, size, unpack = self.b, self.p, self.size, _U8.unpack_from
                for _ in range(count):
                    if p + 8 > size:
                        raise ValueError('read past end of file')
                    p += 8 + unpack(b, p)[0]
                if p > size:
                    raise ValueError('read past end of file')
                self.p = p
            else:
                for _ in range(count):
                    self.skip_value(inner, depth + 1)
        else:
            raise ValueError(f'unknown value type {kind}')


def check_gguf(path, size):
    """Return (issues, info). info may hold 'chat_templates' {key: text} for template inspection."""
    issues, info = [], {}
    with open(path, 'rb') as stream:
        if size < 4:
            return ['Missing GGUF magic'], info
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as buf:
            try:
                _parse_gguf(_Reader(buf), size, issues, info)
            except (ValueError, struct.error) as exc:
                issues.append(f'Malformed GGUF: {exc}')
    return issues, info


def _parse_gguf(r, size, issues, info):
    r.need(4)
    if r.b[0:4] != b'GGUF':
        issues.append('Missing GGUF magic')
        return
    r.p = 4
    version = r.u32()
    tensors, kvs = r.u64(), r.u64()
    info.update(version=version, tensor_count=tensors, kv_count=kvs)
    if version not in (2, 3):
        issues.append(f'Unsupported GGUF version {version}')
    if tensors > MAX_TENSORS or kvs > MAX_KV:
        issues.append('Tensor or metadata count exceeds limit')
        return
    alignment, templates, keys = 32, {}, set()
    for _ in range(kvs):
        key = r.string(keep=4096) or '<long key>'
        if key in keys:
            issues.append(f'Duplicate metadata key {key[:60]}')
        keys.add(key)
        kind = r.u32()
        if key == 'general.alignment' and kind == 4:
            alignment = r.u32()
        elif key.startswith('tokenizer.chat_template') and kind == 8:
            text = r.string()
            if text is None:
                issues.append(f'{key[:60]} longer than {MAX_TEMPLATE} bytes; not inspected')
            else:
                templates[key] = text
        else:
            r.skip_value(kind)
    if templates:
        info['chat_templates'] = templates
    if alignment <= 0 or alignment & (alignment - 1):
        issues.append(f'Invalid alignment {alignment}')
        alignment = 32
    spans, names, unknown = [], set(), set()
    for _ in range(tensors):
        name = r.string(keep=4096) or '<long name>'
        if name in names:
            issues.append(f'Duplicate tensor name {name[:60]}')
        names.add(name)
        dims = r.u32()
        if dims > 8:
            raise ValueError(f'tensor {name[:60]} has {dims} dims')
        shape = [r.u64() for _ in range(dims)]
        ggml_type, offset = r.u32(), r.u64()
        if offset % alignment:
            issues.append(f'Misaligned offset for {name[:60]}')
        layout = GGML_TYPES.get(ggml_type)
        if layout is None:
            unknown.add(ggml_type)
            spans.append((offset, offset, name))
            continue
        block, nbytes = layout
        if shape and shape[0] % block:
            issues.append(f'Tensor {name[:60]} row size not divisible by block size')
        spans.append((offset, offset + math.prod(shape) // block * nbytes, name))
    data_start = -(-r.p // alignment) * alignment
    info['data_start'] = data_start
    if unknown:
        info['unknown_tensor_types'] = sorted(unknown)
    if data_start > size:
        issues.append('Tensor data section starts past end of file')
        return
    spans.sort()
    cursor = 0
    for begin, end, name in spans:
        if begin < cursor:
            issues.append(f'Tensor {name[:60]} overlaps the previous tensor')
        elif begin - cursor >= alignment:
            issues.append(f'Unexpected {begin - cursor}-byte gap before tensor {name[:60]}')
        cursor = max(cursor, end)
    data_end = data_start + cursor
    if data_end > size:
        issues.append(f'Tensor data extends {data_end - size} bytes beyond end of file')
    elif not unknown and size - data_end >= alignment:
        issues.append(f'{size - data_end} trailing bytes after tensor data')


def sniff(path, size):
    """Identify a file by content signature: gguf, safetensors, zip, npy, pickle or None."""
    from .pickle_scan import looks_like_pickle
    with open(path, 'rb') as stream:
        head = stream.read(256)
    if head[:4] == b'GGUF':
        return 'gguf'
    if head[:6] == b'\x93NUMPY':
        return 'npy'
    if head[:4] in (b'PK\x03\x04', b'PK\x05\x06'):
        return 'zip'
    if looks_like_pickle(head):
        return 'pickle'
    if len(head) >= 9:
        (n,) = struct.unpack('<Q', head[:8])
        if head[8:9] == b'{' and 0 < n <= MAX_ST_HEADER and 8 + n <= size:
            return 'safetensors'
    return None
