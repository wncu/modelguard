"""Static pickle analysis: walks opcodes over a memory-mapped buffer with a symbolic stack.

Never unpickles, imports or executes anything. Large payloads (tensor bytes, long strings) are
skipped by offset without being read, so memory stays flat regardless of file size.
"""
import codecs
import mmap
from array import array
import pickletools
import re
import struct
import time
import zipfile
import zlib

MAX_OPS = 5_000_000          # per file, across all streams
MAX_SECONDS = 10.0           # per file
MAX_STREAMS = 5              # legacy (pre-zip) torch files chain 5 pickles before the raw storages
MAX_STACK = 1_000_000
MAX_MEMO = 4_000_000        # memo slots tracked (8 bytes each); beyond this, lookups become unknown
MAX_LINE = 1 << 16           # protocol 0 text arguments
MAX_STR = 512                # strings longer than this are tracked as opaque (no module name is that long)
MAX_INFLATE = 64 * 1024 * 1024   # compressed zip members are decompressed into memory up to this size
MAX_MEMBERS = 100_000
SCAN_SUFFIXES = ('.pkl', '.pickle', '.npy')

DANGEROUS_MODULES = {
    'os', 'posix', 'nt', 'subprocess', 'sys', 'socket', 'shutil', 'pty', 'commands', 'importlib',
    'runpy', 'webbrowser', 'ctypes', 'marshal', 'pickle', '_pickle', 'cPickle', 'code', 'codeop',
    'multiprocessing', 'asyncio', 'threading', '_thread', 'signal', 'tempfile', 'urllib', 'http', 'requests',
    'ftplib', 'smtplib', 'telnetlib', 'pip', 'setuptools', 'timeit', 'platform', 'sysconfig', 'pdb', 'bdb',
    'ssl', 'posixpath', 'ntpath', 'genericpath', 'distutils', 'lib2to3', 'idlelib', 'pydoc', 'trace',
    'cProfile', 'profile', 'operator', '_operator', 'functools', '_functools', 'types', 'io', '_io',
    'pathlib', 'glob', 'fileinput', 'linecache', 'zipimport', 'imp', 'pkgutil', 'site', 'dill', 'cloudpickle',
    'joblib', 'shelve', 'dbm', 'sqlite3', 'xmlrpc', 'smtpd', 'socketserver', 'gc', 'inspect', 'builtins_',
    'numpy.testing', 'numpy.f2py', 'numpy.distutils', 'numpy.lib.utils', 'torch.hub', 'torch.utils.bottleneck',
    'torch.jit', 'torch.distributed', 'torch._dynamo', 'torch._inductor', 'torch.fx', 'torch.serialization',
    'torch.storage', 'torch.utils.cpp_extension', 'torch.package', 'keras.models', 'tensorflow.io',
    'venv', 'ensurepip', 'httplib', 'urllib2', 'urllib3', 'httplib2', 'aiohttp', 'httpx', 'paramiko', 'pycurl',
    'websocket', 'websockets', 'poplib', 'imaplib', 'nntplib', 'xmlrpclib', 'SimpleHTTPServer', 'popen2',
    'pexpect', 'sh', 'plumbum', 'fabric', 'invoke', 'uvicorn', 'flask', 'fastapi',
}
DANGEROUS_MODULES.discard('builtins_')
SAFE_BUILTINS = {'set', 'frozenset', 'dict', 'list', 'tuple', 'int', 'float', 'complex', 'bool', 'str', 'bytes',
                 'bytearray', 'slice', 'range'}
TORCH_DTYPES = {'float32', 'float', 'float64', 'double', 'float16', 'half', 'bfloat16', 'uint8', 'int8', 'int16',
                'short', 'int32', 'int', 'int64', 'long', 'bool', 'complex64', 'complex128', 'float8_e4m3fn',
                'float8_e5m2', 'uint16', 'uint32', 'uint64'}
TORCH_STORAGES = {'FloatStorage', 'HalfStorage', 'BFloat16Storage', 'LongStorage', 'IntStorage', 'ByteStorage',
                  'BoolStorage', 'DoubleStorage', 'ShortStorage', 'CharStorage', 'ComplexFloatStorage',
                  'ComplexDoubleStorage', 'UntypedStorage', 'TypedStorage', 'QInt8Storage', 'QUInt8Storage',
                  'QInt32Storage', 'Size', 'device', 'Tensor', 'dtype', 'memory_format', 'layout'}
SAFE_GLOBALS = {
    ('collections', 'OrderedDict'), ('collections', 'defaultdict'), ('collections', 'deque'),
    ('torch._utils', '_rebuild_tensor'), ('torch._utils', '_rebuild_tensor_v2'), ('torch._utils', '_rebuild_tensor_v3'),
    ('torch._utils', '_rebuild_parameter'), ('torch._utils', '_rebuild_parameter_with_state'),
    ('torch._utils', '_rebuild_qtensor'), ('torch._utils', '_rebuild_meta_tensor_no_storage'),
    ('torch._utils', '_rebuild_device_tensor_from_numpy'), ('torch._tensor', '_rebuild_from_type_v2'),
    ('numpy.core.multiarray', '_reconstruct'), ('numpy.core.multiarray', 'scalar'),
    ('numpy._core.multiarray', '_reconstruct'), ('numpy._core.multiarray', 'scalar'),
    ('numpy', 'ndarray'), ('numpy', 'dtype'), ('numpy.dtypes', 'Float32DType'), ('_codecs', 'encode'),
}
_IDENT = re.compile(r'[A-Za-z_][A-Za-z0-9_]*\Z')


def classify(module, name):
    """Return 'high', 'review' or None (allowlisted) for a global import (module, name)."""
    if not isinstance(module, str) or not isinstance(name, str):
        return 'high'
    if '__' in name:                      # dunder traversal (__globals__, __reduce__, __class__ ...)
        return 'high'
    parts = module.split('.')
    prefixes = {'.'.join(parts[:i]) for i in range(1, len(parts) + 1)}
    if prefixes & DANGEROUS_MODULES:
        return 'high'
    if parts[0] in ('builtins', '__builtin__'):
        return None if name in SAFE_BUILTINS else 'high'
    if '.' in name or not _IDENT.match(name):   # attribute chains can reach anything; never allowlisted
        return 'review'
    if (module, name) in SAFE_GLOBALS:
        return None
    if module == 'torch' and (name in TORCH_DTYPES or name in TORCH_STORAGES):
        return None
    if module.startswith(('torch.nn.modules.', 'torch.nn.parameter')):
        return None
    return 'review'


# ---- opcode table, derived once from pickletools metadata -------------------------------------------
_MARK, _OPAQUE, _LONG = object(), object(), object()
_M_OPAQUE, _M_LONG = -1, -2       # memo slot values; >= 0 is a packed string reference
(A_NONE, A_FIXED, A_LEN1, A_LEN4S, A_LEN4U, A_LEN8, A_LINE, A_LINE2) = range(8)
(S_GENERIC, S_STR, S_DUP, S_PUT, S_MEMO, S_GET, S_GLOBAL, S_INST, S_SGLOBAL, S_STOP, S_MARK, S_EXT) = range(12)
_STR_DECODE = {'SHORT_BINUNICODE': 0, 'BINUNICODE': 0, 'BINUNICODE8': 0, 'UNICODE': 1, 'STRING': 2,
               'BINSTRING': 3, 'SHORT_BINSTRING': 3}
_DECODERS = ('utf8', 'rawuni', 'repr', 'ascii')
_SPECIAL = {'DUP': S_DUP, 'PUT': S_PUT, 'BINPUT': S_PUT, 'LONG_BINPUT': S_PUT, 'MEMOIZE': S_MEMO,
            'GET': S_GET, 'BINGET': S_GET, 'LONG_BINGET': S_GET, 'GLOBAL': S_GLOBAL, 'INST': S_INST,
            'STACK_GLOBAL': S_SGLOBAL, 'STOP': S_STOP, 'MARK': S_MARK, 'EXT1': S_EXT, 'EXT2': S_EXT, 'EXT4': S_EXT}


def _build_table():
    table = [None] * 256
    for op in pickletools.opcodes:
        arg = op.arg
        if arg is None:
            kind, n = A_NONE, 0
        elif arg.name == 'stringnl_noescape_pair':
            kind, n = A_LINE2, 0
        elif arg.n > 0:
            kind, n = A_FIXED, arg.n
        else:
            kind, n = {pickletools.UP_TO_NEWLINE: A_LINE, pickletools.TAKEN_FROM_ARGUMENT1: A_LEN1,
                       pickletools.TAKEN_FROM_ARGUMENT4: A_LEN4S, pickletools.TAKEN_FROM_ARGUMENT4U: A_LEN4U,
                       pickletools.TAKEN_FROM_ARGUMENT8U: A_LEN8}[arg.n], 0
        before = op.stack_before
        has_mark = pickletools.markobject in before
        pre = before.index(pickletools.markobject) if has_mark else len(before)
        special = S_STR if op.name in _STR_DECODE else _SPECIAL.get(op.name, S_GENERIC)
        table[ord(op.code)] = (op.name, kind, n, pre, has_mark, len(op.stack_after), special,
                               _STR_DECODE.get(op.name))
    return table


_TABLE = _build_table()
_U4, _S4, _U8 = struct.Struct('<I'), struct.Struct('<i'), struct.Struct('<Q')


class _Malformed(Exception):
    pass


class _Limit(Exception):
    pass


class _Budget:
    def __init__(self):
        self.ops, self.deadline, self.memo_note = MAX_OPS, time.monotonic() + MAX_SECONDS, True


def _ref_value(buf, ref):
    """Strings are kept as packed ints (offset << 13 | length << 3 | codec) and decoded only when used."""
    if isinstance(ref, int):
        start, length = ref >> 13, (ref >> 3) & 0x3FF
        return _decode(bytes(buf[start:start + length]), _DECODERS[ref & 7])
    return ref


def _decode(raw, how):
    try:
        if how == 'utf8':
            return raw.decode('utf-8', 'surrogatepass')
        if how == 'ascii':
            return raw.decode('ascii')
        if how == 'rawuni':
            return raw.decode('raw-unicode-escape')
        if len(raw) >= 2 and raw[:1] == raw[-1:] and raw[:1] in (b'"', b"'"):   # STRING: quoted repr
            return codecs.escape_decode(raw[1:-1])[0].decode('ascii')
    except (UnicodeError, ValueError):
        pass
    return _OPAQUE


def _walk(buf, pos, end, budget, found, notes):
    """Walk one pickle stream starting at pos. Appends (module, name, severity) to found. Returns end offset.

    Stack entries are _MARK, _OPAQUE, _LONG or packed string references (ints); the memo is an int array,
    so memory stays small even for pickles with millions of objects or strings."""
    table, stack = _TABLE, []
    memo, sparse = array('q'), {}       # dense memo slots 0..len-1 plus sparse extras: tracks len(memo) exactly
    ops_left = budget.ops
    while True:
        if pos >= end:
            raise _Malformed('truncated stream (no STOP)')
        spec = table[buf[pos]]
        if spec is None:
            raise _Malformed(f'invalid opcode 0x{buf[pos]:02x} at {pos}')
        name, kind, n, pre, has_mark, push, special, how = spec
        pos += 1
        a = pos
        if kind == A_NONE:
            pass
        elif kind == A_FIXED:
            pos += n
        elif kind == A_LEN1:
            if pos >= end:
                raise _Malformed('truncated length')
            a = pos + 1
            pos = a + buf[pos]
        elif kind == A_LEN4U or kind == A_LEN4S:
            if pos + 4 > end:
                raise _Malformed('truncated length')
            ln = (_U4 if kind == A_LEN4U else _S4).unpack_from(buf, pos)[0]
            if ln < 0:
                raise _Malformed('negative length')
            a = pos + 4
            pos = a + ln
        elif kind == A_LEN8:
            if pos + 8 > end:
                raise _Malformed('truncated length')
            a = pos + 8
            pos = a + _U8.unpack_from(buf, pos)[0]
        else:  # A_LINE / A_LINE2
            nl = buf.find(b'\n', pos, min(end, pos + MAX_LINE))
            if nl < 0:
                raise _Malformed('unterminated text argument')
            if kind == A_LINE2:
                nl2 = buf.find(b'\n', nl + 1, min(end, nl + 1 + MAX_LINE))
                if nl2 < 0:
                    raise _Malformed('unterminated text argument')
                line2 = buf[nl + 1:nl2]
                pos = nl2 + 1
            else:
                pos = nl + 1
            line1 = buf[a:nl]
        if pos > end:
            raise _Malformed(f'{name} argument runs past end of data')

        ops_left -= 1
        if not ops_left & 0xFFFF:
            if ops_left <= 0:
                raise _Limit('opcode limit reached')
            if time.monotonic() > budget.deadline:
                raise _Limit('time limit reached')

        if special == S_GENERIC:
            if has_mark:
                try:
                    while stack.pop() is not _MARK:
                        pass
                except IndexError:
                    raise _Malformed(f'{name} without MARK') from None
            if pre:
                if len(stack) < pre:
                    raise _Malformed(f'stack underflow at {name}')
                del stack[-pre:]
            if push:
                stack.append(_OPAQUE)
                if len(stack) > MAX_STACK:
                    raise _Limit('stack limit reached')
            continue
        if special == S_STR:
            length = (nl if kind == A_LINE else pos) - a
            stack.append((a << 13) | (length << 3) | how if length <= MAX_STR else _LONG)
        elif special == S_PUT or special == S_MEMO:
            if not stack:
                raise _Malformed('memo store on empty stack')
            top = stack[-1]
            value = top if isinstance(top, int) else (_M_LONG if top is _LONG else _M_OPAQUE)
            dense = len(memo)
            if special == S_MEMO:
                idx = dense + len(sparse)
            elif kind == A_LINE:
                try:
                    idx = int(line1)
                except ValueError:
                    raise _Malformed('bad PUT index') from None
            elif n == 1:
                idx = buf[a]
            else:
                idx = _U4.unpack_from(buf, a)[0]
            if idx < dense:
                memo[idx] = value
            elif idx == dense and dense < MAX_MEMO:
                memo.append(value)
                while len(memo) in sparse:
                    memo.append(sparse.pop(len(memo)))
            elif len(sparse) < MAX_MEMO:
                sparse[idx] = value
            elif budget.memo_note:
                budget.memo_note = False
                notes.append('Memo limit reached; later memo lookups treated as unknown')
        elif special == S_GET:
            if kind == A_LINE:
                try:
                    idx = int(line1)
                except ValueError:
                    raise _Malformed('bad GET index') from None
            elif n == 1:
                idx = buf[a]
            else:
                idx = _U4.unpack_from(buf, a)[0]
            value = memo[idx] if idx < len(memo) else sparse.get(idx, _M_LONG if not budget.memo_note else _M_OPAQUE)
            stack.append(value if value >= 0 else (_LONG if value == _M_LONG else _OPAQUE))
        elif special == S_DUP:
            if not stack:
                raise _Malformed('DUP on empty stack')
            stack.append(stack[-1])
        elif special == S_MARK:
            stack.append(_MARK)
        elif special == S_GLOBAL or special == S_INST:
            module = bytes(line1).decode('utf-8', 'replace')
            attr = bytes(line2).decode('utf-8', 'replace')
            found.append((module, attr, classify(module, attr)))
            if special == S_INST:
                try:
                    while stack.pop() is not _MARK:
                        pass
                except IndexError:
                    raise _Malformed('INST without MARK') from None
            stack.append(_OPAQUE)
        elif special == S_SGLOBAL:
            if len(stack) < 2:
                raise _Malformed('stack underflow at STACK_GLOBAL')
            attr, module = _ref_value(buf, stack.pop()), _ref_value(buf, stack.pop())
            if isinstance(module, str) and isinstance(attr, str):
                found.append((module, attr, classify(module, attr)))
            else:
                found.append(('<unresolved>', '<unresolved>', 'high'))
            stack.append(_OPAQUE)
        elif special == S_EXT:
            found.append(('copyreg', f'<extension {name}>', 'review'))
            stack.append(_OPAQUE)
        elif special == S_STOP:
            budget.ops = ops_left
            return pos


def scan_buffer(buf, start=0, end=None, strict=True, budget=None):
    """Scan consecutive pickle streams in buf[start:end]. Returns (globals, notes).

    strict=False is used when the bytes were not identified as pickle by a strong signature: a parse
    failure with no globals then means "not a pickle" and produces no note (it could not run code)."""
    end = len(buf) if end is None else end
    budget = budget or _Budget()
    found, notes, pos = [], [], start
    for index in range(MAX_STREAMS):
        before = len(found)
        try:
            pos = _walk(buf, pos, end, budget, found, notes)
        except _Limit as exc:
            notes.append(f'Scan limit reached ({exc}); result incomplete')
            break
        except _Malformed as exc:
            if index == 0 and (strict or len(found) > before):
                notes.append(f'Malformed or truncated pickle: {exc}')
            break                      # a later malformed stream is trailing data (joblib arrays, storages)
        if pos >= end or buf[pos] != 0x80:
            break
    return found, notes


# ---- file entry points --------------------------------------------------------------------------------
_GLOBAL_START = re.compile(rb'c[A-Za-z_][\w.]*\n[A-Za-z_][\w.]*\n')


def looks_like_pickle(head):
    """Strong signature check for the first bytes of a file."""
    if len(head) >= 2 and head[0] == 0x80 and 2 <= head[1] <= 5:
        return True
    if head[:2] in (b'(d', b'(l', b'(i', b'(c', b'(t', b'(S', b'(V', b'(I', b'(F', b'(N', b'}q', b']q', b'(L'):
        return True
    return bool(_GLOBAL_START.match(head))


class Result:
    __slots__ = ('kind', 'found', 'notes', 'flags')

    def __init__(self, kind):
        self.kind, self.found, self.notes, self.flags = kind, [], [], []


def _map(path):
    stream = open(path, 'rb')
    try:
        return stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ)
    except (ValueError, OSError):  # empty file or not mappable
        stream.close()
        return None, None


def scan_file(path, strict=None):
    """Scan a pickle, PyTorch zip, npy or npz file by content. Returns Result or None if not applicable.

    strict=None decides from the signature; pass False for extension-only candidates."""
    stream, buf = _map(path)
    if buf is None:
        return None
    try:
        if buf[:2] == b'PK':
            return _scan_zip(path, buf)
        if buf[:6] == b'\x93NUMPY':
            return _scan_npy(buf, 0, len(buf), _Budget())
        strong = looks_like_pickle(buf[:256])
        if not strong and strict is not False:
            return None
        result = Result('pickle')
        result.found, result.notes = scan_buffer(buf, strict=strong if strict is None else strict)
        if strict is False and not strong and not result.found and not result.notes:
            return None
        return result
    finally:
        buf.close()
        stream.close()


def _npy_header(buf, start, end):
    if end - start < 10 or buf[start:start + 6] != b'\x93NUMPY':
        return None, None
    if buf[start + 6] == 1:
        hlen, body = struct.unpack_from('<H', buf, start + 8)[0], start + 10
    else:
        if end - start < 12:
            return None, None
        hlen, body = _U4.unpack_from(buf, start + 8)[0], start + 12
    return bytes(buf[body:min(body + hlen, body + 65536, end)]), body + hlen


def _scan_npy(buf, start, end, budget, label='npy-object'):
    """Only object arrays embed a pickle after the header; plain numeric arrays return None."""
    header, data = _npy_header(buf, start, end)
    if header is None or not re.search(rb"""['"]\|?O['"]""", header):
        return None
    result = Result(label)
    if data >= end:
        result.notes.append('npy object array without payload')
        return result
    result.found, result.notes = scan_buffer(buf, data, end, strict=True, budget=budget)
    return result


def _scan_zip(path, buf):
    result = Result('zip')
    budget = _Budget()
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_MEMBERS:
                result.notes.append(f'Archive has {len(infos)} members; only the first {MAX_MEMBERS} inspected')
                infos = infos[:MAX_MEMBERS]
            names = [i.filename for i in infos]
            prefixes = {n[:-len('data.pkl')] for n in names if n == 'data.pkl' or n.endswith('/data.pkl')}
            if prefixes:
                result.kind = 'torch-zip'
            if any('/code/' in n and n.endswith('.py') for n in names):
                result.flags.append(('MG014', 'review', 'TorchScript archive: contains serialized code that runs '
                                     'when loaded with torch.jit.load'))
            storage_dirs = tuple(p + 'data/' for p in prefixes)
            for info in infos:
                fname = info.filename
                if fname.startswith('/') or '..' in fname.replace('\\', '/').split('/'):
                    result.notes.append('Unsafe archive member name: ' + fname[:120])
                if fname.endswith('/') or (storage_dirs and fname.startswith(storage_dirs)):
                    continue                  # directories and raw tensor storages are never unpickled
                named = fname.endswith(SCAN_SUFFIXES)
                encrypted = bool(info.flag_bits & 0x1)
                member, a, b = _member_view(archive, info, buf, encrypted)
                if member is None:
                    if named:
                        result.notes.append(('Encrypted' if encrypted else 'Oversized or unsupported') +
                                            f' archive member not inspected: {fname[:120]}')
                    continue
                head = bytes(member[a:min(b, a + 256)])
                if fname.endswith('.npy') or head[:6] == b'\x93NUMPY':
                    sub = _scan_npy(member, a, b, budget, 'npz-object')
                    if sub is None:
                        continue
                    found, notes = sub.found, sub.notes
                    if result.kind == 'zip':
                        result.kind = 'npz'
                elif named or looks_like_pickle(head):
                    found, notes = scan_buffer(member, a, b, strict=named, budget=budget)
                    if not named and found:
                        result.notes.append(f'Pickle stored under a non-pickle name: {fname[:120]}')
                else:
                    continue
                if encrypted and (found or notes):
                    result.notes.append(f'Encryption flag set on a plaintext member: {fname[:120]} '
                                        '(some loaders ignore the flag)')
                result.found += found
                result.notes += [f'{fname[:120]}: {n}' for n in notes]
    except (zipfile.BadZipFile, zipfile.LargeZipFile, NotImplementedError, RuntimeError, OSError, EOFError, ValueError):
        result.notes.append('Unreadable or corrupt zip archive')
    return result


def _member_view(archive, info, buf, encrypted):
    """Return (buffer, start, end) for a member's bytes without trusting the zip flags.

    Stored members are a zero-copy slice of the mmap; deflated members are inflated with a hard size bound.
    Members flagged as encrypted are read raw: real ciphertext simply fails the pickle signature check."""
    off = info.header_offset
    if buf[off:off + 4] != b'PK\x03\x04':
        return None, 0, 0
    name_len, extra_len = struct.unpack_from('<HH', buf, off + 26)
    start = off + 30 + name_len + extra_len
    if info.compress_type == zipfile.ZIP_STORED:
        if start + info.file_size <= len(buf):
            return buf, start, start + info.file_size
        return None, 0, 0
    if info.compress_type == zipfile.ZIP_DEFLATED and not encrypted:
        stop = min(len(buf), start + info.compress_size)
        inflater = zlib.decompressobj(-15)
        try:
            data = inflater.decompress(bytes(buf[start:min(stop, start + MAX_INFLATE)]), MAX_INFLATE + 1)
        except zlib.error:
            return None, 0, 0
        if len(data) > MAX_INFLATE:
            return None, 0, 0
        return data, 0, len(data)
    if encrypted:
        return None, 0, 0
    try:
        with archive.open(info) as member:
            data = member.read(MAX_INFLATE + 1)
    except (NotImplementedError, RuntimeError, zipfile.BadZipFile, OSError, EOFError):
        return None, 0, 0
    if len(data) > MAX_INFLATE:
        return None, 0, 0
    return data, 0, len(data)
