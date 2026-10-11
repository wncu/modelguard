"""Static pickle opcode analysis. Uses pickletools.genops only: never unpickles."""
import io
import time
import pickletools
import zipfile

MAX_PICKLE = 256 * 1024 * 1024
MAX_OPS = 5_000_000
MAX_READ = 32 * 1024 * 1024
MAX_SECONDS = 10.0

DANGEROUS_MODULES = {
    'os', 'posix', 'nt', 'subprocess', 'sys', 'socket', 'shutil', 'pty', 'commands', 'importlib',
    'runpy', 'webbrowser', 'ctypes', 'marshal', 'pickle', 'cPickle', 'code', 'codeop', 'multiprocessing',
    'asyncio', 'threading', 'signal', 'tempfile', 'urllib', 'http', 'requests', 'ftplib', 'smtplib',
    'telnetlib', 'pip', 'setuptools', 'timeit', 'platform', 'sysconfig', 'pdb', 'bdb', 'ssl',
    'posixpath', 'ntpath', 'genericpath', 'distutils', 'lib2to3', 'idlelib', 'pydoc', 'trace', 'cProfile',
    'profile', 'operator', 'functools', 'types', 'io', '_io', 'pathlib', 'glob', 'fileinput', 'linecache',
    'zipimport', 'imp', 'pkgutil', 'site', 'numpy.testing', 'torch.hub', 'torch.utils.bottleneck',
    'torch.jit', 'torch.distributed', 'torch._dynamo', 'torch._inductor', 'torch.fx', 'torch.serialization',
    'dill', 'cloudpickle', 'joblib', 'shelve', 'dbm', 'sqlite3', 'xmlrpc', 'webbrowser', 'smtpd', 'socketserver',
}
DANGEROUS_BUILTINS = {'eval', 'exec', 'compile', 'open', '__import__', 'getattr', 'setattr', 'globals',
                      'locals', 'input', 'breakpoint', 'vars', 'delattr'}
SAFE_BUILTINS = {'set', 'frozenset', 'dict', 'list', 'tuple', 'int', 'float', 'complex', 'bool', 'str', 'bytes',
                 'bytearray', 'slice', 'range', 'object'}
SAFE_GLOBALS = {
    ('collections', 'OrderedDict'), ('collections', 'defaultdict'), ('torch._utils', '_rebuild_tensor_v2'),
    ('torch._utils', '_rebuild_tensor'), ('torch._utils', '_rebuild_parameter'),
    ('torch._utils', '_rebuild_tensor_v3'), ('torch', 'Size'), ('torch', 'device'), ('torch', 'Tensor'),
    ('numpy.core.multiarray', '_reconstruct'), ('numpy', 'ndarray'), ('numpy', 'dtype'),
    ('numpy.core.multiarray', 'scalar'), ('numpy._core.multiarray', '_reconstruct'),
    ('numpy._core.multiarray', 'scalar'), ('_codecs', 'encode'),
}
SAFE_PREFIXES = (('torch', 'FloatStorage'), ('torch', 'HalfStorage'), ('torch', 'BFloat16Storage'),
                 ('torch', 'LongStorage'), ('torch', 'IntStorage'), ('torch', 'ByteStorage'),
                 ('torch', 'BoolStorage'), ('torch', 'DoubleStorage'), ('torch', 'ShortStorage'),
                 ('torch', 'CharStorage'))
STRING_OPS = {'SHORT_BINUNICODE', 'BINUNICODE', 'BINUNICODE8', 'UNICODE', 'STRING', 'BINSTRING', 'SHORT_BINSTRING'}


def classify(module, name):
    """Return 'high', 'review' or None for a (module, name) global import."""
    if (module, name) in SAFE_GLOBALS or (module, name) in SAFE_PREFIXES:
        return None
    if module in ('builtins', '__builtin__') and name in SAFE_BUILTINS:
        return None
    if module.startswith('torch.nn.modules.') or module.startswith('torch.nn.parameter'):
        return None
    root = module.split('.')[0]
    if root in DANGEROUS_MODULES or module in DANGEROUS_MODULES or (root in ('builtins', '__builtin__') and name in DANGEROUS_BUILTINS):
        return 'high'
    return 'review'


MAX_STREAMS = 5  # legacy (pre-zip) torch files chain several pickles before the raw storages


class _Limit(ValueError):
    pass


class _Limited:
    """Read-only wrapper bounding total bytes, single-read size and wall time, so memory and CPU stay flat."""

    def __init__(self, stream, total=MAX_PICKLE, deadline=MAX_SECONDS):
        self.s, self.left, self.end = stream, total, time.monotonic() + deadline

    def _check(self, n):
        if n > MAX_READ:
            raise _Limit('single opcode argument too large')
        if n > self.left:
            raise _Limit('byte limit reached')
        if time.monotonic() > self.end:
            raise _Limit('time limit reached')

    def read(self, n=-1):
        self._check(MAX_READ if n < 0 else n)
        data = self.s.read(n)
        self.left -= len(data)
        return data

    def readline(self, limit=-1):
        self._check(0)
        data = self.s.readline(1 << 16 if limit < 0 else min(limit, 1 << 16))
        self.left -= len(data)
        return data

    def tell(self):
        return self.s.tell()

    def seek(self, *args):
        return self.s.seek(*args)


def scan_pickle(source, total=MAX_PICKLE):
    """Scan consecutive pickle streams from bytes or a binary file object, in bounded memory.

    Returns (globals, notes); globals = [(module, name, severity)]."""
    found, notes = [], []
    stream = _Limited(io.BytesIO(source) if isinstance(source, (bytes, bytearray)) else source, total)
    for _ in range(MAX_STREAMS):
        f, n = _scan_stream(stream)
        found += f
        notes += n
        if n:
            break
        try:
            nxt = stream.read(1)
        except ValueError:
            break
        if nxt != b'\x80':
            break
        stream.seek(-1, 1)
    return found, notes


def _scan_stream(stream):
    found, notes, memo, strings = [], [], {}, []
    try:
        for count, (op, arg, _pos) in enumerate(pickletools.genops(stream)):
            if count > MAX_OPS:
                notes.append('Opcode limit reached; scan incomplete')
                break
            if op.name in STRING_OPS:
                strings.append(arg)
                strings = strings[-4:]
            elif op.name in ('MEMOIZE',):
                if strings:
                    memo[len(memo)] = strings[-1]
            elif op.name in ('BINPUT', 'LONG_BINPUT'):
                if strings:
                    memo[arg] = strings[-1]
            elif op.name in ('BINGET', 'LONG_BINGET', 'GET'):
                strings.append(memo.get(arg))
                strings = strings[-4:]
            elif op.name in ('GLOBAL', 'INST'):
                module, _, name = str(arg).replace('\n', ' ').partition(' ')
                found.append((module, name, classify(module, name)))
            elif op.name == 'STACK_GLOBAL':
                if len(strings) >= 2 and all(isinstance(s, str) for s in strings[-2:]):
                    module, name = strings[-2], strings[-1]
                    found.append((module, name, classify(module, name)))
                else:
                    found.append(('?', '?', 'high'))
                    notes.append('STACK_GLOBAL with unresolved operands')
    except _Limit as exc:
        notes.append(f'Scan limit reached ({exc}); result incomplete')
    except Exception as exc:  # genops raises ValueError/KeyError/struct errors on malformed data
        notes.append('Malformed or truncated pickle: ' + type(exc).__name__)
    return found, notes


def scan_npy(path):
    """numpy .npy: only object arrays embed a pickle after the header. Returns None for plain arrays."""
    with open(path, 'rb') as stream:
        head = stream.read(10)
        if len(head) < 10 or head[:6] != b'\x93NUMPY':
            return None
        major = head[6]
        hlen = int.from_bytes(head[8:10], 'little') if major == 1 else int.from_bytes(head[8:10] + stream.read(2), 'little')
        header = stream.read(min(hlen, 65536))
        if b"'O'" not in header and b'|O' not in header and b'"O"' not in header:
            return None
        found, notes = scan_pickle(stream)
    return found, notes, 'npy-object'


def scan_file(path):
    """Scan a pickle/PyTorch file by content, not extension. Returns None if not pickle-like."""
    with open(path, 'rb') as stream:
        head = stream.read(4)
        if head[:2] == b'PK':
            return _scan_zip(path)
        if head[:1] != b'\x80' and not head[:1] in (b'(', b'c', b']', b'}'):
            return None
        stream.seek(0)
        found, notes = scan_pickle(stream)
    return found, notes, 'pickle'


def _scan_zip(path):
    found, notes, budget = [], [], 2 * MAX_PICKLE
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if info.filename.startswith('/') or '..' in info.filename.split('/'):
                    notes.append('Unsafe archive member name: ' + info.filename)
                if not info.filename.endswith(('.pkl', 'data.pkl')):
                    continue
                if info.file_size > MAX_PICKLE or info.file_size > budget:
                    notes.append('Archive pickle exceeds size limit or total budget: ' + info.filename)
                    continue
                budget -= info.file_size
                with archive.open(info) as member:
                    f, n = scan_pickle(member, min(info.file_size + 1, MAX_PICKLE))
                found += f
                notes += n
    except (zipfile.BadZipFile, OSError, RuntimeError) as exc:
        return [], ['Unreadable zip archive: ' + type(exc).__name__], 'zip'
    return found, notes, 'torch-zip'
