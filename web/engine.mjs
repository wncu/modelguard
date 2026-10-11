// ModelGuard browser engine: a port of the Python static checks. Reads files in slices with Blob.slice,
// never uploads, never executes, never unpickles. Runs in browsers and in Node (for parity tests).
export const VERSION = 'web-0.2.0';

const MAX_OPS = 5_000_000, MAX_STREAMS = 5, MAX_STACK = 1_000_000, MAX_MEMO = 4_000_000;
const MAX_LINE = 1 << 16, MAX_STR = 512, MAX_INFLATE = 64 * 1024 * 1024, MAX_MEMBERS = 100_000;
const MAX_ST_HEADER = 16 * 1024 * 1024, MAX_GGUF_META = 256 * 1024 * 1024, MAX_TEMPLATE = 1 << 20;
const WINDOW = 4 * 1024 * 1024, MAX_SECONDS = 10;

// ---- rules shared with the CLI -------------------------------------------------------------------
const EXECUTABLE_SERIALIZATION = new Set(['.pkl', '.pickle', '.pt', '.pth', '.bin', '.ckpt', '.joblib', '.npy', '.npz', '.h5', '.keras', '.mar', '.nemo']);
const PICKLE_CANDIDATES = new Set(['.pkl', '.pickle', '.pt', '.pth', '.bin', '.ckpt', '.joblib', '.npy', '.npz', '.mar', '.nemo']);
const CODE_SUFFIXES = new Set(['.py', '.pyc', '.pyo', '.pyd', '.sh', '.bash', '.bat', '.cmd', '.ps1', '.so', '.dll', '.dylib', '.exe', '.js', '.jar']);
const ARCHIVE_SUFFIXES = new Set(['.7z', '.rar', '.tar', '.tgz', '.gz', '.bz2', '.xz', '.zst', '.lz4']);
const EXPECTED = {'.safetensors': 'safetensors', '.gguf': 'gguf', '.npy': 'npy', '.npz': 'zip'};
const AUTO_MAP_FILES = new Set(['config.json', 'tokenizer_config.json', 'preprocessor_config.json', 'processor_config.json', 'feature_extractor_config.json', 'image_processor_config.json', 'video_preprocessor_config.json']);
const TEMPLATE_FILES = new Set(['chat_template.jinja', 'chat_template.json']);

const DANGEROUS_MODULES = new Set(['os', 'posix', 'nt', 'subprocess', 'sys', 'socket', 'shutil', 'pty', 'commands', 'importlib',
  'runpy', 'webbrowser', 'ctypes', 'marshal', 'pickle', '_pickle', 'cPickle', 'code', 'codeop', 'multiprocessing', 'asyncio',
  'threading', '_thread', 'signal', 'tempfile', 'urllib', 'http', 'requests', 'ftplib', 'smtplib', 'telnetlib', 'pip',
  'setuptools', 'timeit', 'platform', 'sysconfig', 'pdb', 'bdb', 'ssl', 'posixpath', 'ntpath', 'genericpath', 'distutils',
  'lib2to3', 'idlelib', 'pydoc', 'trace', 'cProfile', 'profile', 'operator', '_operator', 'functools', '_functools', 'types',
  'io', '_io', 'pathlib', 'glob', 'fileinput', 'linecache', 'zipimport', 'imp', 'pkgutil', 'site', 'dill', 'cloudpickle',
  'joblib', 'shelve', 'dbm', 'sqlite3', 'xmlrpc', 'smtpd', 'socketserver', 'gc', 'inspect', 'numpy.testing', 'numpy.f2py',
  'numpy.distutils', 'numpy.lib.utils', 'torch.hub', 'torch.utils.bottleneck', 'torch.jit', 'torch.distributed', 'torch._dynamo',
  'torch._inductor', 'torch.fx', 'torch.serialization', 'torch.storage', 'torch.utils.cpp_extension', 'torch.package',
  'keras.models', 'tensorflow.io', 'venv', 'ensurepip', 'httplib', 'urllib2', 'urllib3', 'httplib2', 'aiohttp', 'httpx',
  'paramiko', 'pycurl', 'websocket', 'websockets', 'poplib', 'imaplib', 'nntplib', 'xmlrpclib', 'SimpleHTTPServer', 'popen2',
  'pexpect', 'sh', 'plumbum', 'fabric', 'invoke', 'uvicorn', 'flask', 'fastapi']);
const SAFE_BUILTINS = new Set(['set', 'frozenset', 'dict', 'list', 'tuple', 'int', 'float', 'complex', 'bool', 'str', 'bytes', 'bytearray', 'slice', 'range']);
const TORCH_NAMES = new Set(['float32', 'float', 'float64', 'double', 'float16', 'half', 'bfloat16', 'uint8', 'int8', 'int16', 'short',
  'int32', 'int', 'int64', 'long', 'bool', 'complex64', 'complex128', 'float8_e4m3fn', 'float8_e5m2', 'uint16', 'uint32', 'uint64',
  'FloatStorage', 'HalfStorage', 'BFloat16Storage', 'LongStorage', 'IntStorage', 'ByteStorage', 'BoolStorage', 'DoubleStorage',
  'ShortStorage', 'CharStorage', 'ComplexFloatStorage', 'ComplexDoubleStorage', 'UntypedStorage', 'TypedStorage', 'QInt8Storage',
  'QUInt8Storage', 'QInt32Storage', 'Size', 'device', 'Tensor', 'dtype', 'memory_format', 'layout']);
const SAFE_GLOBALS = new Set(['collections.OrderedDict', 'collections.defaultdict', 'collections.deque', 'torch._utils._rebuild_tensor',
  'torch._utils._rebuild_tensor_v2', 'torch._utils._rebuild_tensor_v3', 'torch._utils._rebuild_parameter',
  'torch._utils._rebuild_parameter_with_state', 'torch._utils._rebuild_qtensor', 'torch._utils._rebuild_meta_tensor_no_storage',
  'torch._utils._rebuild_device_tensor_from_numpy', 'torch._tensor._rebuild_from_type_v2', 'numpy.core.multiarray._reconstruct',
  'numpy.core.multiarray.scalar', 'numpy._core.multiarray._reconstruct', 'numpy._core.multiarray.scalar', 'numpy.ndarray',
  'numpy.dtype', 'numpy.dtypes.Float32DType', '_codecs.encode'].map(s => { const i = s.lastIndexOf('.'); return s.slice(0, i) + '\u0000' + s.slice(i + 1); }));
const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;

export function classify(module, name) {
  if (typeof module !== 'string' || typeof name !== 'string') return 'high';
  if (name.includes('__')) return 'high';
  const parts = module.split('.');
  for (let i = 1; i <= parts.length; i++) if (DANGEROUS_MODULES.has(parts.slice(0, i).join('.'))) return 'high';
  if (parts[0] === 'builtins' || parts[0] === '__builtin__') return SAFE_BUILTINS.has(name) ? null : 'high';
  if (name.includes('.') || !IDENT.test(name)) return 'review';
  if (SAFE_GLOBALS.has(module + '\u0000' + name)) return null;
  if (module === 'torch' && TORCH_NAMES.has(name)) return null;
  if (module.startsWith('torch.nn.modules.') || module.startsWith('torch.nn.parameter')) return null;
  return 'review';
}

// ---- byte sources ------------------------------------------------------------------------------
export class BlobSource {
  constructor(blob) { this.blob = blob; this.size = blob.size; }
  async read(start, len) {
    const end = Math.min(this.size, start + len);
    if (end <= start) return new Uint8Array(0);
    return new Uint8Array(await this.blob.slice(start, end).arrayBuffer());
  }
}
class BytesSource {
  constructor(bytes) { this.bytes = bytes; this.size = bytes.length; }
  async read(start, len) { return this.bytes.subarray(Math.max(0, start), Math.min(this.size, start + len)); }
}
const u32 = (b, p) => (b[p] | (b[p + 1] << 8) | (b[p + 2] << 16)) + b[p + 3] * 0x1000000;
const i32 = (b, p) => b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] << 24);
const u16 = (b, p) => b[p] | (b[p + 1] << 8);
const u64 = (b, p) => { const lo = u32(b, p), hi = u32(b, p + 4); return hi >= 0x200000 ? Infinity : hi * 0x100000000 + lo; };
const latin1 = bytes => { let s = ''; for (let i = 0; i < bytes.length; i += 8192) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192)); return s; };
const utf8 = new TextDecoder('utf-8', {fatal: true}), utf8Loose = new TextDecoder('utf-8');
const count = n => (typeof n === 'bigint' ? (n < 2n ** 53n ? String(n) : 'an out-of-range number of')
  : (Number.isFinite(n) && n < 2 ** 53 ? String(n) : 'an out-of-range number of'));
const u64n = (b, p) => BigInt(u32(b, p)) | (BigInt(u32(b, p + 4)) << 32n);
const CP437 = 'ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u00a0';
const cp437 = bytes => { let s = ''; for (const c of bytes) s += c < 128 ? String.fromCharCode(c) : CP437[c - 128]; return s; };

// ---- pickle ------------------------------------------------------------------------------------
// [code, name, argKind, n, pre, hasMark, push, special, codec] generated from Python's pickletools metadata
const OPS = [[40,"MARK",0,0,0,0,1,10,-1],[41,"EMPTY_TUPLE",0,0,0,0,1,0,-1],[46,"STOP",0,0,1,0,0,9,-1],[48,"POP",0,0,1,0,0,0,-1],[49,"POP_MARK",0,0,0,1,0,0,-1],[50,"DUP",0,0,1,0,2,2,-1],[66,"BINBYTES",4,0,0,0,1,0,-1],[67,"SHORT_BINBYTES",2,0,0,0,1,0,-1],[70,"FLOAT",6,0,0,0,1,0,-1],[71,"BINFLOAT",1,8,0,0,1,0,-1],[73,"INT",6,0,0,0,1,0,-1],[74,"BININT",1,4,0,0,1,0,-1],[75,"BININT1",1,1,0,0,1,0,-1],[76,"LONG",6,0,0,0,1,0,-1],[77,"BININT2",1,2,0,0,1,0,-1],[78,"NONE",0,0,0,0,1,0,-1],[80,"PERSID",6,0,0,0,1,0,-1],[81,"BINPERSID",0,0,1,0,1,0,-1],[82,"REDUCE",0,0,2,0,1,0,-1],[83,"STRING",6,0,0,0,1,1,2],[84,"BINSTRING",3,0,0,0,1,1,3],[85,"SHORT_BINSTRING",2,0,0,0,1,1,3],[86,"UNICODE",6,0,0,0,1,1,1],[88,"BINUNICODE",4,0,0,0,1,1,0],[93,"EMPTY_LIST",0,0,0,0,1,0,-1],[97,"APPEND",0,0,2,0,1,0,-1],[98,"BUILD",0,0,2,0,1,0,-1],[99,"GLOBAL",7,0,0,0,1,6,-1],[100,"DICT",0,0,0,1,1,0,-1],[101,"APPENDS",0,0,1,1,1,0,-1],[103,"GET",6,0,0,0,1,5,-1],[104,"BINGET",1,1,0,0,1,5,-1],[105,"INST",7,0,0,1,1,7,-1],[106,"LONG_BINGET",1,4,0,0,1,5,-1],[108,"LIST",0,0,0,1,1,0,-1],[111,"OBJ",0,0,0,1,1,0,-1],[112,"PUT",6,0,0,0,0,3,-1],[113,"BINPUT",1,1,0,0,0,3,-1],[114,"LONG_BINPUT",1,4,0,0,0,3,-1],[115,"SETITEM",0,0,3,0,1,0,-1],[116,"TUPLE",0,0,0,1,1,0,-1],[117,"SETITEMS",0,0,1,1,1,0,-1],[125,"EMPTY_DICT",0,0,0,0,1,0,-1],[128,"PROTO",1,1,0,0,0,0,-1],[129,"NEWOBJ",0,0,2,0,1,0,-1],[130,"EXT1",1,1,0,0,1,11,-1],[131,"EXT2",1,2,0,0,1,11,-1],[132,"EXT4",1,4,0,0,1,11,-1],[133,"TUPLE1",0,0,1,0,1,0,-1],[134,"TUPLE2",0,0,2,0,1,0,-1],[135,"TUPLE3",0,0,3,0,1,0,-1],[136,"NEWTRUE",0,0,0,0,1,0,-1],[137,"NEWFALSE",0,0,0,0,1,0,-1],[138,"LONG1",2,0,0,0,1,0,-1],[139,"LONG4",3,0,0,0,1,0,-1],[140,"SHORT_BINUNICODE",2,0,0,0,1,1,0],[141,"BINUNICODE8",5,0,0,0,1,1,0],[142,"BINBYTES8",5,0,0,0,1,0,-1],[143,"EMPTY_SET",0,0,0,0,1,0,-1],[144,"ADDITEMS",0,0,1,1,1,0,-1],[145,"FROZENSET",0,0,0,1,1,0,-1],[146,"NEWOBJ_EX",0,0,3,0,1,0,-1],[147,"STACK_GLOBAL",0,0,2,0,1,8,-1],[148,"MEMOIZE",0,0,1,0,1,4,-1],[149,"FRAME",1,8,0,0,0,0,-1],[150,"BYTEARRAY8",5,0,0,0,1,0,-1],[151,"NEXT_BUFFER",0,0,0,0,1,0,-1],[152,"READONLY_BUFFER",0,0,1,0,1,0,-1]];
const TABLE = new Array(256).fill(null);
for (const op of OPS) TABLE[op[0]] = op;
const A_NONE = 0, A_FIXED = 1, A_LEN1 = 2, A_LEN4S = 3, A_LEN4U = 4, A_LEN8 = 5, A_LINE = 6, A_LINE2 = 7;
const S_GENERIC = 0, S_STR = 1, S_DUP = 2, S_PUT = 3, S_MEMO = 4, S_GET = 5, S_GLOBAL = 6, S_INST = 7, S_SGLOBAL = 8, S_STOP = 9, S_MARK = 10, S_EXT = 11;
const MARK = Symbol('mark'), OPAQUE = Symbol('opaque'), LONG = Symbol('long');
class Malformed extends Error {}
class Limit extends Error {}

function decodeStr(bytes, codec) {
  try {
    if (codec === 0) return utf8.decode(bytes);
    if (codec === 3) { for (const c of bytes) if (c > 127) return OPAQUE; return latin1(bytes); }
    if (codec === 1) return latin1(bytes).replace(/\\u([0-9a-fA-F]{4})|\\U([0-9a-fA-F]{8})/g, (_, a, b) => String.fromCodePoint(parseInt(a || b, 16)));
    const s = latin1(bytes);                                   // STRING: quoted Python repr
    if (s.length < 2 || s[0] !== s[s.length - 1] || (s[0] !== "'" && s[0] !== '"')) return OPAQUE;
    const out = s.slice(1, -1).replace(/\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|.)/gs, (_, e) => {
      if (e[0] === 'x') return String.fromCharCode(parseInt(e.slice(1), 16));
      if (/^[0-7]/.test(e)) return String.fromCharCode(parseInt(e, 8));
      return ({n: '\n', t: '\t', r: '\r', '\\': '\\', "'": "'", '"': '"', a: '\x07', b: '\b', f: '\f', v: '\v'})[e] ?? '\\' + e;
    });
    for (let i = 0; i < out.length; i++) if (out.charCodeAt(i) > 127) return OPAQUE;
    return out;
  } catch { return OPAQUE; }
}

function newState(pos, budget) { return {pos, stack: [], memo: [], sparse: new Map(), budget}; }

// Runs opcodes from state.pos while the window holds enough bytes. Returns 'stop' or 'need'.
function walk(st, win, end, found, notes) {
  const {stack, memo, sparse, budget} = st;
  const b = win.bytes, base = win.base, winEnd = base + b.length;
  let pos = st.pos;
  while (true) {
    if (pos >= end) throw new Malformed('truncated stream (no STOP)');
    if (winEnd < end && pos + 2 * MAX_LINE + 32 > winEnd) { st.pos = pos; return 'need'; }
    const at = pos - base;
    if (at < 0) { st.pos = pos; return 'need'; }
    const spec = TABLE[b[at]];
    if (spec === null) throw new Malformed(`invalid opcode 0x${b[at].toString(16).padStart(2, '0')} at ${pos}`);
    const [, name, kind, n, pre, hasMark, push, special, codec] = spec;
    pos += 1;
    let a = pos, line1 = null, line2 = null, nl = 0;
    if (kind === A_FIXED) pos += n;
    else if (kind === A_LEN1) { if (pos >= end) throw new Malformed('truncated length'); a = pos + 1; pos = a + b[pos - base]; }
    else if (kind === A_LEN4U || kind === A_LEN4S) {
      if (pos + 4 > end) throw new Malformed('truncated length');
      const ln = kind === A_LEN4U ? u32(b, pos - base) : i32(b, pos - base);
      if (ln < 0) throw new Malformed('negative length');
      a = pos + 4; pos = a + ln;
    } else if (kind === A_LEN8) {
      if (pos + 8 > end) throw new Malformed('truncated length');
      a = pos + 8; pos = a + u64(b, pos - base);
    } else if (kind === A_LINE || kind === A_LINE2) {
      const lim = Math.min(end, pos + MAX_LINE, winEnd);
      nl = b.indexOf(10, pos - base);
      if (nl < 0 || nl + base >= lim) throw new Malformed('unterminated text argument');
      nl += base;
      line1 = b.subarray(a - base, nl - base);
      if (kind === A_LINE2) {
        let nl2 = b.indexOf(10, nl + 1 - base);
        if (nl2 < 0 || nl2 + base >= Math.min(end, nl + 1 + MAX_LINE, winEnd)) throw new Malformed('unterminated text argument');
        line2 = b.subarray(nl + 1 - base, nl2);
        pos = nl2 + base + 1;
      } else pos = nl + 1;
    }
    if (pos > end) throw new Malformed(`${name} argument runs past end of data`);
    if (--budget.ops <= 0) throw new Limit('opcode limit reached');
    if ((budget.ops & 0xFFFF) === 0 && Date.now() > budget.deadline) throw new Limit('time limit reached');

    if (special === S_GENERIC) {
      if (hasMark) { let v; do { if (!stack.length) throw new Malformed(`${name} without MARK`); v = stack.pop(); } while (v !== MARK); }
      if (pre) { if (stack.length < pre) throw new Malformed(`stack underflow at ${name}`); stack.length -= pre; }
      if (push) { stack.push(OPAQUE); if (stack.length > MAX_STACK) throw new Limit('stack limit reached'); }
      continue;
    }
    if (special === S_STR) {
      const length = (kind === A_LINE ? nl : pos) - a;
      stack.push(length <= MAX_STR ? decodeStr(b.subarray(a - base, a - base + length), codec) : LONG);
    } else if (special === S_PUT || special === S_MEMO) {
      if (!stack.length) throw new Malformed('memo store on empty stack');
      let idx;
      if (special === S_MEMO) idx = memo.length + sparse.size;
      else if (kind === A_LINE) { idx = Number(latin1(line1)); if (!Number.isInteger(idx)) throw new Malformed('bad PUT index'); }
      else idx = n === 1 ? b[a - base] : u32(b, a - base);
      const value = stack[stack.length - 1];
      if (idx < memo.length) memo[idx] = value;
      else if (idx === memo.length && memo.length < MAX_MEMO) { memo.push(value); while (sparse.has(memo.length)) { const k = memo.length; memo.push(sparse.get(k)); sparse.delete(k); } }
      else if (sparse.size < MAX_MEMO) sparse.set(idx, value);
      else if (budget.memoNote) { budget.memoNote = false; notes.push('Memo limit reached; later memo lookups treated as unknown'); }
    } else if (special === S_GET) {
      let idx;
      if (kind === A_LINE) { idx = Number(latin1(line1)); if (!Number.isInteger(idx)) throw new Malformed('bad GET index'); }
      else idx = n === 1 ? b[a - base] : u32(b, a - base);
      stack.push(idx < memo.length ? memo[idx] : (sparse.has(idx) ? sparse.get(idx) : (budget.memoNote ? OPAQUE : LONG)));
    } else if (special === S_DUP) {
      if (!stack.length) throw new Malformed('DUP on empty stack');
      stack.push(stack[stack.length - 1]);
    } else if (special === S_MARK) stack.push(MARK);
    else if (special === S_GLOBAL || special === S_INST) {
      const module = utf8Loose.decode(line1), attr = utf8Loose.decode(line2);
      found.push([module, attr, classify(module, attr)]);
      if (special === S_INST) { let v; do { if (!stack.length) throw new Malformed('INST without MARK'); v = stack.pop(); } while (v !== MARK); }
      stack.push(OPAQUE);
    } else if (special === S_SGLOBAL) {
      if (stack.length < 2) throw new Malformed('stack underflow at STACK_GLOBAL');
      const attr = stack.pop(), module = stack.pop();
      if (typeof module === 'string' && typeof attr === 'string') found.push([module, attr, classify(module, attr)]);
      else found.push(['<unresolved>', '<unresolved>', 'high']);
      stack.push(OPAQUE);
    } else if (special === S_EXT) { found.push(['copyreg', `<extension ${name}>`, 'review']); stack.push(OPAQUE); }
    else if (special === S_STOP) { st.pos = pos; return 'stop'; }
  }
}

function newBudget() { return {ops: MAX_OPS, deadline: Date.now() + MAX_SECONDS * 1000, memoNote: true}; }

// Scan consecutive pickle streams in source[start:end]. Returns {found, notes}.
export async function scanPickle(source, start = 0, end = source.size, strict = true, budget = newBudget()) {
  const found = [], notes = [];
  let pos = start, win = {base: start, bytes: await source.read(start, WINDOW)};
  for (let index = 0; index < MAX_STREAMS; index++) {
    const before = found.length;
    const st = newState(pos, budget);
    try {
      while (walk(st, win, end, found, notes) === 'need') win = {base: st.pos, bytes: await source.read(st.pos, WINDOW)};
    } catch (e) {
      if (e instanceof Limit) { notes.push(`Scan limit reached (${e.message}); result incomplete`); break; }
      if (e instanceof Malformed) { if (index === 0 && (strict || found.length > before)) notes.push(`Malformed or truncated pickle: ${e.message}`); break; }
      throw e;
    }
    pos = st.pos;
    if (pos >= end) break;
    if (pos - win.base >= win.bytes.length) win = {base: pos, bytes: await source.read(pos, WINDOW)};
    if (win.bytes[pos - win.base] !== 0x80) break;
  }
  return {found, notes};
}

const GLOBAL_START = /^c[A-Za-z_][\w.]*\n[A-Za-z_][\w.]*\n/;
const PROTO0_STARTS = new Set(['(d', '(l', '(i', '(c', '(t', '(S', '(V', '(I', '(F', '(N', '}q', ']q', '(L']);
export function looksLikePickle(head) {
  if (head.length >= 2 && head[0] === 0x80 && head[1] >= 2 && head[1] <= 5) return true;
  if (head.length >= 2 && PROTO0_STARTS.has(String.fromCharCode(head[0], head[1]))) return true;
  return GLOBAL_START.test(latin1(head.subarray(0, 256)));
}

// ---- npy / zip -----------------------------------------------------------------------------------
async function scanNpy(source, start, end, budget, label = 'npy-object') {
  const head = await source.read(start, 12);
  if (head.length < 10 || latin1(head.subarray(0, 6)) !== '\x93NUMPY') return null;
  let hlen, body;
  if (head[6] === 1) { hlen = u16(head, 8); body = start + 10; }
  else { if (head.length < 12) return null; hlen = u32(head, 8); body = start + 12; }
  const header = latin1(await source.read(body, Math.min(hlen, 65536)));
  if (!/['"]\|?O['"]/.test(header)) return null;
  const data = body + hlen, result = {kind: label, found: [], notes: [], flags: []};
  if (data >= end) { result.notes.push('npy object array without payload'); return result; }
  Object.assign(result, await scanPickle(source, data, end, true, budget));
  return result;
}

async function inflateRaw(bytes) {
  // Input is fed in small pieces so that, like zlib.decompressobj in the CLI, everything decoded before a corrupt
  // or truncated point is kept (DecompressionStream drops pending output when it errors).
  if (typeof DecompressionStream === 'undefined') return null;
  const ds = new DecompressionStream('deflate-raw'), writer = ds.writable.getWriter(), reader = ds.readable.getReader();
  const chunks = [];
  let size = 0, failed = false, errored = false;
  const pump = (async () => {
    try {
      while (true) {
        const {done, value} = await reader.read();
        if (done) break;
        size += value.length;
        if (size > MAX_INFLATE) { failed = true; await reader.cancel(); break; }
        chunks.push(value);
      }
    } catch { errored = true; }           // corrupt stream: keep partial output
  })();
  try {
    for (let o = 0; o < bytes.length && !failed; o += 256) await writer.write(bytes.subarray(o, o + 256));
    await writer.close();
  } catch { /* the reader side reports the same error */ }
  await pump;
  if (failed || (errored && !size)) return null;
  const out = new Uint8Array(size);
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.length; }
  return out;
}

export async function zipEntries(source) {
  // Mirrors Python's zipfile: the central directory is located from the end record and any data prepended to the
  // archive (self-extractors, shifted offsets) is compensated for, so both engines inspect the same members.
  const tailLen = Math.min(source.size, 65557);
  const tailBase = source.size - tailLen, tail = await source.read(tailBase, tailLen);
  let e = -1;
  for (let i = tail.length - 22; i >= 0; i--) if (tail[i] === 0x50 && tail[i + 1] === 0x4b && tail[i + 2] === 5 && tail[i + 3] === 6) { e = i; break; }
  if (e < 0) throw new Error('no end of central directory');
  let count = u16(tail, e + 10), cdSize = u32(tail, e + 12), cdOff = u32(tail, e + 16), endPos = tailBase + e;
  // Port of zipfile._EndRecData64: a ZIP64 locator right before the end record is always honoured, even when the
  // classic fields are not saturated (PyTorch/miniz writes ZIP64 records for small archives too).
  let off = tailBase + e - 20;
  if (off >= 0) {
    const locator = await source.read(off, 20);
    if (locator.length === 20 && u32(locator, 0) === 0x07064b50) {
      if (u32(locator, 4) !== 0 || u32(locator, 16) > 1) throw new Error('multi-disk archive');
      const reloff = u64(locator, 8);
      off -= 56;
      if (reloff > off) throw new Error('corrupt ZIP64 locator');
      let extra = off - reloff, rec = await source.read(reloff, 56);
      if (!(rec.length === 56 && u32(rec, 0) === 0x06064b50) && reloff !== off) { rec = await source.read(off, 56); extra = 0; }
      if (rec.length < 56 || u32(rec, 0) !== 0x06064b50) throw new Error('ZIP64 end record not found');
      count = u64(rec, 32); cdSize = u64(rec, 40); cdOff = u64(rec, 48);
      if (cdOff + cdSize !== reloff || u64(rec, 4) + 12 !== 56 + extra) throw new Error('corrupt ZIP64 end record');
      endPos = off - extra;
    }
  }
  const start = endPos - cdSize, concat = start - cdOff;
  if (start < 0 || cdSize > 512 * 1024 * 1024) throw new Error('central directory out of range');
  const cd = await source.read(start, cdSize), entries = [];
  for (let p = 0; p < cd.length && entries.length < MAX_MEMBERS; ) {
    if (p + 46 > cd.length || u32(cd, p) !== 0x02014b50) throw new Error('bad central directory entry');
    if (cd[p + 6] > 63) throw new Error('unsupported zip version');   // extract_version is one byte, as in zipfile
    const flags = u16(cd, p + 8), method = u16(cd, p + 10);
    let csize = u32(cd, p + 20), usize = u32(cd, p + 24), lho = u32(cd, p + 42);
    const nlen = u16(cd, p + 28), elen = u16(cd, p + 30), clen = u16(cd, p + 32);
    const rawName = cd.subarray(p + 46, p + 46 + nlen);
    let name = flags & 0x800 ? utf8.decode(rawName) : cp437(rawName);     // throws on invalid UTF-8, like zipfile
    if (name.includes('\0')) name = name.slice(0, name.indexOf('\0'));   // zipfile truncates names at NUL
    const extraEnd = Math.min(cd.length, p + 46 + nlen + elen);
    for (let x = p + 46 + nlen; x + 4 <= extraEnd; ) {                          // extra fields, validated like zipfile
      const id = u16(cd, x), sz = u16(cd, x + 2);
      if (x + 4 + sz > extraEnd) throw new Error('corrupt extra field');
      if (id === 1) {                                                          // ZIP64 sizes and offset
        let y = x + 4;
        const take = () => { if (y + 8 > x + 4 + sz) throw new Error('corrupt zip64 extra field'); const v = u64(cd, y); y += 8; return v; };
        if (usize === 0xFFFFFFFF) usize = take();
        if (csize === 0xFFFFFFFF) csize = take();
        if (lho === 0xFFFFFFFF) lho = take();
      }
      x += 4 + sz;
    }
    entries.push({name, flags, method, csize, usize, lho: lho + concat});
    p += 46 + nlen + elen + clen;
  }
  return {entries, total: Math.max(count, entries.length)};
}

async function memberSource(source, entry) {
  const local = await source.read(entry.lho, 30);
  if (local.length < 30 || u32(local, 0) !== 0x04034b50) return null;
  const start = entry.lho + 30 + u16(local, 26) + u16(local, 28);
  if (entry.method === 0) {
    if (start + entry.usize > source.size) return null;
    return {src: source, start, end: start + entry.usize};
  }
  if (entry.method === 8 && !(entry.flags & 1)) {          // declared sizes are attacker-controlled: cap the real output
    const data = await inflateRaw(await source.read(start, Math.min(entry.csize, MAX_INFLATE)));
    return data ? {src: new BytesSource(data), start: 0, end: data.length} : null;
  }
  return null;
}

async function scanZip(source) {
  const result = {kind: 'zip', found: [], notes: [], flags: []}, budget = newBudget();
  let listing;
  try { listing = await zipEntries(source); }
  catch { result.notes.push('Unreadable or corrupt zip archive'); return result; }
  const {entries, total} = listing;
  if (total > MAX_MEMBERS) result.notes.push(`Archive has ${total} members; only the first ${MAX_MEMBERS} inspected`);
  const names = entries.map(x => x.name);
  const prefixes = names.filter(n => n === 'data.pkl' || n.endsWith('/data.pkl')).map(n => n.slice(0, -'data.pkl'.length));
  if (prefixes.length) result.kind = 'torch-zip';
  if (names.some(n => n.includes('/code/') && n.endsWith('.py'))) result.flags.push(['MG014', 'review', 'TorchScript archive: contains serialized code that runs when loaded with torch.jit.load']);
  const storageDirs = prefixes.map(p => p + 'data/');
  for (const entry of entries) {
    const fname = entry.name, short = fname.slice(0, 120);
    if (fname.startsWith('/') || fname.replaceAll('\\', '/').split('/').includes('..')) result.notes.push('Unsafe archive member name: ' + short);
    if (fname.endsWith('/') || storageDirs.some(d => fname.startsWith(d))) continue;
    const named = /\.(pkl|pickle|npy)$/.test(fname), encrypted = !!(entry.flags & 1);
    const m = await memberSource(source, entry);
    if (!m) { if (named) result.notes.push(`${encrypted ? 'Encrypted' : 'Oversized or unsupported'} archive member not inspected: ${short}`); continue; }
    const head = await m.src.read(m.start, Math.min(256, m.end - m.start));
    let found, notes;
    if (fname.endsWith('.npy') || latin1(head.subarray(0, 6)) === '\x93NUMPY') {
      const sub = await scanNpy(m.src, m.start, m.end, budget, 'npz-object');
      if (!sub) continue;
      ({found, notes} = sub);
      if (result.kind === 'zip') result.kind = 'npz';
    } else if (named || looksLikePickle(head)) {
      ({found, notes} = await scanPickle(m.src, m.start, m.end, named, budget));
      if (!named && found.length) result.notes.push(`Pickle stored under a non-pickle name: ${short}`);
    } else continue;
    if (encrypted && (found.length || notes.length)) result.notes.push(`Encryption flag set on a plaintext member: ${short} (some loaders ignore the flag)`);
    result.found.push(...found);
    result.notes.push(...notes.map(n => `${short}: ${n}`));
  }
  return result;
}

// ---- safetensors / GGUF --------------------------------------------------------------------------
const ST_DTYPES = {BOOL: 1, U8: 1, I8: 1, F8_E5M2: 1, F8_E4M3: 1, F8_E4M3FN: 1, F8_E8M0: 1, I16: 2, U16: 2, F16: 2, BF16: 2, I32: 4, U32: 4, F32: 4, I64: 8, U64: 8, F64: 8, C64: 8, C128: 16};
const ST_BITS = {F4: 4, F6_E2M3: 6, F6_E3M2: 6, U4: 4, I4: 4};

// JSON.parse silently keeps the last duplicate key; parsers that keep the first see different tensors.
function hasDuplicateKeys(text) {
  const stack = [];
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      const top = stack[stack.length - 1];
      if (top && top.expectKey) {
        const key = JSON.parse(text.slice(i, j + 1));
        if (top.keys.has(key)) return true;
        top.keys.add(key);
        top.expectKey = false;
      }
      i = j;
    } else if (c === '{') stack.push({keys: new Set(), expectKey: true});
    else if (c === '[') stack.push(null);
    else if (c === '}' || c === ']') stack.pop();
    else if (c === ',' && stack[stack.length - 1]) stack[stack.length - 1].expectKey = true;
  }
  return false;
}

async function checkSafetensors(source) {
  const size = source.size, raw = await source.read(0, 8);
  if (raw.length < 8) return ['File shorter than 8-byte header length'];
  const n = u64(raw, 0);
  if (n > MAX_ST_HEADER || 8 + n > size) return [`Header length ${count(n)} exceeds limit or file size`];
  const header = await source.read(8, n), issues = [];
  if (header[0] !== 0x7b) issues.push('Header does not start with "{"');
  let meta;
  let text;
  try { text = utf8.decode(header); meta = JSON.parse(text); } catch { return issues.concat(['Header is not valid JSON']); }
  if (hasDuplicateKeys(text)) return issues.concat(['Duplicate keys in header JSON']);
  if (!meta || typeof meta !== 'object' || Array.isArray(meta)) return issues.concat(['Header JSON is not an object']);
  const body = size - 8 - n, spans = [];
  for (const [name, entry] of Object.entries(meta)) {
    const label = name.slice(0, 80);
    if (name === '__metadata__') {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry) || !Object.values(entry).every(v => typeof v === 'string')) issues.push('__metadata__ must map strings to strings');
      continue;
    }
    const offs = entry && entry.data_offsets, shape = entry && entry.shape;
    const ok = entry && typeof entry === 'object' && 'dtype' in entry && Array.isArray(offs) && offs.length === 2 && offs.every(Number.isInteger)
      && 0 <= offs[0] && offs[0] <= offs[1] && Array.isArray(shape) && shape.every(d => Number.isInteger(d) && d >= 0);
    if (!ok) { issues.push(`Malformed tensor entry: ${label}`); continue; }
    const count = shape.reduce((x, y) => x * y, 1);
    let expected = null;
    if (entry.dtype in ST_DTYPES) expected = ST_DTYPES[entry.dtype] * count;
    else if (entry.dtype in ST_BITS) expected = Math.ceil(ST_BITS[entry.dtype] * count / 8);
    else issues.push(`Unknown dtype ${JSON.stringify(String(entry.dtype).slice(0, 20))} for ${label}`);
    if (expected !== null && expected !== offs[1] - offs[0]) issues.push(`Byte span does not match dtype/shape: ${label}`);
    spans.push([offs[0], offs[1], label]);
  }
  spans.sort((x, y) => x[0] - y[0] || x[1] - y[1]);
  let cursor = 0;
  for (const [begin, end, label] of spans) {
    if (begin !== cursor) issues.push(`${begin > cursor ? 'Gap' : 'Overlap'} before tensor ${label}`);
    cursor = Math.max(cursor, end);
  }
  if (cursor !== body) issues.push(`Tensor data covers ${cursor} bytes but file body is ${body}`);
  return issues;
}

const GGUF_SCALARS = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8};
const GGML_TYPES = {0: [1, 4], 1: [1, 2], 2: [32, 18], 3: [32, 20], 6: [32, 22], 7: [32, 24], 8: [32, 34], 9: [32, 36], 10: [256, 84],
  11: [256, 110], 12: [256, 144], 13: [256, 176], 14: [256, 210], 15: [256, 292], 16: [256, 66], 17: [256, 74], 18: [256, 98],
  19: [256, 50], 20: [32, 18], 21: [256, 110], 22: [256, 82], 23: [256, 136], 24: [1, 1], 25: [1, 2], 26: [1, 4], 27: [1, 8],
  28: [1, 8], 29: [256, 56], 30: [1, 2], 34: [256, 54], 35: [256, 66], 39: [32, 17]};
class NeedMore extends Error {}
class GgufError extends Error {}

function parseGguf(b, size, issues, info) {
  let p = 0;
  const need = n => { if (p + n > size) throw new GgufError('read past end of file'); if (p + n > b.length) throw new NeedMore(); };
  const r32 = () => { need(4); const v = u32(b, p); p += 4; return v; };
  const r64 = () => { need(8); const v = u64(b, p); p += 8; return v; };
  const skip = n => { if (n === Infinity || p + n > size) throw new GgufError('read past end of file'); p += n; };
  const str = keep => { const n = r64(); if (n > (1 << 24)) throw new GgufError('string too long'); need(n); const s = n <= keep ? utf8Loose.decode(b.subarray(p, p + n)) : null; p += n; return s; };
  const skipValue = (kind, depth) => {
    if (kind in GGUF_SCALARS) { need(GGUF_SCALARS[kind]); p += GGUF_SCALARS[kind]; }
    else if (kind === 8) { const n = r64(); if (n > (1 << 24)) throw new GgufError('string too long'); skip(n); }
    else if (kind === 9) {
      if (depth > 4) throw new GgufError('array nesting too deep');
      const inner = r32(), n = r64();
      if (n > (1 << 26)) throw new GgufError('array too large');
      if (inner in GGUF_SCALARS) skip(GGUF_SCALARS[inner] * n);
      else if (inner === 8) {                     // tokenizer vocab: walk lengths only, like the CLI
        for (let i = 0; i < n; i++) { if (p + 8 > size) throw new GgufError('read past end of file'); need(8); p += 8 + u64(b, p); }
        if (p > size) throw new GgufError('read past end of file');
      } else for (let i = 0; i < n; i++) skipValue(inner, depth + 1);
    } else throw new GgufError(`unknown value type ${kind}`);
  };
  need(4);
  if (latin1(b.subarray(0, 4)) !== 'GGUF') { issues.push('Missing GGUF magic'); return; }
  p = 4;
  const version = r32(), tensors = r64(), kvs = r64();
  Object.assign(info, {version, tensor_count: tensors, kv_count: kvs});
  if (version !== 2 && version !== 3) issues.push(`Unsupported GGUF version ${version}`);
  if (tensors > 1_000_000 || kvs > 100_000) { issues.push('Tensor or metadata count exceeds limit'); return; }
  let alignment = 32;
  const templates = {}, keys = new Set();
  for (let i = 0; i < kvs; i++) {
    const key = str(4096) ?? '<long key>';
    if (keys.has(key)) issues.push(`Duplicate metadata key ${key.slice(0, 60)}`);
    keys.add(key);
    const kind = r32();
    if (key === 'general.alignment' && kind === 4) alignment = r32();
    else if (key.startsWith('tokenizer.chat_template') && kind === 8) {
      const text = str(MAX_TEMPLATE);
      if (text === null) issues.push(`${key.slice(0, 60)} longer than ${MAX_TEMPLATE} bytes; not inspected`);
      else templates[key] = text;
    } else skipValue(kind, 0);
  }
  if (Object.keys(templates).length) info.chat_templates = templates;
  if (alignment <= 0 || (alignment & (alignment - 1))) { issues.push(`Invalid alignment ${alignment}`); alignment = 32; }
  const spans = [], names = new Set(), unknown = new Set();
  for (let i = 0; i < tensors; i++) {
    const name = str(4096) ?? '<long name>';
    if (names.has(name)) issues.push(`Duplicate tensor name ${name.slice(0, 60)}`);
    names.add(name);
    const dims = r32();
    if (dims > 8) throw new GgufError(`tensor ${name.slice(0, 60)} has ${dims} dims`);
    const shape = [];                                  // exact 64-bit arithmetic: offsets/sizes are attacker-chosen
    for (let d = 0; d < dims; d++) { need(8); shape.push(u64n(b, p)); p += 8; }
    const type = r32();
    need(8);
    const offset = u64n(b, p);
    p += 8;
    if (offset % BigInt(alignment)) issues.push(`Misaligned offset for ${name.slice(0, 60)}`);
    const layout = GGML_TYPES[type];
    if (!layout) { unknown.add(type); spans.push([offset, offset, name]); continue; }
    if (shape.length && shape[0] % BigInt(layout[0])) issues.push(`Tensor ${name.slice(0, 60)} row size not divisible by block size`);
    spans.push([offset, offset + shape.reduce((x, y) => x * y, 1n) / BigInt(layout[0]) * BigInt(layout[1]), name]);
  }
  const dataStart = Math.ceil(p / alignment) * alignment;
  info.data_start = dataStart;
  if (unknown.size) info.unknown_tensor_types = [...unknown].sort((x, y) => x - y);
  if (dataStart > size) { issues.push('Tensor data section starts past end of file'); return; }
  const cmp = (x, y) => (x < y ? -1 : x > y ? 1 : 0);
  spans.sort((x, y) => cmp(x[0], y[0]) || cmp(x[1], y[1]) || cmp(x[2], y[2]));
  let cursor = 0n;
  const align = BigInt(alignment), total = BigInt(size);
  for (const [begin, end, name] of spans) {
    if (begin < cursor) issues.push(`Tensor ${name.slice(0, 60)} overlaps the previous tensor`);
    else if (begin - cursor >= align) issues.push(`Unexpected ${count(begin - cursor)}-byte gap before tensor ${name.slice(0, 60)}`);
    if (end > cursor) cursor = end;
  }
  const dataEnd = BigInt(dataStart) + cursor;
  if (dataEnd > total) issues.push(`Tensor data extends ${count(dataEnd - total)} bytes beyond end of file`);
  else if (!unknown.size && total - dataEnd >= align) issues.push(`${count(total - dataEnd)} trailing bytes after tensor data`);
}

async function checkGguf(source) {
  if (source.size < 4) return {issues: ['Missing GGUF magic'], info: {}};
  for (let len = 8 * 1024 * 1024; ; len *= 4) {
    const issues = [], info = {};
    const b = await source.read(0, Math.min(source.size, len));
    try { parseGguf(b, source.size, issues, info); return {issues, info}; }
    catch (e) {
      if (e instanceof NeedMore && len < MAX_GGUF_META) continue;
      if (e instanceof NeedMore) return {issues: issues.concat(['Metadata larger than 256 MB; not inspected in the browser']), info};
      if (e instanceof GgufError) return {issues: issues.concat([`Malformed GGUF: ${e.message}`]), info};
      throw e;
    }
  }
}

// ---- chat templates -------------------------------------------------------------------------------
const TPL_HIGH = [[/__[A-Za-z]\w*__/, 'dunder attribute access'], [/\\x5f|\\u005f|\\137|\\N\{LOW LINE\}/i, 'escaped underscore (obfuscated attribute)'],
  [/_TemplateReference__|\b(?:os|subprocess)\.(?:popen|system|exec)/i, 'sandbox escape pattern'],
  [/\b(?:lipsum|cycler|joiner|url_for|get_flashed_messages)\b\s*[.[|]/, 'Jinja global used as gadget']];
const TPL_REVIEW = [[/\|\s*attr\s*\(/, 'attr() filter'], [/\b(?:self|config|request)\s*[.[]/, 'access to template context objects'],
  [/\b(?:import|include|extends|from)\b[^%]*%\}/, 'template loads other templates'], [/\bhttps?:\/\//i, 'URL inside template']];
export function checkTemplate(text) {
  const out = [];
  for (const [re, reason] of TPL_HIGH) if (re.test(text)) out.push(['high', reason]);
  for (const [re, reason] of TPL_REVIEW) if (re.test(text)) out.push(['review', reason]);
  return out;
}

// ---- SHA-256 (incremental, so files of any size are hashed in slices) ----------------------------
const K = new Uint32Array([0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
export class Sha256 {
  constructor() { this.h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]); this.buf = new Uint8Array(64); this.fill = 0; this.len = 0; this.w = new Uint32Array(64); }
  block(b, o) {
    const w = this.w, h = this.h;
    for (let i = 0; i < 16; i++) w[i] = (b[o + 4 * i] << 24) | (b[o + 4 * i + 1] << 16) | (b[o + 4 * i + 2] << 8) | b[o + 4 * i + 3];
    for (let i = 16; i < 64; i++) {
      const x = w[i - 15], y = w[i - 2];
      w[i] = (((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3)) + w[i - 16] + (((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10)) + w[i - 7];
    }
    let a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (let i = 0; i < 64; i++) {
      const t1 = hh + (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + K[i] + w[i] | 0;
      const t2 = (((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) + ((a & bb) ^ (a & c) ^ (bb & c)) | 0;
      hh = g; g = f; f = e; e = d + t1 | 0; d = c; c = bb; bb = a; a = t1 + t2 | 0;
    }
    h[0] += a; h[1] += bb; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }
  update(data) {
    let i = 0;
    this.len += data.length;
    if (this.fill) { while (this.fill < 64 && i < data.length) this.buf[this.fill++] = data[i++]; if (this.fill === 64) { this.block(this.buf, 0); this.fill = 0; } }
    for (; i + 64 <= data.length; i += 64) this.block(data, i);
    while (i < data.length) this.buf[this.fill++] = data[i++];
  }
  hex() {
    const bits = this.len * 8, pad = new Uint8Array(((this.fill < 56) ? 56 : 120) - this.fill + 8);
    pad[0] = 0x80;
    for (let i = 0; i < 8; i++) pad[pad.length - 1 - i] = Math.floor(bits / 2 ** (8 * i)) & 0xff;
    this.update(pad);
    return Array.from(this.h, v => v.toString(16).padStart(8, '0')).join('');
  }
}
export async function sha256Blob(blob, onProgress) {
  // Native WebCrypto is one-shot (needs the whole file in memory): use it only for files up to 64 MB.
  if (blob.size <= 64 * 1024 * 1024 && globalThis.crypto?.subtle) {
    const digest = await crypto.subtle.digest('SHA-256', await blob.arrayBuffer());
    return Array.from(new Uint8Array(digest), x => x.toString(16).padStart(2, '0')).join('');
  }
  const hash = new Sha256(), step = 4 * 1024 * 1024;
  for (let o = 0; o < blob.size; o += step) {
    hash.update(new Uint8Array(await blob.slice(o, o + step).arrayBuffer()));
    if (onProgress) onProgress(Math.min(blob.size, o + step), blob.size);
  }
  return hash.hex();
}

// ---- file inspection ------------------------------------------------------------------------------
const finding = (rule, severity, file, message) => ({rule, severity, file, message});
const suffixOf = name => { const base = name.split('/').pop(), i = base.lastIndexOf('.'); return i > 0 ? base.slice(i).toLowerCase() : ''; };

export function extensionFindings(name) {
  const suffix = suffixOf(name), out = [];
  if (EXECUTABLE_SERIALIZATION.has(suffix)) out.push(finding('MG001', 'review', name, 'Potential executable serialization; extension alone cannot identify malicious content.'));
  if (ARCHIVE_SUFFIXES.has(suffix)) out.push(finding('MG016', 'review', name, 'Archive format not inspected; extract it and scan the contents.'));
  if (CODE_SUFFIXES.has(suffix)) out.push(finding('MG002', 'review', name, 'Code or native executable present; it is never executed by ModelGuard.'));
  return out;
}

export function sniff(head, size) {
  const sig = latin1(head.subarray(0, 6));
  if (sig.startsWith('GGUF')) return 'gguf';
  if (sig === '\x93NUMPY') return 'npy';
  if (sig.startsWith('PK\x03\x04') || sig.startsWith('PK\x05\x06')) return 'zip';
  if (looksLikePickle(head)) return 'pickle';
  if (head.length >= 9) {
    const n = u64(head, 0);
    if (head[8] === 0x7b && n > 0 && n <= MAX_ST_HEADER && 8 + n <= size) return 'safetensors';
  }
  return null;
}

function pickleFindings(result, name) {
  const out = [], high = new Set(), review = new Map();
  for (const [module, attr, sev] of result.found) {
    if (sev === 'high') high.add(`${module}.${attr}`);
    else if (sev) { const pkg = module.split('.')[0]; if (!review.has(pkg)) review.set(pkg, new Set()); review.get(pkg).add(`${module}.${attr}`); }
  }
  for (const t of high) out.push(finding('MG006', 'high', name, `Dangerous global in ${result.kind} stream: ${t} (static opcode scan, not executed)`));
  for (const [pkg, names] of review) {
    const list = [...names], shown = list.slice(0, 4).join(', ') + (list.length > 4 ? ` (+${list.length - 4} more)` : '');
    out.push(finding('MG006', 'review', name, `${result.kind} stream imports ${list.length} non-allowlisted global(s) from package '${pkg}': ${shown}. Loading would run code from that package.`));
  }
  for (const note of new Set(result.notes)) out.push(finding('MG007', 'review', name, note));
  for (const [rule, sev, message] of result.flags) out.push(finding(rule, sev, name, message));
  return out;
}

const templateFindings = (text, name, where) => checkTemplate(text).map(([sev, reason]) => finding('MG015', sev, name, `Chat template (${where}): ${reason}. Templates are rendered by the inference runtime; unsandboxed Jinja can execute code.`));

async function configFindings(blob, name, base) {
  if (blob.size > 2 * 1024 * 1024) return [finding('MG005', 'review', name, 'Config larger than 2 MiB; not inspected')];
  const text = utf8Loose.decode(new Uint8Array(await blob.arrayBuffer()));
  if (base === 'chat_template.jinja') return templateFindings(text, name, base);
  let config;
  try { config = JSON.parse(text); } catch { return [finding('MG005', 'review', name, 'Invalid JSON')]; }
  const out = [];
  if (!config || typeof config !== 'object' || Array.isArray(config)) return out;
  if (config.auto_map && (typeof config.auto_map !== 'object' || Object.keys(config.auto_map).length)) out.push(finding('MG004', 'review', name, 'auto_map references custom code; review the referenced Python files before enabling trust_remote_code.'));
  if (config.custom_pipelines && (typeof config.custom_pipelines !== 'object' || Object.keys(config.custom_pipelines).length)) out.push(finding('MG004', 'review', name, 'custom_pipelines references custom code.'));
  const tpl = config.chat_template;
  if (typeof tpl === 'string') out.push(...templateFindings(tpl, name, 'chat_template'));
  else if (Array.isArray(tpl)) for (const item of tpl) if (item && typeof item.template === 'string') out.push(...templateFindings(item.template, name, `chat_template:${item.name ?? '?'}`));
  return out;
}

// Content checks for one file (a Blob/File). name is the relative path shown in the report.
export async function inspectFile(blob, name) {
  const source = new BlobSource(blob), size = blob.size, suffix = suffixOf(name), base = name.split('/').pop();
  const out = [];
  const head = size ? await source.read(0, 256) : new Uint8Array(0);
  const kind = size ? sniff(head, size) : null;
  const expected = EXPECTED[suffix];
  if (expected && kind !== expected) out.push(finding('MG010', kind === 'pickle' || kind === 'zip' ? 'high' : 'review', name, `Extension ${suffix} but content signature is ${kind || 'unknown'}`));
  if (kind === 'safetensors' || (suffix === '.safetensors' && kind === null && size)) {
    for (const i of await checkSafetensors(source)) out.push(finding('MG008', 'review', name, 'safetensors: ' + i));
  } else if (kind === 'gguf' || (suffix === '.gguf' && kind === null && size)) {
    const {issues, info} = await checkGguf(source);
    for (const i of issues) out.push(finding('MG009', 'review', name, 'GGUF: ' + i));
    for (const [key, text] of Object.entries(info.chat_templates || {})) out.push(...templateFindings(text, name, key));
  } else if (kind === 'zip' || (PICKLE_CANDIDATES.has(suffix) && head[0] === 0x50 && head[1] === 0x4b)) {
    out.push(...pickleFindings(await scanZip(source), name));
  } else if (kind === 'npy') {
    const r = await scanNpy(source, 0, size, newBudget());
    if (r) out.push(...pickleFindings(r, name));
  } else if (kind === 'pickle' || (PICKLE_CANDIDATES.has(suffix) && size)) {
    const strong = kind === 'pickle';
    const r = await scanPickle(source, 0, size, strong);
    if (strong || r.found.length || r.notes.length) out.push(...pickleFindings({kind: 'pickle', flags: [], ...r}, name));
  }
  if (AUTO_MAP_FILES.has(base) || TEMPLATE_FILES.has(base)) out.push(...await configFindings(blob, name, base));
  return out;
}

// Inspect a list of {file: Blob, path: string}. Options: {hash, onProgress}.
export async function inspectAll(entries, options = {}) {
  const started = Date.now(), report = {
    schema_version: '1.0', scanner_version: VERSION, created_at: new Date().toISOString(), target: options.target || 'local-selection',
    status: 'insufficient_evidence', files: [], findings: [],
    coverage: {inventory: true, static_formats: true, content: false, behavior: false, weights: false},
    limitations: ['No malware certification.', 'No backdoor detection or inference performed.', 'Analyzed in the browser: files were read locally in slices and never uploaded.',
      'Static checks only: pickle opcodes (raw, PyTorch zip, npy/npz), safetensors/GGUF structure, chat templates and config auto_map. Python AST review (MG013) is CLI-only.']};
  let total = 0, done = 0;
  for (const {file, path} of entries.slice().sort((x, y) => (x.path < y.path ? -1 : x.path > y.path ? 1 : 0))) {
    const item = {path, size: file.size};
    if (options.onProgress) options.onProgress(done, entries.length, path);
    try {
      if (options.hash) item.sha256 = await sha256Blob(file);
      report.findings.push(...await inspectFile(file, path));
    } catch (e) {
      report.findings.push(finding('MG007', 'review', path, `File not inspected: ${e.message || e}`));
    }
    report.files.push(item);
    total += file.size;
    done++;
  }
  for (const item of report.files) report.findings.push(...extensionFindings(item.path));
  report.summary = summarize(report, total, started);
  return report;
}

export function summarize(report, bytes, started) {
  const high = report.findings.filter(f => f.severity === 'high').length;
  return {files: report.files.length, bytes, findings_high: high, findings_review: report.findings.length - high, elapsed_seconds: (Date.now() - started) / 1000};
}

// Compare a local report (with sha256) against Hub file metadata, like `modelguard verify --partial`.
export function compareWithHub(report, hubFiles, revision, repo, partial = true) {
  const declared = new Map(hubFiles.map(f => [f.path, f])), present = new Map(report.files.map(f => [f.path, f]));
  let compared = 0;
  for (const [path, item] of present) {
    const ref = declared.get(path);
    if (!ref) report.findings.push(finding('MG012', 'review', path, 'File not present in the Hub revision'));
    else if (ref.declared_lfs_sha256 && item.sha256) { compared++; if (ref.declared_lfs_sha256 !== item.sha256) report.findings.push(finding('MG011', 'high', path, 'SHA-256 differs from the hash declared by the Hub')); }
    else if (ref.size != null && ref.size !== item.size) report.findings.push(finding('MG011', 'high', path, 'Size differs from the size declared by the Hub'));
  }
  if (!partial) for (const path of declared.keys()) if (!present.has(path)) report.findings.push(finding('MG012', 'review', path, 'Hub file missing locally'));
  report.revision = revision;
  report.limitations.push(`Compared against Hub ${repo} at ${revision}: ${compared} file(s) by SHA-256; non-LFS files by size only.`);
  return report;
}
