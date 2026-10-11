"""Static review of chat templates (Jinja) and repository Python code. Parses only; never renders or runs."""
import ast
import re

MAX_PY = 1024 * 1024

# Jinja server-side template injection: legitimate chat templates never need dunder attributes,
# escaped underscores or the sandbox-escape globals below.
_TPL_HIGH = [
    (re.compile(r'__[A-Za-z]\w*__'), 'dunder attribute access'),
    (re.compile(r'\\x5f|\\u005f|\\137|\\N\{LOW LINE\}', re.I), 'escaped underscore (obfuscated attribute)'),
    (re.compile(r'_TemplateReference__|\b(?:os|subprocess)\.(?:popen|system|exec)', re.I), 'sandbox escape pattern'),
    (re.compile(r'\b(?:lipsum|cycler|joiner|url_for|get_flashed_messages)\b\s*[.\[|]'), 'Jinja global used as gadget'),
]
_TPL_REVIEW = [
    (re.compile(r'\|\s*attr\s*\('), 'attr() filter'),
    (re.compile(r'\b(?:self|config|request)\s*[.\[]'), 'access to template context objects'),
    (re.compile(r'\b(?:import|include|extends|from)\b[^%]*%\}'), 'template loads other templates'),
    (re.compile(r'\bhttps?://', re.I), 'URL inside template'),
]


def check_template(text):
    """Return a list of (severity, reason) for a Jinja chat template."""
    out, seen = [], set()
    for pattern, reason in _TPL_HIGH:
        if reason not in seen and pattern.search(text):
            out.append(('high', reason))
            seen.add(reason)
    for pattern, reason in _TPL_REVIEW:
        if reason not in seen and pattern.search(text):
            out.append(('review', reason))
            seen.add(reason)
    return out


# Calls/imports in Python files shipped with a model (auto_map / trust_remote_code).
_PY_EXEC = {'eval', 'exec', 'compile', '__import__', 'execfile'}
_PY_MODULES = {
    'subprocess': 'process execution', 'os.system': 'process execution', 'os.popen': 'process execution',
    'os.exec': 'process execution', 'os.spawn': 'process execution', 'pty': 'process execution',
    'socket': 'network', 'urllib': 'network', 'http.client': 'network', 'requests': 'network',
    'httpx': 'network', 'aiohttp': 'network', 'ftplib': 'network', 'smtplib': 'network', 'paramiko': 'network',
    'ctypes': 'native code', 'cffi': 'native code', 'marshal': 'bytecode loading', 'pickle': 'unpickling',
    'dill': 'unpickling', 'cloudpickle': 'unpickling', 'base64': 'encoded payload', 'codecs.decode': 'encoded payload',
    'zlib': 'compressed payload', 'lzma': 'compressed payload', 'importlib': 'dynamic import',
    'shutil.rmtree': 'file deletion', 'os.remove': 'file deletion', 'os.unlink': 'file deletion',
    'webbrowser': 'opens browser', 'keyring': 'credential access', 'getpass': 'credential access',
}


def _dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return '.'.join(reversed(parts))
    return None


def _category(name):
    for key, label in _PY_MODULES.items():
        if name == key or name.startswith(key + '.') or (key.count('.') and name.startswith(key)):
            return label
    return None


def check_python(source):
    """Return (severity, summary) or None. Uses ast.parse only; the code is never imported or executed."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return 'review', 'Python file could not be parsed statically; review manually'
    hits, aliases = {}, {}

    def hit(label, line):
        hits.setdefault(label, line)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                aliases[a.asname or a.name.split('.')[0]] = a.name if a.asname else a.name.split('.')[0]
                label = _category(a.name)
                if label:
                    hit(label, node.lineno)
        elif isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                full = f'{node.module}.{a.name}'
                aliases[a.asname or a.name] = full
                label = _category(full) or _category(node.module)
                if label:
                    hit(label, node.lineno)
        elif isinstance(node, ast.Call):
            name = _dotted(node.func)
            if name is None:
                continue
            head, _, rest = name.partition('.')
            resolved = aliases.get(head, head) + ('.' + rest if rest else '')
            if resolved in _PY_EXEC or name in _PY_EXEC:
                hit('dynamic code execution (eval/exec/compile)', node.lineno)
            else:
                label = _category(resolved)
                if label:
                    hit(label, node.lineno)
    if not hits:
        return None
    severity = 'review'
    payload = {'encoded payload', 'compressed payload', 'bytecode loading'}
    if 'dynamic code execution (eval/exec/compile)' in hits and payload & hits.keys():
        severity = 'high'   # exec(decode(...)) is the classic obfuscated dropper
    elif {'process execution', 'network'} <= hits.keys():
        severity = 'high'
    summary = ', '.join(f'{label} (line {line})' for label, line in sorted(hits.items(), key=lambda x: x[1])[:6])
    return severity, summary
