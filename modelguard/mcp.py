"""Model Context Protocol server over stdio, standard library only.

Exposes read-only ModelGuard tools to MCP clients (Claude Code, Claude Desktop, IDEs). Messages are
newline-delimited JSON-RPC 2.0 on stdin/stdout; nothing but protocol messages is ever written to stdout.
"""
import json
import sys
import traceback

from . import __version__
from .cli import _lower_priority, hub_scan, local_scan, verify

PROTOCOL_VERSIONS = ('2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05')
MAX_FINDINGS = 200

_READ_ONLY = {'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True}
TOOLS = [
    {
        'name': 'modelguard_scan',
        'title': 'Scan local model files',
        'description': (
            'Statically inspect a local model file or directory for supply-chain risks: pickle payloads '
            '(PyTorch .bin/.pt/.ckpt, joblib, npy/npz), safetensors and GGUF structure, Jinja chat-template '
            'injection, auto_map/trust_remote_code configs and risky Python code. Never unpickles, imports or '
            'executes anything. A clean result is not proof of safety.'),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'path': {'type': 'string', 'description': 'Absolute path to a model file or directory'},
                'hash': {'type': 'boolean', 'default': False,
                         'description': 'Also compute SHA-256 of every file (reads all bytes; slow for large models)'},
                'follow_symlinks': {'type': 'boolean', 'default': False,
                                    'description': 'Inspect symlink targets (Hugging Face cache links are always followed)'},
                'include_files': {'type': 'boolean', 'default': False,
                                  'description': 'Include the per-file inventory in the result'},
            },
            'required': ['path'],
            'additionalProperties': False,
        },
        'annotations': {**_READ_ONLY, 'openWorldHint': False},
    },
    {
        'name': 'modelguard_hub',
        'title': 'Inspect Hugging Face repo metadata',
        'description': (
            'List the files of a public Hugging Face model repo pinned to an immutable commit, with extension-based '
            'risk signals and declared LFS hashes. Downloads metadata only, never weights or code.'),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'repo': {'type': 'string', 'description': 'owner/model'},
                'revision': {'type': 'string', 'default': 'main', 'description': 'Branch, tag or commit'},
                'include_files': {'type': 'boolean', 'default': False},
            },
            'required': ['repo'],
            'additionalProperties': False,
        },
        'annotations': {**_READ_ONLY, 'openWorldHint': True},
    },
    {
        'name': 'modelguard_verify',
        'title': 'Verify a local copy against the Hub',
        'description': (
            'Scan a local model directory, hash every file and compare it with the SHA-256/size declared by a '
            'Hugging Face revision. Reports tampered, extra and missing files.'),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'path': {'type': 'string', 'description': 'Absolute path to the local model directory'},
                'repo': {'type': 'string', 'description': 'owner/model'},
                'revision': {'type': 'string', 'default': 'main'},
                'partial': {'type': 'boolean', 'default': True,
                            'description': 'Do not report Hub files that were not downloaded'},
                'include_files': {'type': 'boolean', 'default': False},
            },
            'required': ['path', 'repo'],
            'additionalProperties': False,
        },
        'annotations': {**_READ_ONLY, 'openWorldHint': True},
    },
]


def _compact(report, include_files):
    """Trim a report for an LLM context: findings first, bounded size, optional inventory."""
    order = {'high': 0, 'review': 1}
    findings = sorted(report['findings'], key=lambda f: (order.get(f['severity'], 2), f['file'], f['rule']))
    out = {k: report[k] for k in ('scanner_version', 'target', 'status', 'coverage', 'summary') if k in report}
    if 'revision' in report:
        out['revision'] = report['revision']
    out['findings'] = findings[:MAX_FINDINGS]
    if len(findings) > MAX_FINDINGS:
        out['findings_truncated'] = len(findings) - MAX_FINDINGS
    out['limitations'] = report['limitations']
    if include_files:
        out['files'] = report['files']
    return out


def _text(report):
    s = report.get('summary', {})
    lines = [f"ModelGuard {report.get('scanner_version')}: {report['target']}"
             + (f" @ {report['revision']}" if report.get('revision') else ''),
             f"{s.get('files', '?')} files, {s.get('findings_high', 0)} high, {s.get('findings_review', 0)} review. "
             'Status: insufficient_evidence (absence of findings is not proof of safety).']
    for f in report['findings']:
        lines.append(f"- [{f['severity'].upper()}] {f['rule']} {f['file']}: {f['message']}")
    if report.get('findings_truncated'):
        lines.append(f"… {report['findings_truncated']} more findings omitted")
    return '\n'.join(lines)


def call_tool(name, args):
    if not isinstance(args, dict):
        raise ValueError('arguments must be an object')
    include = bool(args.get('include_files', False))
    if name == 'modelguard_scan':
        report = local_scan(_str(args, 'path'), bool(args.get('hash', False)), bool(args.get('follow_symlinks', False)))
    elif name == 'modelguard_hub':
        report = hub_scan(_str(args, 'repo'), _str(args, 'revision', 'main'))
    elif name == 'modelguard_verify':
        report = verify(_str(args, 'path'), _str(args, 'repo'), _str(args, 'revision', 'main'),
                        bool(args.get('partial', True)))
    else:
        raise KeyError(name)
    compact = _compact(report, include)
    return {'content': [{'type': 'text', 'text': _text(compact)}], 'structuredContent': compact, 'isError': False}


def _str(args, key, default=None):
    value = args.get(key, default)
    if not isinstance(value, str) or not value:
        raise ValueError(f'{key} must be a non-empty string')
    return value


def handle(message):
    """Return the response for one JSON-RPC message, or None for notifications."""
    if not isinstance(message, dict) or message.get('jsonrpc') != '2.0' or not isinstance(message.get('method'), str):
        return _error(message.get('id') if isinstance(message, dict) else None, -32600, 'Invalid Request')
    method, msg_id, params = message['method'], message.get('id'), message.get('params') or {}
    if 'id' not in message:          # notification: never answered
        return None
    if method == 'initialize':
        requested = params.get('protocolVersion') if isinstance(params, dict) else None
        version = requested if requested in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0]
        return _result(msg_id, {
            'protocolVersion': version,
            'capabilities': {'tools': {'listChanged': False}},
            'serverInfo': {'name': 'modelguard', 'title': 'ModelGuard', 'version': __version__},
            'instructions': ('Read-only static inspection of AI model files. Use modelguard_scan before loading a '
                             'downloaded model; findings are evidence for review, never a safety certificate.'),
        })
    if method == 'ping':
        return _result(msg_id, {})
    if method == 'tools/list':
        return _result(msg_id, {'tools': TOOLS})
    if method == 'tools/call':
        if not isinstance(params, dict) or not isinstance(params.get('name'), str):
            return _error(msg_id, -32602, 'Invalid params')
        try:
            return _result(msg_id, call_tool(params['name'], params.get('arguments') or {}))
        except KeyError:
            return _error(msg_id, -32602, f"Unknown tool: {params['name']}")
        except (OSError, ValueError) as exc:   # tool-level failure: reported to the model, not a protocol error
            return _result(msg_id, {'content': [{'type': 'text', 'text': f'Incomplete scan: {exc}'}], 'isError': True})
    return _error(msg_id, -32601, f'Method not found: {method}')


def _result(msg_id, result):
    return {'jsonrpc': '2.0', 'id': msg_id, 'result': result}


def _error(msg_id, code, text):
    return {'jsonrpc': '2.0', 'id': msg_id, 'error': {'code': code, 'message': text}}


def serve(stdin=None, stdout=None):
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    _lower_priority()
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            response = _error(None, -32700, 'Parse error')
        else:
            try:
                response = handle(message)
            except Exception:              # never let one bad request kill the server
                traceback.print_exc(file=sys.stderr)
                response = _error(message.get('id') if isinstance(message, dict) else None, -32603, 'Internal error')
        if response is not None:
            stdout.write(json.dumps(response, ensure_ascii=False) + '\n')
            stdout.flush()


def main():
    try:
        serve()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
