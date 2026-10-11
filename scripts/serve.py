"""Serve only static web assets on loopback; no model-upload endpoint."""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
root = Path(__file__).resolve().parents[1] / 'web'
print('ModelGuard preview: http://127.0.0.1:8000 (Ctrl+C to stop)')
with ThreadingHTTPServer(('127.0.0.1', 8000), partial(SimpleHTTPRequestHandler, directory=str(root))) as server:
    server.serve_forever()
