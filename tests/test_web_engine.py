"""Parity between the browser engine (web/engine.mjs, run under Node) and the Python engine."""
import collections
import json
import os
import pickle
import random
import shutil
import struct
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from modelguard.cli import local_scan

ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which('node')
FS_ONLY = {'MG003', 'MG013'}   # symlinks and Python AST exist only in the CLI


class Evil:
    def __reduce__(self):
        return (os.system, ('echo no',))


def gstr(s):
    return struct.pack('<Q', len(s)) + s.encode()


def gguf(tensors, kv=(), tail=0):
    out = b'GGUF' + struct.pack('<IQQ', 3, len(tensors), len(kv))
    for key, kind, value in kv:
        out += gstr(key) + struct.pack('<I', kind) + value
    for i, (elements, offset) in enumerate(tensors):
        out += gstr(f't{i}') + struct.pack('<I', 1) + struct.pack('<Q', elements) + struct.pack('<IQ', 0, offset)
    out += b'\0' * ((-len(out)) % 32)
    return out + b'\0' * (max((o + e * 4 for e, o in tensors), default=0) + tail)


def safetensors(header, body, raw=None):
    raw = raw or json.dumps(header).encode()
    return struct.pack('<Q', len(raw)) + raw + body


def npy(payload, version=1, pad=0):
    header = b"{'descr': '|O', 'fortran_order': False, 'shape': (1,), }" + b' ' * pad
    header += b' ' * (-(10 + len(header) + 1) % 64) + b'\n'
    return b'\x93NUMPY' + bytes([version, 0]) + len(header).to_bytes(2 if version == 1 else 4, 'little') + header + payload


def build_corpus(root):
    files = {}
    for proto in range(6):
        files[f'evil_p{proto}.pkl'] = pickle.dumps(Evil(), protocol=proto)
    files['benign.pkl'] = pickle.dumps({'a': [1, 2.5, 'x', b'y', None]}, protocol=4)
    files['fraction.pkl'] = pickle.dumps(__import__('fractions').Fraction(1, 3))
    files['pop_evasion.pkl'] = b'\x80\x04\x8c\x02os\x8c\x06system\x8c\x01x0\x93\x8c\x04echo\x85R.'
    files['memo.pkl'] = b'\x80\x04\x8c\x02os\x94\x8c\x06system\x94h\x00h\x01\x93.'
    files['unresolved.pkl'] = b'\x80\x04K\x01\x8c\x06system\x93.'
    files['dunder.pkl'] = b'\x80\x04\x8c\x0bcollections\x8c\x1fOrderedDict.__init__.__globals__\x93.'
    files['proto0.txt'] = b"cos\nsystem\n(S'echo hi'\ntR."
    files['chained.pkl'] = pickle.dumps({'a': 1}) + pickle.dumps(Evil())
    files['trailing.pkl'] = pickle.dumps([1, 2]) + b'\x80\xff\x00garbage'
    files['huge_len.pkl'] = b'\x80\x04\x8e' + (1 << 60).to_bytes(8, 'little') + b'x.'
    files['ext.pkl'] = b'\x80\x02\x82\x01.'
    files['raw.bin'] = bytes(range(256)).replace(b'\x80', b'\x00') * 8
    files['disguised.safetensors'] = pickle.dumps(Evil())
    files['obj.npy'] = npy(pickle.dumps([Evil()]))
    files['obj_v2.npy'] = npy(pickle.dumps([Evil()]), version=2, pad=70000)
    files['plain.npy'] = npy(b'\0' * 16).replace(b'|O', b'<f')
    for name, comp, members in [
        ('stored.pt', zipfile.ZIP_STORED, {'archive/data.pkl': pickle.dumps(Evil(), protocol=2), 'archive/data/0': b'\x80\x02cx\ny\n'}),
        ('deflated.pt', zipfile.ZIP_DEFLATED, {'archive/data.pkl': pickle.dumps(Evil(), protocol=0)}),
        ('wrong_name.zip', zipfile.ZIP_STORED, {'data.txt': pickle.dumps(Evil()), 'readme.txt': b'hi'}),
        ('arrays.npz', zipfile.ZIP_DEFLATED, {'a.npy': npy(pickle.dumps([Evil()])), 'b.npy': npy(b'\0' * 8).replace(b'|O', b'<f')}),
        ('script.pt', zipfile.ZIP_STORED, {'m/data.pkl': pickle.dumps({}), 'm/code/__torch__/m.py': b'def f(): pass'}),
        ('traversal.zip', zipfile.ZIP_STORED, {'../evil.pkl': pickle.dumps(1)}),
    ]:
        p = root / name
        with zipfile.ZipFile(p, 'w', comp) as zf:
            for member, data in members.items():
                zf.writestr(member, data)
    files['bad.zip'] = b'PK\x03\x04' + b'\0' * 40
    # small archive with ZIP64 end records, as PyTorch/miniz writes them
    plain = root / 'tmp_plain.zip'
    with zipfile.ZipFile(plain, 'w') as zf:
        zf.writestr('archive/data.pkl', pickle.dumps(Evil(), protocol=2))
    raw = plain.read_bytes()
    plain.unlink()
    eocd = raw.rfind(b'PK\x05\x06')
    entries, cd_size, cd_off = struct.unpack_from('<HII', raw, eocd + 10)
    rec = struct.pack('<IQHHIIQQQQ', 0x06064b50, 44, 45, 45, 0, 0, entries, entries, cd_size, cd_off)
    locator = struct.pack('<IIQI', 0x07064b50, 0, eocd, 1)
    files['zip64_small.pt'] = raw[:eocd] + rec + locator + raw[eocd:]
    files['ok.safetensors'] = safetensors({'a': {'dtype': 'F32', 'shape': [2], 'data_offsets': [0, 8]}}, b'\0' * 8)
    files['gap.safetensors'] = safetensors({'a': {'dtype': 'U8', 'shape': [2], 'data_offsets': [1, 3]}}, b'\0' * 3)
    files['overlap.safetensors'] = safetensors({'a': {'dtype': 'U8', 'shape': [4], 'data_offsets': [0, 4]},
                                                'b': {'dtype': 'U8', 'shape': [2], 'data_offsets': [2, 4]}}, b'\0' * 4)
    files['dup.safetensors'] = safetensors(None, b'\0', raw=b'{"a": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}, "a": {"dtype": "U8", "shape": [1], "data_offsets": [0, 1]}}')
    files['f4.safetensors'] = safetensors({'a': {'dtype': 'F4', 'shape': [3], 'data_offsets': [0, 2]}}, b'\0' * 2)
    files['huge.safetensors'] = struct.pack('<Q', 1 << 40) + b'{}'
    files['ok.gguf'] = gguf([(4, 0), (8, 32)])
    files['overlap.gguf'] = gguf([(16, 0), (8, 32)])
    files['trailing.gguf'] = gguf([(4, 0)], tail=4096)
    files['gap.gguf'] = gguf([(4, 0), (4, 256)])
    files['template.gguf'] = gguf([(4, 0)], kv=(('tokenizer.ggml.tokens', 9, struct.pack('<IQ', 8, 2) + gstr('a') + gstr('b')),
                                               ('tokenizer.chat_template', 8, gstr("{{ cycler.__init__.__globals__.os.popen('id') }}"))))
    files['short.gguf'] = b'GG'
    files['config.json'] = json.dumps({'auto_map': {'AutoModel': 'm.M'}, 'custom_pipelines': {'x': {}}}).encode()
    files['tokenizer_config.json'] = json.dumps({'chat_template': [{'name': 'd', 'template': "{{ x|attr('y') }}"}]}).encode()
    files['chat_template.jinja'] = b"{{ ''.__class__.__mro__ }}"
    files['sub/processor_config.json'] = b'{'
    files['notes.7z'] = b"7z\xbc\xaf'\x1c"
    files['run.sh'] = b'echo'
    for name, data in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(data)


def run_js(target, hashes=False):
    args = ['node', str(ROOT / 'tests' / 'web_engine_runner.mjs'), str(target)] + (['--hash'] if hashes else [])
    return json.loads(subprocess.run(args, capture_output=True, text=True, check=True, cwd=ROOT).stdout)


def keyed(report, exclude=()):
    """Exact message comparison, except MG007 notes on corrupt archives: their wording depends on the library
    (zlib vs DecompressionStream) while the rule, severity and file must still match."""
    return collections.Counter((f['rule'], f['severity'], f['file'], '' if f['rule'] == 'MG007' else f['message'])
                               for f in report['findings'] if f['rule'] not in exclude)


@unittest.skipUnless(NODE, 'node not installed')
class WebEngineParityTests(unittest.TestCase):
    def assert_parity(self, target, hashes=False):
        py, js = local_scan(str(target), hashes), run_js(target, hashes)
        a, b = keyed(py, FS_ONLY), keyed(js)
        self.assertEqual(a - b, collections.Counter(), 'missing in JS')
        self.assertEqual(b - a, collections.Counter(), 'extra in JS')
        if hashes:
            self.assertEqual({f['path']: f['sha256'] for f in py['files']}, {f['path']: f['sha256'] for f in js['files']})
        return py

    def test_adversarial_corpus(self):
        with tempfile.TemporaryDirectory() as tmp:
            build_corpus(Path(tmp))
            report = self.assert_parity(tmp, hashes=True)
            self.assertGreater(report['summary']['findings_high'], 20)

    def test_incremental_sha256(self):
        code = ("import {Sha256} from './web/engine.mjs'; const h = new Sha256(); "
                "for (const n of [0, 1, 55, 56, 63, 64, 65, 1000]) h.update(new Uint8Array(n).fill(n % 251)); "
                "console.log(h.hex());")
        out = subprocess.run(['node', '--input-type=module', '-e', code], capture_output=True, text=True, check=True, cwd=ROOT)
        import hashlib
        data = b''.join(bytes([n % 251]) * n for n in [0, 1, 55, 56, 63, 64, 65, 1000])
        self.assertEqual(out.stdout.strip(), hashlib.sha256(data).hexdigest())

    def test_mutation_parity(self):
        rnd = random.Random(2026)
        with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as out:
            build_corpus(Path(src))
            seeds = [p for p in Path(src).rglob('*') if p.is_file() and p.stat().st_size > 4]
            for i in range(300):
                seed = rnd.choice(seeds)
                data = bytearray(seed.read_bytes())
                for _ in range(rnd.randint(1, 8)):
                    choice = rnd.random()
                    if choice < 0.5:
                        data[rnd.randrange(len(data))] = rnd.randrange(256)
                    elif choice < 0.75 and len(data) > 2:
                        del data[rnd.randrange(len(data)):]
                    else:
                        data.insert(rnd.randrange(len(data) + 1), rnd.randrange(256))
                    if not data:
                        data = bytearray(b'\x80')
                (Path(out) / f'm{i:03d}{seed.suffix}').write_bytes(bytes(data))
            self.assert_parity(out)


if __name__ == '__main__':
    unittest.main()
