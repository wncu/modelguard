"""Synthetic worst cases for time and peak memory. No network, no model downloads.

Each case runs in a fresh subprocess so peak RSS is measured per scan."""
import json
import pickle
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def gstr(s):
    return struct.pack('<Q', len(s)) + s.encode()


def build(tmp):
    cases = {}
    p = tmp / 'huge_bytes.pkl'                       # one 256 MB payload: must be skipped, not read
    with open(p, 'wb') as f:
        f.write(b'\x80\x04\x95' + struct.pack('<Q', 0) + b'\x8e' + struct.pack('<Q', 256 << 20))
        f.truncate(f.tell() + (256 << 20))
        f.seek(0, 2)
        f.write(b'\x94.')
    cases['pickle 256 MB bytes payload'] = p
    p = tmp / 'many_ints.pkl'
    p.write_bytes(pickle.dumps(list(range(2_000_000)), protocol=4))
    cases['pickle 2M ints'] = p
    p = tmp / 'many_strings.pkl'
    p.write_bytes(pickle.dumps({f'token-{i}': i for i in range(300_000)}, protocol=4))
    cases['pickle 300k unique strings'] = p
    p = tmp / 'model.pt'
    with zipfile.ZipFile(p, 'w') as zf:
        zf.writestr('archive/data.pkl', pickle.dumps({f'layer{i}.weight': i for i in range(5000)}, protocol=2))
        for i in range(2000):
            zf.writestr(f'archive/data/{i}', b'\x80\x02' + bytes(1024))
    cases['torch zip, 2000 storages'] = p
    vocab = struct.pack('<IQ', 8, 300_000) + b''.join(gstr(f'tok{i}') for i in range(300_000))
    header = b'GGUF' + struct.pack('<IQQ', 3, 1, 1) + gstr('tokenizer.ggml.tokens') + struct.pack('<I', 9) + vocab
    header += gstr('t0') + struct.pack('<I', 1) + struct.pack('<Q', 1 << 28) + struct.pack('<IQ', 0, 0)
    header += b'\0' * ((-len(header)) % 32)
    p = tmp / 'sparse.gguf'
    with open(p, 'wb') as f:
        f.write(header)
        f.truncate(len(header) + (1 << 30))         # 1 GiB F32 tensor, sparse on disk
    cases['GGUF 1 GiB, 300k-token vocab'] = p
    return cases


def run(target, extra=()):
    # VmHWM is per address space, so it is not inherited from this (larger) parent process like ru_maxrss
    code = ('import json, re, time; from modelguard.cli import local_scan; t = time.perf_counter(); '
            f'r = local_scan({str(target)!r}, {"--hash" in extra}); dt = time.perf_counter() - t; '
            'hwm = int(re.search(r"VmHWM:\\s+(\\d+)", open("/proc/self/status").read()).group(1)); '
            'print(json.dumps([dt, hwm, r["summary"]["findings_high"], r["summary"]["findings_review"]]))')
    out = subprocess.run([sys.executable, '-c', code], cwd=ROOT, capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def baseline():
    code = 'import re, modelguard.cli; print(re.search(r"VmHWM:\\s+(\\d+)", open("/proc/self/status").read()).group(1))'
    return int(subprocess.run([sys.executable, '-c', code], cwd=ROOT, capture_output=True, text=True).stdout)


def main():
    base = baseline()
    print(f'{"case":34} {"seconds":>8} {"peak MB":>8}  findings')
    with tempfile.TemporaryDirectory() as tmp:
        for label, path in build(Path(tmp)).items():
            seconds, rss, high, review = run(path)
            print(f'{label:34} {seconds:8.3f} {rss // 1024:8d}  {high} high, {review} review')
    print(f'(Python interpreter + modelguard import baseline: {base // 1024} MB)')


if __name__ == '__main__':
    start = time.perf_counter()
    main()
    print(f'total {time.perf_counter() - start:.1f} s')
