"""Run local checks from any working directory. No network/model downloads."""
from pathlib import Path
import shutil
import subprocess
import sys
root = Path(__file__).resolve().parents[1]
subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-v'], cwd=root, check=True)
node = shutil.which('node')
if node:
    for script in ('web/app.js', 'web/engine.mjs'):
        subprocess.run([node, '--check', script], cwd=root, check=True)
else:
    print('Node unavailable: JavaScript syntax check skipped.')
