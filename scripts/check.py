"""Run local checks from any working directory. No network/model downloads."""
from pathlib import Path
import shutil
import subprocess
import sys
root = Path(__file__).resolve().parents[1]
subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-v'], cwd=root, check=True)
node = shutil.which('node')
if node:
    subprocess.run([node, '--check', 'web/app.js'], cwd=root, check=True)
else:
    print('Node unavailable: JavaScript syntax check skipped.')
