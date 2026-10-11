// Runs the browser engine under Node on a local path and prints a JSON report (used by test_web_engine.py).
import {openAsBlob} from 'node:fs';
import {readdir, stat} from 'node:fs/promises';
import {join, relative} from 'node:path';
import {inspectAll} from '../web/engine.mjs';

async function walk(root, dir = root, out = []) {
  for (const entry of await readdir(dir, {withFileTypes: true})) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) { if (!['.git', '__pycache__'].includes(entry.name)) await walk(root, full, out); }
    else if (entry.isFile()) out.push({file: await openAsBlob(full), path: relative(root, full).split('\\').join('/')});
  }
  return out;
}

const target = process.argv[2], hash = process.argv.includes('--hash');
const info = await stat(target);
const entries = info.isDirectory() ? await walk(target) : [{file: await openAsBlob(target), path: target.split('/').pop()}];
process.stdout.write(JSON.stringify(await inspectAll(entries, {hash, target})));
