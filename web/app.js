import {inspectAll, compareWithHub, extensionFindings, summarize, VERSION} from './engine.mjs';

const $ = id => document.getElementById(id);
const KEY = 'modelguard:last:v1';
const REPO = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
let current = null, busy = false;

function setStatus(text) { $('status').textContent = text; }

function render(report, imported = false) {
  if (!report || report.schema_version !== '1.0' || !Array.isArray(report.files) || !Array.isArray(report.findings) || typeof report.target !== 'string') throw new Error('Informe incompatible');
  current = report;
  const text = JSON.stringify(report, null, 2);
  $('result').textContent = text;
  $('export').disabled = false;
  const findings = report.findings.filter(f => f && typeof f === 'object');
  const high = findings.filter(f => f.severity === 'high').length, review = findings.length - high;
  setStatus(`${imported ? 'Informe importado sin verificar. ' : ''}${report.files.length} ${report.files.length === 1 ? 'archivo' : 'archivos'} · evidencia insuficiente para descartar backdoors.`);
  const counts = $('counts');
  counts.hidden = false;
  counts.replaceChildren(badge(high, 'alta', 'high'), badge(review, 'revisar', 'review'));
  const list = $('findings');
  list.replaceChildren();
  const order = {high: 0, review: 1};
  for (const f of findings.slice().sort((a, b) => (order[a.severity] ?? 2) - (order[b.severity] ?? 2) || String(a.file).localeCompare(String(b.file)))) {
    const li = document.createElement('li');
    li.className = f.severity === 'high' ? 'high' : 'review';
    const head = document.createElement('div');
    head.className = 'fhead';
    const sev = document.createElement('span');
    sev.className = 'sev';
    sev.textContent = f.severity === 'high' ? 'ALTA' : 'REVISAR';
    const rule = document.createElement('span');
    rule.className = 'rule';
    rule.textContent = String(f.rule);
    const file = document.createElement('span');
    file.className = 'file';
    file.textContent = String(f.file);
    head.append(sev, rule, file);
    const msg = document.createElement('p');
    msg.textContent = String(f.message);
    li.append(head, msg);
    list.append(li);
  }
  if (!findings.length) {
    const li = document.createElement('li');
    li.className = 'none';
    li.textContent = 'Sin hallazgos en las reglas actuales. Esto no prueba que el modelo sea seguro.';
    list.append(li);
  }
  try {
    if (new Blob([text]).size <= 1024 * 1024) localStorage.setItem(KEY, text);
    else { localStorage.removeItem(KEY); setStatus($('status').textContent + ' Informe demasiado grande para conservar; expórtalo.'); }
  } catch { /* storage unavailable: the report stays on screen */ }
}

function badge(n, label, cls) {
  const el = document.createElement('span');
  el.className = 'badge ' + (n ? cls : 'zero');
  el.textContent = `${n} ${label}`;
  return el;
}

function progress(done, total, label) {
  const box = $('progress');
  box.hidden = false;
  $('bar').style.width = `${total ? Math.round((done / total) * 100) : 0}%`;
  setStatus(`Analizando ${done + 1}/${total}: ${label}`);
}

async function hubMetadata(repo, revision = 'main') {
  const response = await fetch(`https://huggingface.co/api/models/${repo}/revision/${encodeURIComponent(revision)}?blobs=true`,
    {signal: AbortSignal.timeout(30000), credentials: 'omit', referrerPolicy: 'no-referrer'});
  if (!response.ok) throw new Error('Hugging Face: HTTP ' + response.status);
  const reader = response.body.getReader(), chunks = [];
  let size = 0;
  while (true) {
    const {done, value} = await reader.read();
    if (done) break;
    size += value.length;
    if (size > 2 * 1024 * 1024) { await reader.cancel(); throw new Error('Metadatos exceden 2 MiB'); }
    chunks.push(value);
  }
  const data = JSON.parse(new TextDecoder().decode(await new Blob(chunks).arrayBuffer()));
  if (!/^[0-9a-f]{40}$/.test(data.sha || '')) throw new Error('Falta commit inmutable');
  const files = (Array.isArray(data.siblings) ? data.siblings : []).filter(f => f && typeof f.rfilename === 'string').map(f => ({
    path: f.rfilename, size: Number.isInteger(f.size) && f.size >= 0 ? f.size : null,
    declared_lfs_sha256: /^[0-9a-f]{64}$/.test(f.lfs?.sha256 || '') ? f.lfs.sha256 : null}));
  return {sha: data.sha, files};
}

// The engine runs in a module worker (File objects are transferable by structured clone); inline fallback otherwise.
function runEngine(entries, hash, target) {
  if (typeof Worker === 'undefined') return inspectAll(entries, {hash, target, onProgress: progress});
  return new Promise((resolve, reject) => {
    let worker;
    try { worker = new Worker('worker.mjs', {type: 'module'}); }
    catch { resolve(inspectAll(entries, {hash, target, onProgress: progress})); return; }
    worker.onmessage = ({data}) => {
      if (data.type === 'progress') progress(data.done, data.total, data.path);
      else { worker.terminate(); data.type === 'done' ? resolve(data.report) : reject(new Error(data.message)); }
    };
    worker.onerror = e => { worker.terminate(); reject(new Error(e.message || 'worker error')); };
    worker.postMessage({entries, hash, target});
  });
}

async function analyze(fileList) {
  if (busy || !fileList.length) return;
  busy = true;
  try {
    const files = Array.from(fileList);
    const folder = files[0].webkitRelativePath ? files[0].webkitRelativePath.split('/')[0] : null;
    const entries = files.map(f => ({file: f, path: f.webkitRelativePath ? f.webkitRelativePath.split('/').slice(1).join('/') : f.name}));
    const compare = $('compare').value.trim();
    let hub = null, repo = '', revision = 'main';
    if (compare) {
      [repo, revision = 'main'] = compare.split('@');
      if (!REPO.test(repo)) throw new Error('Usa owner/model o owner/model@revision para comparar');
      setStatus('Consultando metadatos del Hub…');
      hub = await hubMetadata(repo, revision);
    }
    const report = await runEngine(entries, $('hash').checked || !!hub, folder || 'local-selection');
    if (hub) compareWithHub(report, hub.files, hub.sha, repo, true);
    report.summary = summarize(report, report.summary.bytes, Date.now() - report.summary.elapsed_seconds * 1000);
    render(report);
  } catch (e) {
    setStatus('Análisis incompleto: ' + (e.message || e));
  } finally {
    busy = false;
    $('progress').hidden = true;
    $('files').value = '';
    $('folder').value = '';
  }
}

$('files').addEventListener('change', () => analyze($('files').files));
$('folder').addEventListener('change', () => analyze($('folder').files));
$('compare').addEventListener('input', () => { if ($('compare').value.trim()) $('hash').checked = true; });

$('hub').addEventListener('click', async () => {
  const repo = $('repo').value.trim();
  if (!REPO.test(repo)) { setStatus('Usa owner/model'); return; }
  $('hub').disabled = true;
  try {
    const started = Date.now(), {sha, files} = await hubMetadata(repo);
    const report = {schema_version: '1.0', scanner_version: VERSION, created_at: new Date().toISOString(), target: repo, revision: sha,
      status: 'insufficient_evidence', files, findings: files.flatMap(f => extensionFindings(f.path)),
      coverage: {inventory: true, static_formats: false, content: false, behavior: false, weights: false},
      limitations: ['Metadatos del Hub: no se descargaron pesos ni código. Hashes declarados, no verificados localmente.']};
    report.summary = summarize(report, files.reduce((n, f) => n + (f.size || 0), 0), started);
    render(report);
  } catch (e) {
    setStatus('Consulta incompleta: ' + e.message + '. Puedes usar modelguard hub desde la CLI.');
  } finally { $('hub').disabled = false; }
});

$('report').addEventListener('change', async () => {
  try {
    const f = $('report').files[0];
    if (!f) return;
    if (f.size > 2 * 1024 * 1024) throw new Error('Límite de importación: 2 MiB');
    render(JSON.parse(await f.text()), true);
  } catch (e) { setStatus(e.message); } finally { $('report').value = ''; }
});

$('export').addEventListener('click', () => {
  if (!current) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(current, null, 2)], {type: 'application/json'}));
  const a = document.createElement('a');
  a.href = url;
  a.download = 'modelguard-report.json';
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

$('clear').addEventListener('click', () => {
  try { localStorage.removeItem(KEY); } catch { /* ignore */ }
  current = null;
  $('result').textContent = 'No hay evidencia todavía.';
  $('findings').replaceChildren();
  $('counts').hidden = true;
  setStatus('Historial eliminado.');
  $('export').disabled = true;
});

try {
  const saved = localStorage.getItem(KEY);
  if (saved && saved.length <= 1024 * 1024) render(JSON.parse(saved), true);
} catch { setStatus('No se pudo restaurar el informe anterior.'); }
