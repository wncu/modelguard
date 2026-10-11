'use strict';
const $ = id => document.getElementById(id);
const KEY = 'modelguard:last:v1';
let current;
function rules(files){return files.filter(f=>/\.(py|sh|so|dll|exe|pkl|pickle|pt|pth|bin)$/i.test(f.path)).map(f=>({rule:'extension-review',file:f.path,severity:'review',message:'Formato o código que requiere revisión. No demuestra malware.'}));}
function make(target,files){return {schema_version:'1.0',scanner_version:'web-0.1.0',created_at:new Date().toISOString(),target,status:'insufficient_evidence',files,findings:rules(files),coverage:{inventory:true,content:false,behavior:false,weights:false},limitations:['Solo inventario y extensiones. No certifica seguridad. No se ejecutó código ni inferencia.']};}
function show(report, imported=false){
 if(!report || report.schema_version!=='1.0' || !Array.isArray(report.files) || !Array.isArray(report.findings) || typeof report.target!=='string') throw new Error('Informe incompatible');
 current=report; const text=JSON.stringify(report,null,2); $('result').textContent=text; $('export').disabled=false;
 $('status').textContent=(imported?'Informe importado sin verificar. ':'')+'Evidencia insuficiente para descartar backdoors. '+report.findings.length+' señales para revisar.';
 try{if(new Blob([text]).size<=1024*1024)localStorage.setItem(KEY,text);else{localStorage.removeItem(KEY);$('status').textContent+=' Informe demasiado grande para conservar; expórtalo.';}}catch{$('status').textContent+=' Almacenamiento no disponible; expórtalo.';}
}
$('files').addEventListener('change',()=>{try{show(make('local-selection',Array.from($('files').files,f=>({path:f.name,size:f.size}))));}catch(e){$('status').textContent=e.message;}});
$('report').addEventListener('change',async()=>{try{const f=$('report').files[0];if(!f)return;if(f.size>2*1024*1024)throw new Error('Límite de importación: 2 MiB');show(JSON.parse(await f.text()),true);}catch(e){$('status').textContent=e.message;}});
$('hub').addEventListener('click',async()=>{const repo=$('repo').value.trim();if(!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)){$('status').textContent='Usa owner/model';return;} $('hub').disabled=true;try{
 const response=await fetch('https://huggingface.co/api/models/'+repo+'?blobs=true',{signal:AbortSignal.timeout(30000),credentials:'omit',referrerPolicy:'no-referrer'});
 if(!response.ok)throw new Error('Hugging Face: HTTP '+response.status);
 const reader=response.body.getReader();let size=0;const chunks=[];while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>2*1024*1024){await reader.cancel();throw new Error('Metadatos exceden 2 MiB');}chunks.push(value);}const raw=new Uint8Array(size);let offset=0;for(const chunk of chunks){raw.set(chunk,offset);offset+=chunk.length;}
 const data=JSON.parse(new TextDecoder().decode(raw));if(!/^[0-9a-f]{40}$/.test(data.sha||''))throw new Error('Falta commit inmutable');
 const report=make(repo,(data.siblings||[]).map(f=>({path:f.rfilename,size:f.size??null,declared_lfs_sha256:f.lfs?.sha256??null})));report.revision=data.sha;report.limitations.push('Hashes declarados por el Hub, no verificados localmente.');show(report);
 }catch(e){$('status').textContent='Consulta incompleta: '+e.message+'. Puedes usar modelguard hub desde la CLI.';}finally{$('hub').disabled=false;}});
$('export').addEventListener('click',()=>{if(!current)return;const url=URL.createObjectURL(new Blob([JSON.stringify(current,null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='modelguard-report.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
$('clear').addEventListener('click',()=>{try{localStorage.removeItem(KEY);}catch{}current=null;$('result').textContent='No hay evidencia todavía.';$('status').textContent='Historial eliminado.';$('export').disabled=true;});
try{const saved=localStorage.getItem(KEY);if(saved && saved.length<=1024*1024)show(JSON.parse(saved),true);}catch{$('status').textContent='No se pudo restaurar el informe anterior.';}
