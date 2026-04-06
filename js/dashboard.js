/* ============================================================
   FileVault — app.js
   FIX: Open uses extension→MIME to open inline (PDF, TXT, images,
        videos). Download always forces a file save.
   Storage  : IndexedDB for blobs, localStorage for metadata only
   Crypto   : AES-256-GCM via Web Crypto API
   ============================================================ */

const API = '';

// ── MIME type map (extension → MIME) ────────────────────────
const MIME = {
  // Images
  jpg:'image/jpeg', jpeg:'image/jpeg', png:'image/png',
  gif:'image/gif',  webp:'image/webp', svg:'image/svg+xml', bmp:'image/bmp',
  // Video
  mp4:'video/mp4', mov:'video/quicktime', avi:'video/x-msvideo',
  mkv:'video/x-matroska', webm:'video/webm',
  // Audio
  mp3:'audio/mpeg', wav:'audio/wav', ogg:'audio/ogg', flac:'audio/flac',
  // Documents that browsers can render inline
  pdf:'application/pdf',
  txt:'text/plain', csv:'text/csv', html:'text/html', htm:'text/html',
  xml:'text/xml',   json:'application/json', md:'text/plain',
  // Everything else → octet-stream (will trigger download)
};
function mimeOf(ext) {
  return MIME[ext.toLowerCase()] || 'application/octet-stream';
}
// Can the browser display this inline?
function isInline(ext) {
  const m = mimeOf(ext);
  return m.startsWith('image/') || m.startsWith('video/') ||
         m.startsWith('audio/') || m.startsWith('text/')  ||
         m === 'application/pdf' || m === 'application/json';
}

// ── IndexedDB ────────────────────────────────────────────────
let DB = null;
function openDB() {
  return new Promise((res, rej) => {
    if (DB) { res(DB); return; }
    const req = indexedDB.open('filevault', 1);
    req.onupgradeneeded = e => {
      if (!e.target.result.objectStoreNames.contains('blobs'))
        e.target.result.createObjectStore('blobs');
    };
    req.onsuccess = e => { DB = e.target.result; res(DB); };
    req.onerror   = e => rej(e.target.error);
  });
}
async function idbPut(key, val) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction('blobs','readwrite');
    tx.objectStore('blobs').put(val, key);
    tx.oncomplete = res; tx.onerror = e => rej(e.target.error);
  });
}
async function idbGet(key) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const req = db.transaction('blobs').objectStore('blobs').get(key);
    req.onsuccess = e => res(e.target.result);
    req.onerror   = e => rej(e.target.error);
  });
}
async function idbDel(key) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction('blobs','readwrite');
    tx.objectStore('blobs').delete(key);
    tx.oncomplete = res; tx.onerror = e => rej(e.target.error);
  });
}

// ── Mock / sample files ──────────────────────────────────────
const MOCK = [
  {id:'m1', name:'Q4 Financial Report.pdf', ext:'pdf',  size:4412000,  fmt:'4.2 MB',  date:'2026-03-28T10:00:00Z', cat:'document', icon:'📄', clr:'#FF5370', star:false, own:false, enc:false, shared:['bob@example.com']},
  {id:'m2', name:'Team Photo 2025.jpg',     ext:'jpg',  size:2150000,  fmt:'2.1 MB',  date:'2026-04-01T14:30:00Z', cat:'image',    icon:'🖼️', clr:'#4F8BFF', star:true,  own:false, enc:false, shared:[]},
  {id:'m3', name:'Project Assets.zip',      ext:'zip',  size:18900000, fmt:'18.0 MB', date:'2026-04-02T09:15:00Z', cat:'archive',  icon:'📦', clr:'#F5A623', star:false, own:false, enc:false, shared:[]},
  {id:'m4', name:'Product Demo.mp4',        ext:'mp4',  size:52000000, fmt:'49.6 MB', date:'2026-03-25T16:00:00Z', cat:'video',    icon:'🎬', clr:'#A259FF', star:true,  own:false, enc:false, shared:['carol@example.com']},
  {id:'m5', name:'Budget 2026.xlsx',        ext:'xlsx', size:890000,   fmt:'869 KB',  date:'2026-04-03T11:00:00Z', cat:'document', icon:'📊', clr:'#22D3A5', star:false, own:false, enc:false, shared:[]},
  {id:'m6', name:'Design Mockups.png',      ext:'png',  size:3200000,  fmt:'3.1 MB',  date:'2026-04-04T08:45:00Z', cat:'image',    icon:'🖼️', clr:'#4F8BFF', star:false, own:false, enc:false, shared:[]},
  {id:'m7', name:'API Documentation.docx',  ext:'docx', size:1100000,  fmt:'1.0 MB',  date:'2026-03-30T13:20:00Z', cat:'document', icon:'📝', clr:'#4F8BFF', star:false, own:false, enc:false, shared:[]},
  {id:'m8', name:'Tutorial Series.mp4',     ext:'mp4',  size:128000000,fmt:'122 MB',  date:'2026-03-22T10:00:00Z', cat:'video',    icon:'🎬', clr:'#A259FF', star:false, own:false, enc:false, shared:[]},
  {id:'m9', name:'Source Code.zip',         ext:'zip',  size:7800000,  fmt:'7.4 MB',  date:'2026-03-31T15:30:00Z', cat:'archive',  icon:'📦', clr:'#F5A623', star:true,  own:false, enc:false, shared:[]},
  {id:'m10',name:'Logo Assets.png',         ext:'png',  size:450000,   fmt:'440 KB',  date:'2026-04-05T07:00:00Z', cat:'image',    icon:'🖼️', clr:'#4F8BFF', star:false, own:false, enc:false, shared:[]},
  {id:'m11',name:'Marketing Strategy.pdf',  ext:'pdf',  size:2900000,  fmt:'2.8 MB',  date:'2026-03-26T12:00:00Z', cat:'document', icon:'📄', clr:'#FF5370', star:false, own:false, enc:false, shared:[]},
  {id:'m12',name:'Presentation.pptx',       ext:'pptx', size:6700000,  fmt:'6.4 MB',  date:'2026-04-04T17:00:00Z', cat:'document', icon:'📊', clr:'#F5A623', star:true,  own:false, enc:false, shared:[]},
];

// ── App state ────────────────────────────────────────────────
let files=[], trash=[], view='dashboard', filter='all', sort='date', grid=true, search='';
let activeFile=null, shareId=null, pendingFiles=[];
let activity=[
  {c:'#4F8BFF',t:'Q4 Financial Report.pdf uploaded',  a:'10 min ago'},
  {c:'#22D3A5',t:'Budget 2026.xlsx edited',            a:'32 min ago'},
  {c:'#A259FF',t:'Product Demo.mp4 shared',            a:'1h ago'},
  {c:'#F5A623',t:'Project Assets.zip downloaded',      a:'3h ago'},
  {c:'#FF5370',t:'Old Report.pdf moved to trash',      a:'5h ago'},
];

// ── Persistence: metadata → localStorage, blobs → IndexedDB ─
function saveMeta() {
  localStorage.setItem('fv_meta', JSON.stringify(
    files.filter(f=>f.own).map(f=>({
      id:f.id,name:f.name,ext:f.ext,size:f.size,fmt:f.fmt,
      date:f.date,cat:f.cat,icon:f.icon,clr:f.clr,
      star:f.star,own:f.own,enc:f.enc,shared:f.shared,
      serverPath:f.serverPath||null,
    }))
  ));
  localStorage.setItem('fv_stars', JSON.stringify(files.map(f=>({id:f.id,star:f.star}))));
  localStorage.setItem('fv_trash', JSON.stringify(
    trash.map(t=>({at:t.at,file:{
      id:t.file.id,name:t.file.name,ext:t.file.ext,size:t.file.size,
      fmt:t.file.fmt,date:t.file.date,cat:t.file.cat,
      icon:t.file.icon,clr:t.file.clr,star:t.file.star,
      own:t.file.own,enc:t.file.enc,shared:t.file.shared,
      serverPath:t.file.serverPath||null,
    }}))
  ));
}
function loadMeta() {
  const meta = JSON.parse(localStorage.getItem('fv_meta')  || '[]');
  const sl   = {};
  JSON.parse(localStorage.getItem('fv_stars') || '[]').forEach(s => sl[s.id]=s.star);
  trash = JSON.parse(localStorage.getItem('fv_trash') || '[]');
  files = [
    ...MOCK.map(f=>({...f, star:sl[f.id]??f.star})),
    ...meta.map(f =>({...f, star:sl[f.id]??f.star})),
  ];
}

// ── Helpers ──────────────────────────────────────────────────
function fmtBytes(b){
  if(b<1024)       return b+' B';
  if(b<1048576)    return (b/1024).toFixed(0)+' KB';
  if(b<1073741824) return (b/1048576).toFixed(1)+' MB';
  return (b/1073741824).toFixed(2)+' GB';
}
function fmtDate(iso){ return iso?new Date(iso).toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'}):'-'; }
function ago(iso){
  const s=(Date.now()-new Date(iso).getTime())/1000;
  if(s<60)    return 'just now';
  if(s<3600)  return Math.floor(s/60)+'m ago';
  if(s<86400) return Math.floor(s/3600)+'h ago';
  return Math.floor(s/86400)+'d ago';
}
function catOf(name){
  const e=name.split('.').pop().toLowerCase();
  if(['jpg','jpeg','png','gif','webp','svg','bmp'].includes(e)) return 'image';
  if(['mp4','mov','avi','mkv','webm'].includes(e))             return 'video';
  if(['zip','rar','7z','tar','gz'].includes(e))                return 'archive';
  if(['pdf','doc','docx','xls','xlsx','ppt','pptx','txt','csv','md'].includes(e)) return 'document';
  return 'other';
}
function iconOf(cat,ext){
  if(cat==='image')   return '🖼️';
  if(cat==='video')   return '🎬';
  if(cat==='archive') return '📦';
  if(ext==='pdf')     return '📄';
  if(['xls','xlsx','csv','ppt','pptx'].includes(ext)) return '📊';
  if(['doc','docx'].includes(ext))                    return '📝';
  if(['txt','md'].includes(ext))                      return '📃';
  return '📁';
}
function clrOf(cat){ return {image:'#4F8BFF',video:'#A259FF',archive:'#F5A623',document:'#FF5370'}[cat]||'#22D3A5'; }
function uid(){ return 'u'+Date.now()+Math.random().toString(36).slice(2,6); }
function totalB(){ return files.reduce((s,f)=>s+(f.size||0),0); }
function x(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

// ── Toast ────────────────────────────────────────────────────
function toast(msg,type='info'){
  const icons={success:'✓',error:'✗',info:'ℹ'};
  const el=document.createElement('div');
  el.className=`toast toast-${type}`;
  el.innerHTML=`<span class="ti">${icons[type]}</span><span class="tm2">${x(msg)}</span><button class="tx" onclick="rmToast(this.parentElement)">✕</button>`;
  document.getElementById('toast-container').appendChild(el);
  setTimeout(()=>rmToast(el),3200);
}
function rmToast(el){ if(!el||el._r)return; el._r=true; el.classList.add('out'); setTimeout(()=>el.remove(),300); }

// ── AES-256-GCM ──────────────────────────────────────────────
async function deriveKey(pw,salt){
  const k=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:100000,hash:'SHA-256'},k,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
async function encryptBlob(blob,pw){
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const iv  =crypto.getRandomValues(new Uint8Array(12));
  const key =await deriveKey(pw,salt);
  const buf =await blob.arrayBuffer();
  const cipher=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,buf);
  const mimeB=new TextEncoder().encode(blob.type);
  const mimeLen=new Uint8Array(2); new DataView(mimeLen.buffer).setUint16(0,mimeB.length);
  const out=new Uint8Array(16+12+2+mimeB.length+cipher.byteLength);
  let o=0; out.set(salt,o);o+=16; out.set(iv,o);o+=12; out.set(mimeLen,o);o+=2; out.set(mimeB,o);o+=mimeB.length; out.set(new Uint8Array(cipher),o);
  return new Blob([out]);
}
async function decryptBlob(encBlob,pw){
  try{
    const buf=await encBlob.arrayBuffer(), d=new Uint8Array(buf);
    const salt=d.slice(0,16), iv=d.slice(16,28);
    const mimeLen=new DataView(d.buffer,28,2).getUint16(0);
    const mime=new TextDecoder().decode(d.slice(30,30+mimeLen));
    const key=await deriveKey(pw,d.slice(0,16));
    const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv},await deriveKey(pw,salt),d.slice(30+mimeLen));
    return new Blob([plain],{type:mime});
  }catch{return null;}
}

// ── OPEN FILE ────────────────────────────────────────────────
// Creates a Blob with the correct MIME type from the file extension
// so the browser knows to display it inline instead of downloading.
async function openFile(id){
  const f=files.find(f=>f.id===id);
  if(!f){toast('File not found','error');return;}

  // Encrypted: ask for password first
  if(f.enc){ promptPW(id,'open'); return; }

  // Server-hosted file: open URL directly
  if(f.serverPath){ window.open(f.serverPath,'_blank','noopener'); return; }

  // Own file stored in IndexedDB
  if(f.own){
    const raw=await idbGet(id);
    if(!raw){ toast('File data not found — it may have been cleared','error'); return; }
    openBlobInline(raw, f.ext, f.name);
    return;
  }

  toast('Sample file — not available to open','info');
}

// Re-wraps the stored blob with the correct MIME type (from extension)
// then opens it inline in a new tab, or downloads if not browser-renderable.
function openBlobInline(rawBlob, ext, filename){
  const mime = mimeOf(ext);
  // Always create a new Blob with the correct MIME — this is the critical fix.
  // If the stored blob already has the right type nothing changes; if it was
  // stored as application/octet-stream this overrides it.
  const blob = new Blob([rawBlob], {type: mime});
  const url  = URL.createObjectURL(blob);

  if(isInline(ext)){
    // Open in new tab — browser will render PDF, image, video, text inline
    window.open(url,'_blank','noopener');
    // Revoke after a generous delay so the tab has time to load
    setTimeout(()=>URL.revokeObjectURL(url), 60000);
  } else {
    // Not renderable (zip, docx, xlsx…) — trigger a download instead
    const a=document.createElement('a');
    a.href=url; a.download=filename;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(()=>URL.revokeObjectURL(url),10000);
    toast(`"${filename}" downloaded (cannot preview this file type)`,'info');
  }
}

// ── DOWNLOAD FILE ────────────────────────────────────────────
// Always forces a file save — never opens in a tab.
async function dlFile(id){
  const f=files.find(f=>f.id===id);
  if(!f){toast('File not found','error');return;}

  if(f.enc){ promptPW(id,'download'); return; }

  if(f.serverPath){
    const a=document.createElement('a'); a.href=API+'/download/'+f.id; a.download=f.name;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    toast(`Downloading "${f.name}"`,'success'); return;
  }

  if(f.own){
    const raw=await idbGet(id);
    if(!raw){ toast('File data not found','error'); return; }
    const blob=new Blob([raw],{type:mimeOf(f.ext)});
    dlBlob(blob,f.name);
    toast(`Downloading "${f.name}"`,'success'); return;
  }

  toast('Sample file — not available for download','info');
}

function dlBlob(blob,name){
  const url=URL.createObjectURL(blob);
  const a=document.createElement('a'); a.href=url; a.download=name;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(()=>URL.revokeObjectURL(url),10000);
}

// ── Navigation ───────────────────────────────────────────────
function switchView(v){
  view=v;
  document.querySelectorAll('.view').forEach(el=>el.classList.remove('active'));
  document.getElementById('view-'+v)?.classList.add('active');
  document.querySelectorAll('.nav-item').forEach(el=>el.classList.toggle('active',el.dataset.view===v));
  const titles={dashboard:'Dashboard',files:'My Files',shared:'Shared',starred:'Starred',recent:'Recent',uploads:'Uploads',trash:'Trash',settings:'Settings'};
  document.getElementById('topbar-title').textContent=titles[v]||'FileVault';
  render();
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebar-overlay').classList.remove('show');
}
function render(){
  ({dashboard:renderDash,files:renderFiles,shared:renderShared,starred:renderStarred,recent:renderRecent,uploads:renderUploads,trash:renderTrash})[view]?.();
  document.getElementById('file-count-badge').textContent=files.length;
}

// ── Dashboard ────────────────────────────────────────────────
function renderDash(){
  const h=new Date().getHours();
  document.getElementById('greeting').innerHTML=`Good ${h<12?'morning':h<17?'afternoon':'evening'}, <span class="name-gradient">Alex</span> 👋`;
  document.getElementById('greeting-date').textContent=new Date().toLocaleDateString('en-US',{weekday:'long',year:'numeric',month:'long',day:'numeric'});
  const tb=totalB();
  countUp('stat-total',files.length,1400);
  countUp('stat-shared',3,900);
  countUp('stat-enc',files.filter(f=>f.enc).length,800);
  document.getElementById('stat-storage').textContent=(tb/1073741824).toFixed(2)+' GB';
  const pct=Math.min((tb/(100*1073741824))*100,100).toFixed(1);
  document.getElementById('donut-pct').textContent=pct+'%';
  document.getElementById('storage-fill').style.width=pct+'%';
  document.getElementById('storage-text').textContent=fmtBytes(tb)+' / 100 GB';
  const recent=[...files].sort((a,b)=>new Date(b.date)-new Date(a.date)).slice(0,6);
  document.getElementById('recent-list').innerHTML=recent.map(f=>`
    <div class="rec-row" onclick="openPreview('${f.id}')">
      <div class="rec-icon" style="background:${f.clr}22">${f.icon}</div>
      <div class="rec-info"><div class="rec-name">${x(f.name)}</div><div class="rec-meta">${f.ext.toUpperCase()} · ${f.fmt}${f.enc?' · 🔐':''}</div></div>
      <div class="rec-date">${ago(f.date)}</div>
    </div>`).join('');
  document.getElementById('activity-feed').innerHTML=activity.slice(0,5).map(a=>`
    <div class="act-item"><div class="act-dot" style="background:${a.c}"></div><div class="act-text">${x(a.t)}</div><div class="act-time">${a.a}</div></div>`).join('');
}
function countUp(id,target,ms){
  const el=document.getElementById(id);if(!el)return;
  let v=0;const step=target/(ms/16);
  const t=setInterval(()=>{v=Math.min(v+step,target);el.textContent=Math.floor(v);if(v>=target)clearInterval(t);},16);
}

// ── File views ───────────────────────────────────────────────
function renderFiles(){
  let list=[...files];
  if(filter==='encrypted') list=list.filter(f=>f.enc);
  else if(filter!=='all')  list=list.filter(f=>f.cat===filter);
  if(search){
    list=list.filter(f=>f.name.toLowerCase().includes(search.toLowerCase()));
    document.getElementById('search-msg').textContent=list.length+' match(es) for "'+search+'"';
  }else document.getElementById('search-msg').textContent='';
  list.sort((a,b)=>{
    if(sort==='name') return a.name.localeCompare(b.name);
    if(sort==='size') return b.size-a.size;
    if(sort==='type') return a.ext.localeCompare(b.ext);
    return new Date(b.date)-new Date(a.date);
  });
  document.getElementById('files-count-badge').textContent=list.length+' file'+(list.length!==1?'s':'');
  const c=document.getElementById('files-container');
  c.className=grid?'files-grid':'files-list';
  c.innerHTML=list.length
    ?list.map((f,i)=>grid?gCard(f,i):lRow(f,i)).join('')
    :`<div class="empty" style="grid-column:1/-1"><div class="ei">📂</div><p>No files found</p></div>`;
}
function renderShared(){
  const l=files.filter(f=>f.shared&&f.shared.length);
  document.getElementById('shared-list').innerHTML=l.length?l.map((f,i)=>gCard(f,i)).join(''):`<div class="empty"><div class="ei">👥</div><p>No shared files</p></div>`;
}
function renderStarred(){
  const l=files.filter(f=>f.star);
  document.getElementById('starred-list').innerHTML=l.length?l.map((f,i)=>gCard(f,i)).join(''):`<div class="empty"><div class="ei">★</div><p>No starred files</p></div>`;
}
function renderRecent(){
  const l=[...files].sort((a,b)=>new Date(b.date)-new Date(a.date)).slice(0,20);
  document.getElementById('recent-view').innerHTML=l.map((f,i)=>gCard(f,i)).join('');
}
function renderUploads(){
  const l=files.filter(f=>f.own).sort((a,b)=>new Date(b.date)-new Date(a.date));
  const el=document.getElementById('uploads-list');
  if(!l.length){el.innerHTML=`<div class="empty"><div class="ei">⬆</div><p>No uploads yet</p></div>`;return;}
  el.innerHTML=`<p style="color:var(--tm);font-size:13px;margin-bottom:14px">${l.length} file(s) · ${fmtBytes(l.reduce((s,f)=>s+f.size,0))} total</p>
    <table class="up-table"><thead><tr><th></th><th>Name</th><th>Type</th><th>Size</th><th>Uploaded</th><th>Status</th></tr></thead>
    <tbody>${l.map(f=>`<tr><td>${f.icon}</td><td>${x(f.name)}</td><td>${f.ext.toUpperCase()}</td><td>${f.fmt}</td><td>${fmtDate(f.date)}</td><td>${f.enc?'<span class="enc-tbadge">🔐 Encrypted</span>':'<span class="ok-badge">✓ Complete</span>'}</td></tr>`).join('')}</tbody></table>`;
}
function renderTrash(){
  const el=document.getElementById('trash-list');
  if(!trash.length){el.innerHTML=`<div class="empty"><div class="ei">🗑</div><p>Trash is empty</p></div>`;return;}
  el.innerHTML=trash.map(t=>`
    <div class="trash-card">
      <div style="font-size:30px">${t.file.icon}</div>
      <div class="trash-name">${x(t.file.name)}</div>
      <div class="trash-date">Deleted ${ago(t.at)}</div>
      <div class="trash-acts">
        <button class="btn-secondary" style="font-size:11px;padding:4px 10px" onclick="restoreFile('${t.file.id}')">Restore</button>
        <button class="btn-danger"    style="font-size:11px;padding:4px 10px" onclick="permDel('${t.file.id}')">Delete</button>
      </div>
    </div>`).join('');
}

// ── Card templates ───────────────────────────────────────────
function gCard(f,i){
  return `
  <div class="fcard${f.enc?' enc-card':''}" style="animation-delay:${i*45}ms" onclick="openPreview('${f.id}')">
    ${f.enc?'<span class="enc-label">🔐 ENC</span>':(!f.own?'<span style="position:absolute;top:8px;right:8px;font-size:10px;opacity:.3">🔒</span>':'')}
    <div class="fcard-top">
      <input type="checkbox" class="fchk" onclick="event.stopPropagation()" />
      <button class="fstar${f.star?' on':''}" onclick="event.stopPropagation();toggleStar('${f.id}')">${f.star?'★':'☆'}</button>
    </div>
    <div class="ficon-box" style="background:${f.clr}22">${f.icon}${f.enc?'<span class="enc-overlay">🔐</span>':''}</div>
    <div class="fname" title="${x(f.name)}">${x(f.name)}</div>
    <div class="fmeta">${f.fmt} · ${ago(f.date)}</div>
    <div class="factions">
      <button class="faction" title="Preview"  onclick="event.stopPropagation();openPreview('${f.id}')">👁</button>
      <button class="faction" title="Open in browser" onclick="event.stopPropagation();openFile('${f.id}')">↗</button>
      <button class="faction" title="Download to disk" onclick="event.stopPropagation();dlFile('${f.id}')">⬇</button>
      <button class="faction" title="Share"    onclick="event.stopPropagation();openShare('${f.id}')">🔗</button>
      ${f.own?`<button class="faction" title="Delete" onclick="event.stopPropagation();delFile('${f.id}')">🗑</button>`:''}
    </div>
  </div>`;
}
function lRow(f,i){
  return `
  <div class="lrow" style="animation-delay:${i*30}ms" onclick="openPreview('${f.id}')">
    <span class="licon">${f.icon}${f.enc?'🔐':''}</span>
    <span class="lname">${x(f.name)}</span>
    <span class="ltype">${f.ext.toUpperCase()}</span>
    <span class="lsize">${f.fmt}</span>
    <span class="ldate">${fmtDate(f.date)}</span>
    <div class="lactions" onclick="event.stopPropagation()">
      <button class="faction" title="Open" onclick="openFile('${f.id}')">↗</button>
      <button class="faction" title="Download" onclick="dlFile('${f.id}')">⬇</button>
      <button class="faction" title="Share" onclick="openShare('${f.id}')">🔗</button>
      ${f.own?`<button class="faction" onclick="delFile('${f.id}')">🗑</button>`:''}
    </div>
  </div>`;
}

// ── Preview modal ─────────────────────────────────────────────
async function openPreview(id){
  const f=files.find(f=>f.id===id);if(!f)return;
  activeFile=f;
  const pa=document.getElementById('modal-preview-area');

  if(f.enc){
    pa.innerHTML=`<div style="text-align:center"><div style="font-size:64px">🔐</div><p style="color:var(--tm);font-size:13px;margin-top:10px">Encrypted — unlock to preview</p></div>`;
  }else if(f.own){
    const raw=await idbGet(id);
    if(raw){
      const blob=new Blob([raw],{type:mimeOf(f.ext)});
      const url=URL.createObjectURL(blob);
      if(f.cat==='image'){
        pa.innerHTML=`<img src="${url}" style="max-width:100%;max-height:380px;object-fit:contain" />`;
        setTimeout(()=>URL.revokeObjectURL(url),60000);
      }else if(f.cat==='video'){
        pa.innerHTML=`<video src="${url}" controls style="width:100%;max-height:340px"></video>`;
      }else if(f.ext==='pdf'){
        pa.innerHTML=`<iframe src="${url}" style="width:100%;height:340px;border:none"></iframe>`;
        setTimeout(()=>URL.revokeObjectURL(url),60000);
      }else if(['txt','md','csv','json'].includes(f.ext)){
        // Show text preview inline
        const text=await raw.text?.()|| await new Response(raw).text();
        pa.innerHTML=`<pre style="color:var(--t);font-size:12px;padding:16px;max-height:360px;overflow:auto;white-space:pre-wrap;word-break:break-word;width:100%">${x(text.slice(0,4000))}${text.length>4000?'\n…(truncated)':''}</pre>`;
        URL.revokeObjectURL(url);
      }else{
        pa.innerHTML=`<span style="font-size:72px">${f.icon}</span>`;
        URL.revokeObjectURL(url);
      }
    }else{
      pa.innerHTML=`<span style="font-size:72px">${f.icon}</span>`;
    }
  }else if(f.serverPath&&f.cat==='image'){
    pa.innerHTML=`<img src="${API}/preview/${f.id}" style="max-width:100%;max-height:380px" />`;
  }else{
    pa.innerHTML=`<span style="font-size:72px">${f.icon}</span>`;
  }

  const ob=document.getElementById('btn-open');
  ob.style.display=(f.own||f.serverPath)?'inline-flex':'none';
  ob.onclick=()=>openFile(f.id);

  document.getElementById('mfname').textContent=f.name;
  document.getElementById('rename-pencil').style.display=f.own?'inline-block':'none';
  document.getElementById('rename-row').style.display='none';
  document.getElementById('rename-input').value=f.name;

  document.getElementById('meta-rows').innerHTML=[
    ['Type',     f.ext.toUpperCase()+' · '+f.cat],
    ['MIME',     mimeOf(f.ext)],
    ['Size',     f.fmt],
    ['Uploaded', fmtDate(f.date)],
    ['Owner',    'Alex Johnson'],
    ['Encrypted',f.enc?'🔐 Yes — AES-256':'No'],
    ['Shared',   f.shared&&f.shared.length?f.shared.join(', '):'-'],
    ['Source',   f.own?'✅ Your upload':'🔒 Sample file'],
  ].map(([k,v])=>`<div class="meta-row"><span class="mk">${k}</span><span class="mv">${x(String(v))}</span></div>`).join('');

  openModal('preview-backdrop');
}
function closePreview(){ closeModal('preview-backdrop'); activeFile=null; }

// ── Password unlock ───────────────────────────────────────────
function promptPW(id,action){
  const f=files.find(f=>f.id===id);if(!f)return;
  document.getElementById('pw-sub').textContent=`"${f.name}" is encrypted. Enter the password to ${action} it.`;
  document.getElementById('pw-input').value='';
  document.getElementById('pw-error').textContent='';
  openModal('pw-backdrop');
  const btn=document.getElementById('pw-confirm');
  btn.onclick=async()=>{
    const pw=document.getElementById('pw-input').value;
    if(!pw){document.getElementById('pw-error').textContent='Enter a password';return;}
    btn.textContent='Unlocking…';btn.disabled=true;
    const encBlob=await idbGet(id);
    if(!encBlob){btn.textContent='Unlock';btn.disabled=false;document.getElementById('pw-error').textContent='File data not found';return;}
    const decBlob=await decryptBlob(encBlob,pw);
    btn.textContent='Unlock';btn.disabled=false;
    if(!decBlob){document.getElementById('pw-error').textContent='❌ Wrong password';return;}
    closeModal('pw-backdrop');
    // Re-wrap with correct MIME from extension
    const typed=new Blob([decBlob],{type:mimeOf(f.ext)});
    if(action==='open')     openBlobInline(typed,f.ext,f.name);
    if(action==='download') dlBlob(typed,f.name);
  };
  document.getElementById('pw-input').onkeydown=e=>{if(e.key==='Enter')btn.click();};
}

// ── File actions ──────────────────────────────────────────────
function delFile(id){
  const f=files.find(f=>f.id===id);if(!f||!f.own)return;
  trash.unshift({file:f,at:new Date().toISOString()});
  files=files.filter(f=>f.id!==id);
  saveMeta();render();toast(`"${f.name}" moved to trash`,'info');
}
function restoreFile(id){
  const item=trash.find(t=>t.file.id===id);if(!item)return;
  files.push(item.file);trash=trash.filter(t=>t.file.id!==id);
  saveMeta();render();toast(`"${item.file.name}" restored`,'success');
}
function permDel(id){
  const item=trash.find(t=>t.file.id===id);
  trash=trash.filter(t=>t.file.id!==id);
  if(item)idbDel(id);
  saveMeta();renderTrash();toast('Permanently deleted','error');
}
function toggleStar(id){
  const f=files.find(f=>f.id===id);if(!f)return;
  f.star=!f.star;saveMeta();render();
  toast(f.star?'★ Starred':'Star removed','info');
}
function renameFile(id,name){
  const f=files.find(f=>f.id===id);if(!f||!f.own)return;
  if(!name.trim()){toast('Name cannot be empty','error');return;}
  f.name=name.trim();saveMeta();render();
  activity.unshift({c:'#22D3A5',t:`Renamed to "${f.name}"`,a:'just now'});
  toast('Renamed','success');
}

// ── Share modal ───────────────────────────────────────────────
function openShare(id){
  const f=files.find(f=>f.id===id);if(!f)return;
  shareId=id;
  document.getElementById('share-link').value=window.location.origin+'/share/'+f.id;
  document.getElementById('share-user').value='';
  openModal('share-backdrop');
}

// ── Encrypt upload modal ──────────────────────────────────────
function showEncModal(fileList){
  pendingFiles=Array.from(fileList);
  if(!pendingFiles.length)return;
  document.getElementById('enc-file-info').textContent=
    pendingFiles.length===1?`📄 ${pendingFiles[0].name} (${fmtBytes(pendingFiles[0].size)})`:`${pendingFiles.length} files selected`;
  document.getElementById('enc-pw').value='';
  document.getElementById('enc-pw2').value='';
  document.getElementById('pw-strength-fill').style.cssText='width:0';
  document.getElementById('pw-strength-label').textContent='';
  document.getElementById('enc-toggle').checked=true;
  document.getElementById('enc-pw').disabled=false;
  document.getElementById('enc-pw2').disabled=false;
  document.getElementById('enc-confirm').textContent='🔐 Upload Encrypted';
  openModal('enc-backdrop');
}
function toggleEye(inputId,btn){
  const inp=document.getElementById(inputId);if(!inp)return;
  const show=inp.type==='password';
  inp.type=show?'text':'password';
  btn.textContent=show?'🙈':'👁';
}
function checkStrength(pw){
  const fill=document.getElementById('pw-strength-fill');
  const lbl=document.getElementById('pw-strength-label');
  if(!pw){fill.style.cssText='width:0';lbl.textContent='';return;}
  const strong=pw.length>=10&&/[A-Z]/.test(pw)&&/[0-9]/.test(pw)&&/[^A-Za-z0-9]/.test(pw);
  const medium=pw.length>=6&&(/[A-Z]/.test(pw)||/[0-9]/.test(pw));
  if(strong){fill.style.cssText='width:100%;background:#22D3A5';lbl.textContent='Strong ✓';lbl.style.color='#22D3A5';}
  else if(medium){fill.style.cssText='width:60%;background:#F5A623';lbl.textContent='Medium';lbl.style.color='#F5A623';}
  else{fill.style.cssText='width:30%;background:#FF5370';lbl.textContent='Weak';lbl.style.color='#FF5370';}
}

// ── Upload: store raw Blob in IndexedDB (fast, no base64) ─────
async function processUpload(file,pw,doEnc){
  const ext=file.name.split('.').pop().toLowerCase();
  const cat=catOf(file.name), id=uid();
  const pList=document.getElementById('upload-progress-list');
  const item=document.createElement('div');
  item.className='up-item';
  item.innerHTML=`<span>${iconOf(cat,ext)}${doEnc?'🔐':''}</span>
    <span style="flex:0 0 auto;max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px">${x(file.name)}</span>
    <div class="pb-wrap"><div class="pb-fill" id="pb${id}" style="width:0"></div></div>`;
  pList.appendChild(item);
  const fill=document.getElementById('pb'+id);
  let pct=0;
  const tk=setInterval(()=>{pct=Math.min(pct+Math.random()*20,90);fill.style.width=pct+'%';},80);

  const stored = doEnc&&pw ? await encryptBlob(file,pw) : file;
  await idbPut(id, stored);

  clearInterval(tk); fill.style.width='100%';

  const nf={id,name:file.name,ext,size:file.size,fmt:fmtBytes(file.size),
    date:new Date().toISOString(),cat,icon:iconOf(cat,ext),clr:clrOf(cat),
    star:false,own:true,enc:doEnc&&!!pw,shared:[]};

  // Background server upload
  const fd=new FormData(); fd.append('file',file);
  fd.append('meta',JSON.stringify({id,name:file.name,size:file.size,ext,cat}));
  fetch(API+'/upload',{method:'POST',body:fd}).then(r=>r.ok?r.json():null)
    .then(d=>{if(d){nf.serverPath=d.path;saveMeta();}}).catch(()=>{});

  files.push(nf); saveMeta();
  activity.unshift({c:doEnc?'#F5A623':'#4F8BFF',t:`"${nf.name}" uploaded${doEnc?' (encrypted)':''}`,a:'just now'});
  toast(`"${nf.name}" uploaded${doEnc?' 🔐 encrypted':''}`, 'success');
  setTimeout(()=>item.remove(),900);
  if(view==='dashboard') renderDash();
  if(view==='files')     renderFiles();
  document.getElementById('file-count-badge').textContent=files.length;
}

// ── Modal helpers ─────────────────────────────────────────────
function openModal(id){  document.getElementById(id).classList.add('open');    }
function closeModal(id){ document.getElementById(id).classList.remove('open'); }
function closeAll(){     document.querySelectorAll('.backdrop').forEach(el=>el.classList.remove('open')); activeFile=null; shareId=null; }

// ── Bind events ───────────────────────────────────────────────
function bind(){
  document.querySelectorAll('.nav-item[data-view]').forEach(el=>
    el.addEventListener('click',e=>{e.preventDefault();switchView(el.dataset.view);}));
  document.querySelectorAll('.view-all[data-view]').forEach(el=>
    el.addEventListener('click',e=>{e.preventDefault();switchView(el.dataset.view);}));

  document.getElementById('hamburger').addEventListener('click',()=>{
    document.getElementById('sidebar').classList.toggle('open');
    document.getElementById('sidebar-overlay').classList.toggle('show');
  });
  document.getElementById('sidebar-overlay').addEventListener('click',()=>{
    document.getElementById('sidebar').classList.remove('open');
    document.getElementById('sidebar-overlay').classList.remove('show');
  });
  document.getElementById('user-menu-btn').addEventListener('click',e=>{
    e.stopPropagation();
    document.getElementById('user-dropdown').classList.toggle('open');
  });
  document.addEventListener('click',()=>document.getElementById('user-dropdown').classList.remove('open'));

  const si=document.getElementById('search-input');
  si.addEventListener('input',e=>{search=e.target.value;if(view==='files')renderFiles();});
  si.addEventListener('keydown',e=>{
    if(e.key==='Escape'){search='';si.value='';if(view==='files')renderFiles();}
    if(e.key==='Enter')switchView('files');
  });
  document.addEventListener('keydown',e=>{
    if((e.metaKey||e.ctrlKey)&&e.key==='k'){e.preventDefault();si.focus();}
    if(e.key==='Escape')closeAll();
  });

  document.getElementById('filter-chips').addEventListener('click',e=>{
    const c=e.target.closest('.chip');if(!c)return;
    document.querySelectorAll('.chip').forEach(el=>el.classList.remove('active'));
    c.classList.add('active');filter=c.dataset.filter;renderFiles();
  });
  document.getElementById('sort-select').addEventListener('change',e=>{sort=e.target.value;renderFiles();});
  document.getElementById('grid-btn').addEventListener('click',()=>{
    grid=true;document.getElementById('grid-btn').classList.add('active');document.getElementById('list-btn').classList.remove('active');renderFiles();
  });
  document.getElementById('list-btn').addEventListener('click',()=>{
    grid=false;document.getElementById('list-btn').classList.add('active');document.getElementById('grid-btn').classList.remove('active');renderFiles();
  });

  document.getElementById('upload-btn').addEventListener('click',()=>document.getElementById('file-input').click());
  document.getElementById('file-input').addEventListener('change',e=>{if(e.target.files.length)showEncModal(e.target.files);e.target.value='';});
  const dz=document.getElementById('dash-drop-zone');
  dz.addEventListener('click',()=>document.getElementById('dash-file-input').click());
  document.getElementById('dash-file-input').addEventListener('change',e=>{if(e.target.files.length)showEncModal(e.target.files);e.target.value='';});
  dz.addEventListener('dragover',e=>{e.preventDefault();dz.classList.add('drag-over');});
  dz.addEventListener('dragleave',()=>dz.classList.remove('drag-over'));
  dz.addEventListener('drop',e=>{e.preventDefault();dz.classList.remove('drag-over');if(e.dataTransfer.files.length)showEncModal(e.dataTransfer.files);});

  document.getElementById('preview-close').addEventListener('click',closePreview);
  document.getElementById('preview-backdrop').addEventListener('click',e=>{if(e.target===e.currentTarget)closePreview();});
  document.getElementById('btn-download').addEventListener('click',()=>{if(activeFile)dlFile(activeFile.id);});
  document.getElementById('btn-share').addEventListener('click',()=>{if(activeFile){closePreview();openShare(activeFile.id);}});
  document.getElementById('btn-delete').addEventListener('click',()=>{
    if(!activeFile)return;
    if(!activeFile.own){toast('Sample files cannot be deleted','error');return;}
    delFile(activeFile.id);closePreview();
  });
  document.getElementById('rename-pencil').addEventListener('click',()=>{
    document.getElementById('rename-row').style.display='flex';
    document.getElementById('rename-input').focus();
  });
  document.getElementById('rename-save').addEventListener('click',()=>{
    if(!activeFile)return;
    const n=document.getElementById('rename-input').value;
    renameFile(activeFile.id,n);
    document.getElementById('mfname').textContent=n.trim()||activeFile.name;
    document.getElementById('rename-row').style.display='none';
  });
  document.getElementById('rename-input').addEventListener('keydown',e=>{if(e.key==='Enter')document.getElementById('rename-save').click();});

  document.getElementById('enc-close').addEventListener('click',()=>{closeModal('enc-backdrop');pendingFiles=[];});
  document.getElementById('enc-backdrop').addEventListener('click',e=>{if(e.target===e.currentTarget){closeModal('enc-backdrop');pendingFiles=[];}});
  document.getElementById('enc-pw').addEventListener('input',e=>checkStrength(e.target.value));
  document.getElementById('enc-toggle').addEventListener('change',e=>{
    const on=e.target.checked;
    document.getElementById('enc-pw').disabled=!on;
    document.getElementById('enc-pw2').disabled=!on;
    document.getElementById('enc-confirm').textContent=on?'🔐 Upload Encrypted':'⬆ Upload';
  });
  document.getElementById('enc-confirm').addEventListener('click',async()=>{
    const doEnc=document.getElementById('enc-toggle').checked;
    const pw=document.getElementById('enc-pw').value;
    const pw2=document.getElementById('enc-pw2').value;
    if(doEnc){if(!pw){toast('Enter a password','error');return;}if(pw!==pw2){toast('Passwords do not match','error');return;}if(pw.length<4){toast('Password too short (min 4)','error');return;}}
    closeModal('enc-backdrop');
    for(const f of pendingFiles)await processUpload(f,pw,doEnc);
    pendingFiles=[];
  });
  document.getElementById('enc-skip').addEventListener('click',async()=>{
    closeModal('enc-backdrop');
    for(const f of pendingFiles)await processUpload(f,'',false);
    pendingFiles=[];
  });

  document.getElementById('pw-close').addEventListener('click',()=>closeModal('pw-backdrop'));
  document.getElementById('pw-backdrop').addEventListener('click',e=>{if(e.target===e.currentTarget)closeModal('pw-backdrop');});

  document.getElementById('new-folder-btn').addEventListener('click',()=>{document.getElementById('folder-input').value='';openModal('folder-backdrop');});
  document.getElementById('folder-close').addEventListener('click',()=>closeModal('folder-backdrop'));
  document.getElementById('folder-backdrop').addEventListener('click',e=>{if(e.target===e.currentTarget)closeModal('folder-backdrop');});
  document.getElementById('folder-create').addEventListener('click',()=>{
    const name=document.getElementById('folder-input').value.trim();
    if(!name){toast('Enter a folder name','error');return;}
    const btn=document.getElementById('folder-create');
    btn.textContent='Creating…';btn.disabled=true;
    setTimeout(()=>{btn.textContent='Create Folder';btn.disabled=false;closeModal('folder-backdrop');toast(`Folder "${name}" created`,'success');},800);
  });

  document.getElementById('share-close').addEventListener('click',()=>closeModal('share-backdrop'));
  document.getElementById('share-backdrop').addEventListener('click',e=>{if(e.target===e.currentTarget)closeModal('share-backdrop');});
  document.getElementById('copy-link').addEventListener('click',()=>{
    navigator.clipboard.writeText(document.getElementById('share-link').value)
      .then(()=>toast('Link copied!','success')).catch(()=>toast('Copy failed','error'));
  });
  document.getElementById('share-send').addEventListener('click',()=>{
    const user=document.getElementById('share-user').value.trim();
    if(!user){toast('Enter a username or email','error');return;}
    if(!shareId)return;
    const f=files.find(f=>f.id===shareId);
    if(f){
      if(!f.shared)f.shared=[];
      if(!f.shared.includes(user)){
        f.shared.push(user);saveMeta();
        fetch(API+'/share',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({fileId:shareId,sharedWith:user})}).catch(()=>{});
        activity.unshift({c:'#A259FF',t:`"${f.name}" shared with ${user}`,a:'just now'});
        toast(`Shared with ${user}`,'success');
      }else toast('Already shared with this user','info');
    }
    closeModal('share-backdrop');
  });
}

// ── Init ─────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded',()=>{loadMeta();bind();switchView('dashboard');});
