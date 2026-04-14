/* ============================================================
   FileVault — dashboard.js  (Full-Stack Version)
   All data comes from the real backend API.
   Client-side AES-256-GCM encryption before upload.
   ============================================================ */
'use strict';

// Auto-detect server URL (works locally and deployed)
const API = window.location.origin;

/* ── Auth guard ── */
const TOKEN = localStorage.getItem('fv_token');
const USER  = JSON.parse(localStorage.getItem('fv_user') || 'null');
if (!TOKEN || !USER) { window.location.href = 'login.html'; }

/* ── API helper ── */
async function api(method, path, body = null, isFormData = false) {
  const opts = {
    method,
    headers: { 'Authorization': `Bearer ${TOKEN}` },
  };
  if (body && !isFormData) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  if (body && isFormData)  { opts.body = body; }
  const res = await fetch(API + path, opts);
  if (res.status === 401) { localStorage.clear(); window.location.href = 'login.html'; return null; }
  return res.json().catch(() => null);
}

/* ── MIME map ── */
const MIME = {
  jpg:'image/jpeg',jpeg:'image/jpeg',png:'image/png',gif:'image/gif',
  webp:'image/webp',svg:'image/svg+xml',bmp:'image/bmp',
  mp4:'video/mp4',mov:'video/quicktime',avi:'video/x-msvideo',mkv:'video/x-matroska',webm:'video/webm',
  mp3:'audio/mpeg',wav:'audio/wav',ogg:'audio/ogg',flac:'audio/flac',
  pdf:'application/pdf',txt:'text/plain',csv:'text/csv',
  html:'text/html',htm:'text/html',xml:'text/xml',json:'application/json',md:'text/plain',
};
function mimeOf(ext) { return MIME[ext?.toLowerCase()] || 'application/octet-stream'; }
function isInline(ext) {
  const m = mimeOf(ext);
  return m.startsWith('image/') || m.startsWith('video/') || m.startsWith('audio/') ||
         m.startsWith('text/') || m === 'application/pdf' || m === 'application/json';
}

/* ── IndexedDB: store encrypted blobs locally ── */
let DB = null;
function openDB() {
  return new Promise((res, rej) => {
    if (DB) { res(DB); return; }
    const req = indexedDB.open('filevault_blobs', 1);
    req.onupgradeneeded = e => { if (!e.target.result.objectStoreNames.contains('blobs')) e.target.result.createObjectStore('blobs'); };
    req.onsuccess = e => { DB = e.target.result; res(DB); };
    req.onerror   = e => rej(e.target.error);
  });
}
async function idbPut(key, val) {
  const db = await openDB();
  return new Promise((res, rej) => { const tx = db.transaction('blobs','readwrite'); tx.objectStore('blobs').put(val, key); tx.oncomplete = res; tx.onerror = e => rej(e.target.error); });
}
async function idbGet(key) {
  const db = await openDB();
  return new Promise((res, rej) => { const req = db.transaction('blobs').objectStore('blobs').get(key); req.onsuccess = e => res(e.target.result); req.onerror = e => rej(e.target.error); });
}
async function idbDel(key) {
  const db = await openDB();
  return new Promise((res, rej) => { const tx = db.transaction('blobs','readwrite'); tx.objectStore('blobs').delete(key); tx.oncomplete = res; tx.onerror = e => rej(e.target.error); });
}

/* ── AES-256-GCM ── */
async function deriveKey(pw, salt) {
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name:'PBKDF2', salt, iterations:100000, hash:'SHA-256' }, k, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']);
}
async function encryptBlob(blob, pw) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key  = await deriveKey(pw, salt);
  const buf  = await blob.arrayBuffer();
  const ciph = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, buf);
  const mimeB = new TextEncoder().encode(blob.type);
  const mLen  = new Uint8Array(2); new DataView(mLen.buffer).setUint16(0, mimeB.length);
  const out   = new Uint8Array(16 + 12 + 2 + mimeB.length + ciph.byteLength);
  let o = 0; out.set(salt,o);o+=16; out.set(iv,o);o+=12; out.set(mLen,o);o+=2; out.set(mimeB,o);o+=mimeB.length; out.set(new Uint8Array(ciph),o);
  return new Blob([out]);
}
async function decryptBlob(encBlob, pw) {
  try {
    const buf = await encBlob.arrayBuffer(), d = new Uint8Array(buf);
    const salt = d.slice(0, 16), iv = d.slice(16, 28);
    const mLen = new DataView(d.buffer, 28, 2).getUint16(0);
    const mime = new TextDecoder().decode(d.slice(30, 30 + mLen));
    const plain = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, await deriveKey(pw, salt), d.slice(30 + mLen));
    return new Blob([plain], { type: mime });
  } catch { return null; }
}

/* ── Helpers ── */
function fmtBytes(b) {
  if (b < 1024)       return b + ' B';
  if (b < 1048576)    return (b/1024).toFixed(0) + ' KB';
  if (b < 1073741824) return (b/1048576).toFixed(1) + ' MB';
  return (b/1073741824).toFixed(2) + ' GB';
}
function fmtDate(iso) { return iso ? new Date(iso).toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'}) : '-'; }
function ago(iso) {
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60)    return 'just now';
  if (s < 3600)  return Math.floor(s/60) + 'm ago';
  if (s < 86400) return Math.floor(s/3600) + 'h ago';
  return Math.floor(s/86400) + 'd ago';
}
function iconOf(cat, ext) {
  if (cat==='image')   return '🖼️';
  if (cat==='video')   return '🎬';
  if (cat==='archive') return '📦';
  if (ext==='pdf')     return '📄';
  if (['xls','xlsx','csv','ppt','pptx'].includes(ext)) return '📊';
  if (['doc','docx'].includes(ext))                   return '📝';
  if (['txt','md'].includes(ext))                     return '📃';
  return '📁';
}
function clrOf(cat) { return { image:'#4F8BFF', video:'#A259FF', archive:'#F5A623', document:'#FF5370' }[cat] || '#22D3A5'; }
function x(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

/* ── Toast ── */
function toast(msg, type = 'info') {
  const icons = { success:'✓', error:'✗', info:'ℹ' };
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.innerHTML = `<span class="ti">${icons[type]}</span><span class="tm2">${x(msg)}</span><button class="tx" onclick="rmToast(this.parentElement)">✕</button>`;
  document.getElementById('toast-container').appendChild(el);
  setTimeout(() => rmToast(el), 3200);
}
function rmToast(el) { if (!el||el._r) return; el._r=true; el.classList.add('out'); setTimeout(()=>el.remove(),300); }

/* ── App State ── */
let files = [], trash = [], view = 'dashboard', filter = 'all', sort = 'date', grid = true, search = '';
let activeFile = null, shareId = null, pendingFiles = [];
let activity = [];
let stats = { total:0, shared:0, encrypted:0, storageUsed:0, storageUsedFmt:'0 B', storagePct:'0', categories:{ document:0, image:0, video:0, other:0 } };

/* ── Load data from backend ── */
async function loadAll() {
  showLoading(true);
  try {
    const [filesRes, statsRes] = await Promise.all([
      api('GET', '/api/files'),
      api('GET', '/api/stats'),
    ]);
    if (filesRes?.success) {
      files = (filesRes.files || []).map(f => ({
        ...f,
        icon: iconOf(f.cat, f.ext),
        clr:  clrOf(f.cat),
        star: f.star || false,
        own:  !f.sharedWithMe,
        enc:  f.encrypted || false,
        fmt:  f.fmt || fmtBytes(f.size || 0),
      }));
      // Merge stars from localStorage
      const stars = JSON.parse(localStorage.getItem('fv_stars_' + USER.username) || '{}');
      files.forEach(f => { if (stars[f.id] !== undefined) f.star = stars[f.id]; });
    }
    if (statsRes?.success) stats = statsRes.stats;
    trash = JSON.parse(localStorage.getItem('fv_trash_' + USER.username) || '[]');
    activity = JSON.parse(localStorage.getItem('fv_activity_' + USER.username) || '[]');
    if (!activity.length) activity = [{ c:'#4F8BFF', t:'Welcome to FileVault!', a:'just now' }];
  } catch (err) {
    toast('Failed to load files', 'error');
  }
  showLoading(false);
}
function showLoading(on) {
  let el = document.getElementById('global-loading');
  if (!el) { el = document.createElement('div'); el.id='global-loading'; el.style.cssText='position:fixed;inset:0;background:rgba(7,9,13,.7);z-index:9999;display:flex;align-items:center;justify-content:center;font-size:24px'; el.innerHTML='<div style="animation:spin .7s linear infinite;border:3px solid rgba(79,139,255,.3);border-top-color:#4F8BFF;border-radius:50%;width:40px;height:40px"></div>'; document.body.appendChild(el); }
  el.style.display = on ? 'flex' : 'none';
}
function saveStars() { const m={}; files.forEach(f=>m[f.id]=f.star); localStorage.setItem('fv_stars_'+USER.username, JSON.stringify(m)); }
function saveTrash() { localStorage.setItem('fv_trash_'+USER.username, JSON.stringify(trash)); }
function saveActivity() { localStorage.setItem('fv_activity_'+USER.username, JSON.stringify(activity.slice(0,50))); }

/* ── Navigation ── */
function switchView(v) {
  view = v;
  document.querySelectorAll('.view').forEach(el => el.classList.remove('active'));
  document.getElementById('view-' + v)?.classList.add('active');
  document.querySelectorAll('.nav-item').forEach(el => el.classList.toggle('active', el.dataset.view === v));
  const titles = { dashboard:'Dashboard',files:'My Files',shared:'Shared',starred:'Starred',recent:'Recent',uploads:'Uploads',trash:'Trash',settings:'Settings' };
  document.getElementById('topbar-title').textContent = titles[v] || 'FileVault';
  render();
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebar-overlay').classList.remove('show');
}
function render() {
  ({ dashboard:renderDash, files:renderFiles, shared:renderShared, starred:renderStarred, recent:renderRecent, uploads:renderUploads, trash:renderTrash, settings:renderSettings })[view]?.();
  document.getElementById('file-count-badge').textContent = files.filter(f => f.own).length;
}

/* ── Dashboard ── */
function renderDash() {
  const h = new Date().getHours();
  const fn = USER?.firstName || 'there';
  document.getElementById('greeting').innerHTML = `Good ${h<12?'morning':h<17?'afternoon':'evening'}, <span class="name-gradient">${x(fn)}</span> 👋`;
  document.getElementById('greeting-date').textContent = new Date().toLocaleDateString('en-US',{weekday:'long',year:'numeric',month:'long',day:'numeric'});

  const owned = files.filter(f => f.own);
  countUp('stat-total',    owned.length,       1400);
  countUp('stat-shared',   stats.shared,        900);
  countUp('stat-enc',      stats.encrypted,     800);
  document.getElementById('stat-storage').textContent = stats.storageUsedFmt || '0 B';
  const pct = parseFloat(stats.storagePct || 0);
  document.getElementById('donut-pct').textContent = pct.toFixed(1) + '%';
  document.getElementById('storage-fill').style.width = Math.min(pct, 100) + '%';
  document.getElementById('storage-text').textContent = (stats.storageUsedFmt||'0 B') + ' / 100 GB';
  document.getElementById('file-count-badge').textContent = owned.length;

  // Real donut chart from categories
  const cats = stats.categories || { document:0, image:0, video:0, other:0 };
  const totalCat = cats.document + cats.image + cats.video + cats.other;
  const circumference = 2 * Math.PI * 45; // r=45 → ≈ 282.7
  const segs = [
    { id:'donut-doc', val: cats.document },
    { id:'donut-img', val: cats.image },
    { id:'donut-vid', val: cats.video },
    { id:'donut-oth', val: cats.other },
  ];
  let offset = 0;
  segs.forEach(s => {
    const el = document.getElementById(s.id);
    if (!el) return;
    const len = totalCat > 0 ? (s.val / totalCat) * circumference : 0;
    el.setAttribute('stroke-dasharray', `${len} ${circumference}`);
    el.setAttribute('stroke-dashoffset', -offset);
    offset += len;
  });

  // Recent files
  const recent = [...files].sort((a,b)=>new Date(b.uploadedAt||b.date)-new Date(a.uploadedAt||a.date)).slice(0,6);
  document.getElementById('recent-list').innerHTML = recent.length
    ? recent.map(f=>`
      <div class="rec-row" onclick="openPreview('${f.id}')">
        <div class="rec-icon" style="background:${f.clr}22">${f.icon}</div>
        <div class="rec-info"><div class="rec-name">${x(f.name)}</div><div class="rec-meta">${(f.ext||'').toUpperCase()} · ${f.fmt||''}${f.enc?' · 🔐':''}</div></div>
        <div class="rec-date">${ago(f.uploadedAt||f.date)}</div>
      </div>`).join('')
    : '<p style="color:var(--tm);font-size:13px;padding:16px 0">No files yet. Upload your first file!</p>';

  document.getElementById('activity-feed').innerHTML = activity.slice(0,5).map(a=>
    `<div class="act-item"><div class="act-dot" style="background:${a.c}"></div><div class="act-text">${x(a.t)}</div><div class="act-time">${a.a}</div></div>`).join('');
}
function countUp(id, target, ms) {
  const el = document.getElementById(id); if (!el) return;
  let v=0; const step=target/(ms/16);
  const t = setInterval(()=>{ v=Math.min(v+step,target); el.textContent=Math.floor(v); if(v>=target)clearInterval(t); },16);
}

/* ── File views ── */
function renderFiles() {
  let list = [...files];
  if (filter === 'encrypted') list = list.filter(f => f.enc);
  else if (filter !== 'all')  list = list.filter(f => f.cat === filter);
  if (search) {
    list = list.filter(f => f.name.toLowerCase().includes(search.toLowerCase()));
    document.getElementById('search-msg').textContent = list.length + ' result(s) for "' + search + '"';
  } else document.getElementById('search-msg').textContent = '';
  list.sort((a,b) => {
    if (sort==='name') return a.name.localeCompare(b.name);
    if (sort==='size') return (b.size||0)-(a.size||0);
    if (sort==='type') return (a.ext||'').localeCompare(b.ext||'');
    return new Date(b.uploadedAt||b.date) - new Date(a.uploadedAt||a.date);
  });
  document.getElementById('files-count-badge').textContent = list.length + ' file' + (list.length!==1?'s':'');
  const c = document.getElementById('files-container');
  c.className = grid ? 'files-grid' : 'files-list';
  c.innerHTML = list.length
    ? list.map((f,i) => grid ? gCard(f,i) : lRow(f,i)).join('')
    : `<div class="empty" style="grid-column:1/-1"><div class="ei">📂</div><p>No files found</p></div>`;
}
function renderShared() {
  const l = files.filter(f => f.sharedWithMe || (f.shared && f.shared.length && f.own));
  document.getElementById('shared-list').innerHTML = l.length ? l.map((f,i)=>gCard(f,i)).join('') : `<div class="empty"><div class="ei">👥</div><p>No shared files yet</p></div>`;
}
function renderStarred() {
  const l = files.filter(f => f.star);
  document.getElementById('starred-list').innerHTML = l.length ? l.map((f,i)=>gCard(f,i)).join('') : `<div class="empty"><div class="ei">★</div><p>No starred files</p></div>`;
}
function renderRecent() {
  const l = [...files].sort((a,b)=>new Date(b.uploadedAt||b.date)-new Date(a.uploadedAt||a.date)).slice(0,20);
  document.getElementById('recent-view').innerHTML = l.length ? l.map((f,i)=>gCard(f,i)).join('') : `<div class="empty"><div class="ei">🕐</div><p>No recent files</p></div>`;
}
function renderUploads() {
  const l = files.filter(f=>f.own).sort((a,b)=>new Date(b.uploadedAt||b.date)-new Date(a.uploadedAt||a.date));
  const el = document.getElementById('uploads-list');
  if (!l.length) { el.innerHTML=`<div class="empty"><div class="ei">⬆</div><p>No uploads yet</p></div>`; return; }
  el.innerHTML=`<p style="color:var(--tm);font-size:13px;margin-bottom:14px">${l.length} file(s) · ${fmtBytes(l.reduce((s,f)=>s+(f.size||0),0))} total</p>
    <table class="up-table"><thead><tr><th></th><th>Name</th><th>Type</th><th>Size</th><th>Uploaded</th><th>Status</th></tr></thead>
    <tbody>${l.map(f=>`<tr><td>${f.icon}</td><td>${x(f.name)}</td><td>${(f.ext||'').toUpperCase()}</td><td>${f.fmt}</td><td>${fmtDate(f.uploadedAt||f.date)}</td><td>${f.enc?'<span class="enc-tbadge">🔐 Encrypted</span>':'<span class="ok-badge">✓ Uploaded</span>'}</td></tr>`).join('')}</tbody></table>`;
}
function renderTrash() {
  const el = document.getElementById('trash-list');
  if (!trash.length) { el.innerHTML=`<div class="empty"><div class="ei">🗑</div><p>Trash is empty</p></div>`; return; }
  el.innerHTML = trash.map(t=>`
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
function renderSettings() {
  const s = document.getElementById('view-settings');
  if (!s) return;
  const nameInput = s.querySelector('.user-name-input');
  const emailInput = s.querySelector('.user-email-input');
  if (nameInput) nameInput.value = USER.firstName + ' ' + (USER.lastName||'');
  if (emailInput) emailInput.value = USER.email || '';

  /* Bind save button */
  const saveBtn = s.querySelector('.btn-primary');
  if (saveBtn && !saveBtn._bound) {
    saveBtn._bound = true;
    saveBtn.addEventListener('click', async () => {
      const nameParts = (nameInput?.value || '').trim().split(' ');
      const firstName = nameParts[0] || '';
      const lastName = nameParts.slice(1).join(' ') || '';
      saveBtn.textContent = 'Saving...';
      saveBtn.disabled = true;
      const res = await api('PATCH', '/api/auth/profile', { firstName, lastName });
      saveBtn.textContent = 'Save Changes';
      saveBtn.disabled = false;
      if (res?.success) {
        USER.firstName = res.user.firstName;
        USER.lastName = res.user.lastName;
        localStorage.setItem('fv_user', JSON.stringify(USER));
        populateUser();
        toast('Settings saved!', 'success');
      } else {
        toast('Failed to save settings', 'error');
      }
    });
  }
}

/* ── Card templates ── */
function gCard(f, i) {
  return `
  <div class="fcard${f.enc?' enc-card':''}" style="animation-delay:${i*45}ms" onclick="openPreview('${f.id}')">
    ${f.enc?'<span class="enc-label">🔐 ENC</span>':(!f.own?'<span style="position:absolute;top:8px;right:8px;font-size:10px;opacity:.4">👥</span>':'')}
    <div class="fcard-top">
      <input type="checkbox" class="fchk" onclick="event.stopPropagation()" />
      <button class="fstar${f.star?' on':''}" onclick="event.stopPropagation();toggleStar('${f.id}')">${f.star?'★':'☆'}</button>
    </div>
    <div class="ficon-box" style="background:${f.clr}22">${f.icon}${f.enc?'<span class="enc-overlay">🔐</span>':''}</div>
    <div class="fname" title="${x(f.name)}">${x(f.name)}</div>
    <div class="fmeta">${f.fmt} · ${ago(f.uploadedAt||f.date)}</div>
    <div class="factions">
      <button class="faction" title="Preview"  onclick="event.stopPropagation();openPreview('${f.id}')">👁</button>
      <button class="faction" title="Open"     onclick="event.stopPropagation();openFile('${f.id}')">↗</button>
      <button class="faction" title="Download" onclick="event.stopPropagation();dlFile('${f.id}')">⬇</button>
      <button class="faction" title="Share"    onclick="event.stopPropagation();openShare('${f.id}')">🔗</button>
      ${f.own?`<button class="faction" title="Delete" onclick="event.stopPropagation();delFile('${f.id}')">🗑</button>`:''}
    </div>
  </div>`;
}
function lRow(f, i) {
  return `
  <div class="lrow" style="animation-delay:${i*30}ms" onclick="openPreview('${f.id}')">
    <span class="licon">${f.icon}${f.enc?'🔐':''}</span>
    <span class="lname">${x(f.name)}</span>
    <span class="ltype">${(f.ext||'').toUpperCase()}</span>
    <span class="lsize">${f.fmt}</span>
    <span class="ldate">${fmtDate(f.uploadedAt||f.date)}</span>
    <div class="lactions" onclick="event.stopPropagation()">
      <button class="faction" onclick="openFile('${f.id}')">↗</button>
      <button class="faction" onclick="dlFile('${f.id}')">⬇</button>
      <button class="faction" onclick="openShare('${f.id}')">🔗</button>
      ${f.own?`<button class="faction" onclick="delFile('${f.id}')">🗑</button>`:''}
    </div>
  </div>`;
}

/* ── Open file inline ── */
async function openFile(id) {
  const f = files.find(f => f.id === id); if (!f) return;
  if (f.enc) { promptPW(id, 'open'); return; }
  const raw = await idbGet(id);
  if (raw) { openBlobInline(raw, f.ext, f.name); return; }
  // Stream from server
  const url = `${API}/api/files/${id}/preview`;
  if (isInline(f.ext)) {
    // Fetch with auth header, create object URL
    try {
      const res = await fetch(url, { headers: { Authorization: `Bearer ${TOKEN}` } });
      if (!res.ok) { toast('Cannot open file', 'error'); return; }
      const blob = await res.blob();
      const typed = new Blob([blob], { type: mimeOf(f.ext) });
      openBlobInline(typed, f.ext, f.name);
    } catch { toast('Failed to open file', 'error'); }
  } else {
    dlFile(id);
  }
}
function openBlobInline(rawBlob, ext, filename) {
  const blob = new Blob([rawBlob], { type: mimeOf(ext) });
  const url  = URL.createObjectURL(blob);
  if (isInline(ext)) {
    window.open(url, '_blank', 'noopener');
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  } else {
    const a = document.createElement('a'); a.href=url; a.download=filename;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 10000);
    toast(`"${filename}" downloaded`, 'info');
  }
}

/* ── Download ── */
async function dlFile(id) {
  const f = files.find(f => f.id === id); if (!f) return;
  if (f.enc) { promptPW(id, 'download'); return; }
  const raw = await idbGet(id);
  if (raw) { dlBlob(new Blob([raw], { type: mimeOf(f.ext) }), f.name); toast(`Downloading "${f.name}"`, 'success'); return; }
  // Download from server
  try {
    const res = await fetch(`${API}/api/files/${id}/download`, { headers: { Authorization: `Bearer ${TOKEN}` } });
    if (!res.ok) { toast('Download failed', 'error'); return; }
    const blob = await res.blob();
    dlBlob(new Blob([blob], { type: mimeOf(f.ext) }), f.name);
    toast(`Downloaded "${f.name}"`, 'success');
  } catch { toast('Download failed', 'error'); }
}
function dlBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a   = document.createElement('a'); a.href=url; a.download=name;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

/* ── Preview modal ── */
async function openPreview(id) {
  const f = files.find(f => f.id === id); if (!f) return;
  activeFile = f;
  const pa = document.getElementById('modal-preview-area');

  if (f.enc) {
    pa.innerHTML = `<div style="text-align:center"><div style="font-size:64px">🔐</div><p style="color:var(--tm);font-size:13px;margin-top:10px">Encrypted — unlock to preview</p></div>`;
  } else {
    const raw = await idbGet(id);
    if (raw) {
      const blob = new Blob([raw], { type: mimeOf(f.ext) });
      const url  = URL.createObjectURL(blob);
      if (f.cat === 'image')       pa.innerHTML = `<img src="${url}" style="max-width:100%;max-height:380px;object-fit:contain" />`;
      else if (f.cat === 'video')  pa.innerHTML = `<video src="${url}" controls style="width:100%;max-height:340px"></video>`;
      else if (f.ext === 'pdf')    pa.innerHTML = `<iframe src="${url}" style="width:100%;height:340px;border:none"></iframe>`;
      else if (['txt','md','csv','json'].includes(f.ext)) {
        const text = await new Response(raw).text();
        pa.innerHTML = `<pre style="color:var(--t);font-size:12px;padding:16px;max-height:360px;overflow:auto;white-space:pre-wrap;word-break:break-word;width:100%">${x(text.slice(0,4000))}${text.length>4000?'\n…(truncated)':''}</pre>`;
        URL.revokeObjectURL(url);
      } else { pa.innerHTML = `<span style="font-size:72px">${f.icon}</span>`; URL.revokeObjectURL(url); }
      setTimeout(() => URL.revokeObjectURL(url), 60000);
    } else {
      // Try server preview
      try {
        const res = await fetch(`${API}/api/files/${id}/preview`, { headers: { Authorization: `Bearer ${TOKEN}` } });
        if (res.ok) {
          const blob = await res.blob();
          const url2 = URL.createObjectURL(new Blob([blob], { type: mimeOf(f.ext) }));
          if (f.cat==='image') pa.innerHTML = `<img src="${url2}" style="max-width:100%;max-height:380px;object-fit:contain" />`;
          else if (f.cat==='video') pa.innerHTML = `<video src="${url2}" controls style="width:100%;max-height:340px"></video>`;
          else if (f.ext==='pdf')   pa.innerHTML = `<iframe src="${url2}" style="width:100%;height:340px;border:none"></iframe>`;
          else pa.innerHTML = `<span style="font-size:72px">${f.icon}</span>`;
          setTimeout(() => URL.revokeObjectURL(url2), 60000);
        } else pa.innerHTML = `<span style="font-size:72px">${f.icon}</span>`;
      } catch { pa.innerHTML = `<span style="font-size:72px">${f.icon}</span>`; }
    }
  }

  const ob = document.getElementById('btn-open');
  ob.style.display = 'inline-flex';
  ob.onclick = () => openFile(f.id);

  document.getElementById('mfname').textContent = f.name;
  document.getElementById('rename-pencil').style.display = f.own ? 'inline-block' : 'none';
  document.getElementById('rename-row').style.display = 'none';
  document.getElementById('rename-input').value = f.name;

  document.getElementById('meta-rows').innerHTML = [
    ['Type',      (f.ext||'').toUpperCase() + ' · ' + (f.cat||'')],
    ['MIME',      mimeOf(f.ext)],
    ['Size',      f.fmt],
    ['Uploaded',  fmtDate(f.uploadedAt||f.date)],
    ['Owner',     f.own ? (USER.firstName + ' ' + (USER.lastName||'')) : (f.owner||'Other')],
    ['Encrypted', f.enc ? '🔐 Yes — AES-256-GCM' : 'No'],
    ['Shared',    f.shared?.length ? f.shared.join(', ') : '—'],
  ].map(([k,v]) => `<div class="meta-row"><span class="mk">${k}</span><span class="mv">${x(String(v))}</span></div>`).join('');

  openModal('preview-backdrop');
}
function closePreview() { closeModal('preview-backdrop'); activeFile = null; }

/* ── Password unlock ── */
function promptPW(id, action) {
  const f = files.find(f => f.id === id); if (!f) return;
  document.getElementById('pw-sub').textContent = `"${f.name}" is encrypted. Enter the password to ${action}.`;
  document.getElementById('pw-input').value = '';
  document.getElementById('pw-error').textContent = '';
  openModal('pw-backdrop');
  const btn = document.getElementById('pw-confirm');
  btn.onclick = async () => {
    const pw = document.getElementById('pw-input').value;
    if (!pw) { document.getElementById('pw-error').textContent = 'Enter a password'; return; }
    btn.textContent = 'Unlocking…'; btn.disabled = true;
    const encBlob = await idbGet(id);
    if (!encBlob) {
      // Try fetching from server and decrypt
      try {
        const res = await fetch(`${API}/api/files/${id}/download`, { headers: { Authorization: `Bearer ${TOKEN}` } });
        if (!res.ok) throw new Error();
        const blob = await res.blob();
        const dec  = await decryptBlob(blob, pw);
        btn.textContent = 'Unlock'; btn.disabled = false;
        if (!dec) { document.getElementById('pw-error').textContent = '❌ Wrong password'; return; }
        closeModal('pw-backdrop');
        if (action === 'open')     openBlobInline(dec, f.ext, f.name);
        if (action === 'download') dlBlob(dec, f.name);
      } catch { btn.textContent='Unlock'; btn.disabled=false; document.getElementById('pw-error').textContent='File not found'; }
      return;
    }
    const dec = await decryptBlob(encBlob, pw);
    btn.textContent = 'Unlock'; btn.disabled = false;
    if (!dec) { document.getElementById('pw-error').textContent = '❌ Wrong password'; return; }
    closeModal('pw-backdrop');
    if (action === 'open')     openBlobInline(dec, f.ext, f.name);
    if (action === 'download') dlBlob(dec, f.name);
  };
  document.getElementById('pw-input').onkeydown = e => { if (e.key === 'Enter') btn.click(); };
}

/* ── File actions ── */
async function delFile(id) {
  const f = files.find(f => f.id === id); if (!f || !f.own) return;
  if (!confirm(`Move "${f.name}" to trash?`)) return;
  const res = await api('DELETE', `/api/files/${id}`);
  if (res?.success) {
    trash.unshift({ file: f, at: new Date().toISOString() });
    files = files.filter(f => f.id !== id);
    await idbDel(id);
    saveTrash(); addActivity('#FF5370', `"${f.name}" deleted`);
    render(); toast(`"${f.name}" deleted`, 'info');
    // Refresh stats
    const s = await api('GET', '/api/stats');
    if (s?.success) stats = s.stats;
  } else toast('Delete failed', 'error');
}
function restoreFile(id) {
  const item = trash.find(t => t.file.id === id); if (!item) return;
  files.push(item.file); trash = trash.filter(t => t.file.id !== id);
  saveTrash(); render(); toast(`"${item.file.name}" restored`, 'success');
}
async function permDel(id) {
  const item = trash.find(t => t.file.id === id);
  trash = trash.filter(t => t.file.id !== id);
  if (item) await idbDel(id);
  saveTrash(); renderTrash(); toast('Permanently deleted', 'error');
}
function toggleStar(id) {
  const f = files.find(f => f.id === id); if (!f) return;
  f.star = !f.star; saveStars(); render();
  toast(f.star ? '★ Starred' : 'Star removed', 'info');
}
async function renameFile(id, name) {
  const f = files.find(f => f.id === id); if (!f || !f.own) return;
  if (!name.trim()) { toast('Name cannot be empty', 'error'); return; }
  const res = await api('PATCH', `/api/files/${id}/rename`, { name: name.trim() });
  if (res?.success) {
    f.name = name.trim(); render();
    addActivity('#22D3A5', `Renamed to "${f.name}"`);
    toast('Renamed', 'success');
  } else toast('Rename failed', 'error');
}

/* ── Share modal ── */
function openShare(id) {
  const f = files.find(f => f.id === id); if (!f) return;
  shareId = id;
  document.getElementById('share-link').value = window.location.origin + '/share/' + f.id;
  document.getElementById('share-user').value = '';
  document.getElementById('share-perm').value = 'read';
  openModal('share-backdrop');
}

/* ── Activity ── */
function addActivity(color, text) {
  activity.unshift({ c: color, t: text, a: 'just now' });
  activity = activity.slice(0, 50);
  saveActivity();
  // Also add as notification
  const iconMap = { '#4F8BFF': '📤', '#22D3A5': '✏️', '#F5A623': '🔐', '#FF5370': '🗑️', '#A259FF': '🔗' };
  addNotification(iconMap[color] || '📌', text, text, false);
}

/* ── Encrypt upload modal ── */
function showEncModal(fileList) {
  pendingFiles = Array.from(fileList);
  if (!pendingFiles.length) return;
  document.getElementById('enc-file-info').textContent =
    pendingFiles.length === 1 ? `📄 ${pendingFiles[0].name} (${fmtBytes(pendingFiles[0].size)})` : `${pendingFiles.length} files selected`;
  document.getElementById('enc-pw').value  = '';
  document.getElementById('enc-pw2').value = '';
  document.getElementById('pw-strength-fill').style.cssText = 'width:0';
  document.getElementById('pw-strength-label').textContent = '';
  document.getElementById('enc-toggle').checked = true;
  document.getElementById('enc-pw').disabled  = false;
  document.getElementById('enc-pw2').disabled = false;
  document.getElementById('enc-confirm').textContent = '🔐 Upload Encrypted';
  openModal('enc-backdrop');
}
function toggleEye(inputId, btn) {
  const inp = document.getElementById(inputId); if (!inp) return;
  const show = inp.type === 'password';
  inp.type = show ? 'text' : 'password';
  btn.textContent = show ? '🙈' : '👁';
}
function checkStrength(pw) {
  const fill = document.getElementById('pw-strength-fill');
  const lbl  = document.getElementById('pw-strength-label');
  if (!pw) { fill.style.cssText='width:0'; lbl.textContent=''; return; }
  const strong = pw.length>=10 && /[A-Z]/.test(pw) && /[0-9]/.test(pw) && /[^A-Za-z0-9]/.test(pw);
  const medium = pw.length>=6  && (/[A-Z]/.test(pw) || /[0-9]/.test(pw));
  if (strong)      { fill.style.cssText='width:100%;background:#22D3A5'; lbl.textContent='Strong ✓'; lbl.style.color='#22D3A5'; }
  else if (medium) { fill.style.cssText='width:60%;background:#F5A623';  lbl.textContent='Medium';   lbl.style.color='#F5A623'; }
  else             { fill.style.cssText='width:30%;background:#FF5370';  lbl.textContent='Weak';     lbl.style.color='#FF5370'; }
}

/* ── Upload ── */
async function processUpload(file, pw, doEnc) {
  const ext  = file.name.split('.').pop().toLowerCase();
  const pList = document.getElementById('upload-progress-list');
  const id   = 'prog_' + Date.now();
  const item = document.createElement('div');
  item.className = 'up-item';
  item.innerHTML = `<span>${iconOf(file.name.split('.').pop()?'other':file.name.split('.').pop(), ext)}${doEnc?'🔐':''}</span>
    <span style="flex:0 0 auto;max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px">${x(file.name)}</span>
    <div class="pb-wrap"><div class="pb-fill" id="${id}" style="width:0"></div></div>`;
  pList.appendChild(item);
  const fill = document.getElementById(id);
  let pct = 0;
  const tk = setInterval(() => { pct = Math.min(pct + Math.random()*15, 85); fill.style.width = pct + '%'; }, 100);

  try {
    let uploadBlob = file;
    if (doEnc && pw) {
      uploadBlob = await encryptBlob(file, pw);
      // Also save to IndexedDB for local access
    }

    const fd = new FormData();
    fd.append('file', doEnc && pw ? new File([uploadBlob], file.name, { type: 'application/octet-stream' }) : file);
    fd.append('meta', JSON.stringify({ encrypted: doEnc && !!pw }));

    clearInterval(tk); fill.style.width = '100%';

    const data = await api('POST', '/api/files/upload', fd, true);

    if (data?.success) {
        const nf = {
          ...data.file,
          icon: iconOf(data.file.cat, data.file.ext),
          clr:  clrOf(data.file.cat),
          star: false,
          own:  true,
          enc:  doEnc && !!pw,
          fmt:  data.file.fmt || fmtBytes(data.file.size),
        };
        // Save encrypted blob locally for instant decrypt
        if (doEnc && pw) await idbPut(data.file.id, uploadBlob);

        files.push(nf);
        addActivity(doEnc ? '#F5A623' : '#4F8BFF', `"${nf.name}" uploaded${doEnc?' (encrypted)':''}`);
        toast(`"${nf.name}" uploaded${doEnc?' 🔐':''}`, 'success');

        // Refresh stats
        const s = await api('GET', '/api/stats');
        if (s?.success) stats = s.stats;
        render();
      } else {
        toast('Upload failed: ' + (data?.message || ''), 'error');
      }
  } catch (err) {
    clearInterval(tk);
    toast('Upload failed: ' + err.message, 'error');
  }
  setTimeout(() => item.remove(), 900);
}

/* ── Modal helpers ── */
function openModal(id)  { document.getElementById(id)?.classList.add('open'); }
function closeModal(id) { document.getElementById(id)?.classList.remove('open'); }
function closeAll()     { document.querySelectorAll('.backdrop').forEach(el=>el.classList.remove('open')); activeFile=null; shareId=null; }

/* ── User info in sidebar ── */
function populateUser() {
  const fn = USER?.firstName || '';
  const ln = USER?.lastName  || '';
  const em = USER?.email     || '';
  const un = USER?.username  || '';
  const initials = (fn[0]||'') + (ln[0]||fn[1]||'');

  document.querySelectorAll('.user-avatar').forEach(el => el.textContent = initials.toUpperCase() || '?');
  document.querySelectorAll('.user-name').forEach(el => el.textContent = fn + (ln?' '+ln:''));
  document.querySelectorAll('.user-email').forEach(el => el.textContent = em);
}

/* ── Event bindings ── */
function bind() {
  /* Nav */
  document.querySelectorAll('.nav-item[data-view]').forEach(el =>
    el.addEventListener('click', e => { e.preventDefault(); switchView(el.dataset.view); }));
  document.querySelectorAll('.view-all[data-view]').forEach(el =>
    el.addEventListener('click', e => { e.preventDefault(); switchView(el.dataset.view); }));

  /* Sidebar hamburger */
  document.getElementById('hamburger').addEventListener('click', () => {
    document.getElementById('sidebar').classList.toggle('open');
    document.getElementById('sidebar-overlay').classList.toggle('show');
  });
  document.getElementById('sidebar-overlay').addEventListener('click', () => {
    document.getElementById('sidebar').classList.remove('open');
    document.getElementById('sidebar-overlay').classList.remove('show');
  });

  /* User menu */
  function toggleUserMenu(e) {
    e?.stopPropagation();
    document.getElementById('user-dropdown').classList.toggle('open');
    document.getElementById('notif-dropdown').classList.remove('open');
  }
  document.getElementById('user-menu-btn').addEventListener('click', toggleUserMenu);
  document.getElementById('user-avatar-click')?.addEventListener('click', toggleUserMenu);
  document.getElementById('user-info-click')?.addEventListener('click', toggleUserMenu);
  document.addEventListener('click', () => document.getElementById('user-dropdown').classList.remove('open'));

  /* Notifications */
  let notifications = [];
  function renderNotifications() {
    const list = document.getElementById('notif-list');
    const empty = document.getElementById('notif-empty');
    if (!notifications.length) {
      if (empty) empty.style.display = 'block';
      list.innerHTML = '';
      list.appendChild(empty);
      return;
    }
    if (empty) empty.style.display = 'none';
    list.innerHTML = notifications.map((n, i) => `
      <div class="notif-item${i === 0 && !n.read ? ' unread' : ''}" onclick="markNotifRead(${i})">
        <div class="notif-icon">${n.icon}</div>
        <div class="notif-content">
          <div class="notif-title">${x(n.title)}</div>
          <div class="notif-desc">${x(n.desc)}</div>
          <div class="notif-time">${n.time}</div>
        </div>
      </div>
    `).join('');
  }
  function addNotification(icon, title, desc, read = false) {
    notifications.unshift({ icon, title, desc, time: 'Just now', read });
    if (notifications.length > 20) notifications = notifications.slice(0, 20);
    renderNotifications();
    updateNotifDot();
  }
  function updateNotifDot() {
    const dot = document.getElementById('notif-dot');
    const hasUnread = notifications.some(n => !n.read);
    if (dot) dot.style.display = hasUnread ? 'block' : 'none';
  }
  function markNotifRead(idx) {
    if (notifications[idx]) {
      notifications[idx].read = true;
      renderNotifications();
      updateNotifDot();
    }
  }
  function clearNotifications() {
    notifications = [];
    renderNotifications();
    updateNotifDot();
    toast('Notifications cleared', 'info');
  }
  document.getElementById('notif-btn').addEventListener('click', e => {
    e.stopPropagation();
    document.getElementById('notif-dropdown').classList.toggle('open');
    document.getElementById('user-dropdown').classList.remove('open');
  });
  document.getElementById('notif-clear-btn')?.addEventListener('click', e => {
    e.stopPropagation();
    clearNotifications();
  });
  document.getElementById('user-avatar-small')?.addEventListener('click', toggleUserMenu);
  document.addEventListener('click', () => document.getElementById('notif-dropdown').classList.remove('open'));

  /* Logout */
  document.getElementById('logout-btn')?.addEventListener('click', async e => {
    e.preventDefault();
    await api('POST', '/api/auth/logout');
    localStorage.clear();
    window.location.href = 'login.html';
  });

  /* Folder tree - filter files by category */
  document.querySelectorAll('.tree-item').forEach(el => {
    el.addEventListener('click', e => {
      e.preventDefault();
      const folder = el.dataset.folder;
      document.querySelectorAll('.tree-item').forEach(t => t.classList.remove('active'));
      el.classList.add('active');
      /* Switch to files view and apply filter */
      switchView('files');
      if (folder === 'root') {
        filter = 'all';
        document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
        document.querySelector('.chip[data-filter="all"]')?.classList.add('active');
      } else {
        filter = folder;
        document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
        document.querySelector(`.chip[data-filter="${folder}"]`)?.classList.add('active');
      }
      renderFiles();
    });
  });

  /* Search */
  const si = document.getElementById('search-input');
  si.addEventListener('input', e => { search = e.target.value; if (view === 'files') renderFiles(); });
  si.addEventListener('keydown', e => {
    if (e.key === 'Escape') { search = ''; si.value = ''; if (view === 'files') renderFiles(); }
    if (e.key === 'Enter')  switchView('files');
  });
  document.addEventListener('keydown', e => {
    if ((e.metaKey||e.ctrlKey) && e.key==='k') { e.preventDefault(); si.focus(); }
    if (e.key === 'Escape') closeAll();
  });

  /* Filter chips */
  document.getElementById('filter-chips').addEventListener('click', e => {
    const c = e.target.closest('.chip'); if (!c) return;
    document.querySelectorAll('.chip').forEach(el => el.classList.remove('active'));
    c.classList.add('active'); filter = c.dataset.filter; renderFiles();
  });
  document.getElementById('sort-select').addEventListener('change', e => { sort = e.target.value; renderFiles(); });
  document.getElementById('grid-btn').addEventListener('click', () => {
    grid = true; document.getElementById('grid-btn').classList.add('active'); document.getElementById('list-btn').classList.remove('active'); renderFiles();
  });
  document.getElementById('list-btn').addEventListener('click', () => {
    grid = false; document.getElementById('list-btn').classList.add('active'); document.getElementById('grid-btn').classList.remove('active'); renderFiles();
  });

  /* Upload */
  document.getElementById('upload-btn').addEventListener('click', () => document.getElementById('file-input').click());
  document.getElementById('file-input').addEventListener('change', e => { if (e.target.files.length) showEncModal(e.target.files); e.target.value=''; });
  const dz = document.getElementById('dash-drop-zone');
  dz.addEventListener('click', () => document.getElementById('dash-file-input').click());
  document.getElementById('dash-file-input').addEventListener('change', e => { if (e.target.files.length) showEncModal(e.target.files); e.target.value=''; });
  dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('drag-over'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('drag-over'));
  dz.addEventListener('drop', e => { e.preventDefault(); dz.classList.remove('drag-over'); if (e.dataTransfer.files.length) showEncModal(e.dataTransfer.files); });

  /* Preview modal */
  document.getElementById('preview-close').addEventListener('click', closePreview);
  document.getElementById('preview-backdrop').addEventListener('click', e => { if (e.target===e.currentTarget) closePreview(); });
  document.getElementById('btn-download').addEventListener('click', () => { if (activeFile) dlFile(activeFile.id); });
  document.getElementById('btn-share').addEventListener('click', () => { if (activeFile) { closePreview(); openShare(activeFile.id); } });
  document.getElementById('btn-delete').addEventListener('click', () => {
    if (!activeFile) return;
    if (!activeFile.own) { toast('Cannot delete shared files', 'error'); return; }
    delFile(activeFile.id); closePreview();
  });
  document.getElementById('rename-pencil').addEventListener('click', () => {
    document.getElementById('rename-row').style.display = 'flex';
    document.getElementById('rename-input').focus();
  });
  document.getElementById('rename-save').addEventListener('click', () => {
    if (!activeFile) return;
    const n = document.getElementById('rename-input').value;
    renameFile(activeFile.id, n);
    document.getElementById('mfname').textContent = n.trim() || activeFile.name;
    document.getElementById('rename-row').style.display = 'none';
  });
  document.getElementById('rename-input').addEventListener('keydown', e => { if (e.key==='Enter') document.getElementById('rename-save').click(); });

  /* Encrypt modal */
  document.getElementById('enc-close').addEventListener('click', () => { closeModal('enc-backdrop'); pendingFiles=[]; });
  document.getElementById('enc-backdrop').addEventListener('click', e => { if (e.target===e.currentTarget) { closeModal('enc-backdrop'); pendingFiles=[]; } });
  document.getElementById('enc-pw').addEventListener('input', e => checkStrength(e.target.value));
  document.getElementById('enc-toggle').addEventListener('change', e => {
    const on = e.target.checked;
    document.getElementById('enc-pw').disabled  = !on;
    document.getElementById('enc-pw2').disabled = !on;
    document.getElementById('enc-confirm').textContent = on ? '🔐 Upload Encrypted' : '⬆ Upload';
  });
  document.getElementById('enc-confirm').addEventListener('click', async () => {
    const doEnc = document.getElementById('enc-toggle').checked;
    const pw    = document.getElementById('enc-pw').value;
    const pw2   = document.getElementById('enc-pw2').value;
    if (doEnc) {
      if (!pw)        { toast('Enter a password', 'error'); return; }
      if (pw !== pw2) { toast('Passwords do not match', 'error'); return; }
      if (pw.length < 4) { toast('Password too short (min 4)', 'error'); return; }
    }
    closeModal('enc-backdrop');
    for (const f of pendingFiles) await processUpload(f, pw, doEnc);
    pendingFiles = [];
  });
  document.getElementById('enc-skip').addEventListener('click', async () => {
    closeModal('enc-backdrop');
    for (const f of pendingFiles) await processUpload(f, '', false);
    pendingFiles = [];
  });

  /* PW unlock modal */
  document.getElementById('pw-close').addEventListener('click', () => closeModal('pw-backdrop'));
  document.getElementById('pw-backdrop').addEventListener('click', e => { if (e.target===e.currentTarget) closeModal('pw-backdrop'); });

  /* New folder */
  document.getElementById('new-folder-btn').addEventListener('click', () => { document.getElementById('folder-input').value=''; openModal('folder-backdrop'); });
  document.getElementById('folder-close').addEventListener('click', () => closeModal('folder-backdrop'));
  document.getElementById('folder-backdrop').addEventListener('click', e => { if (e.target===e.currentTarget) closeModal('folder-backdrop'); });
  document.getElementById('folder-create').addEventListener('click', async () => {
    const name = document.getElementById('folder-input').value.trim();
    if (!name) { toast('Enter a folder name', 'error'); return; }
    const btn = document.getElementById('folder-create'); btn.textContent='Creating…'; btn.disabled=true;
    try {
      const res = await api('POST', '/api/folders', { name });
      btn.textContent='Create Folder'; btn.disabled=false;
      if (res?.success) {
        closeModal('folder-backdrop');
        toast(`Folder "${name}" created`,'success');
        addActivity('#A259FF', `Folder "${name}" created`);
      } else {
        toast(res?.message || 'Failed to create folder', 'error');
      }
    } catch (err) {
      btn.textContent='Create Folder'; btn.disabled=false;
      toast('Failed to create folder', 'error');
    }
  });

  /* Share modal */
  document.getElementById('share-close').addEventListener('click', () => closeModal('share-backdrop'));
  document.getElementById('share-backdrop').addEventListener('click', e => { if (e.target===e.currentTarget) closeModal('share-backdrop'); });
  document.getElementById('copy-link').addEventListener('click', () => {
    navigator.clipboard.writeText(document.getElementById('share-link').value)
      .then(() => toast('Link copied!', 'success')).catch(() => toast('Copy failed', 'error'));
  });
  document.getElementById('share-send').addEventListener('click', async () => {
    const shareWith = document.getElementById('share-user').value.trim();
    const perm      = document.getElementById('share-perm')?.value || 'read';
    if (!shareWith) { toast('Enter a username or email', 'error'); return; }
    if (!shareId) return;
    const res = await api('POST', `/api/files/${shareId}/share`, { shareWith, permission: perm });
    if (res?.success) {
      const f = files.find(f => f.id === shareId);
      if (f) { if (!f.shared) f.shared=[]; if (!f.shared.includes(shareWith)) f.shared.push(shareWith); }
      addActivity('#A259FF', `"${f?.name||'File'}" shared with ${shareWith}`);
      toast(`Shared with ${shareWith}`, 'success');
    } else toast(res?.message || 'Share failed', 'error');
    closeModal('share-backdrop');
  });
}

/* ── Init ── */
document.addEventListener('DOMContentLoaded', async () => {
  populateUser();
  bind();
  await loadAll();
  switchView('dashboard');
});