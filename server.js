/**
 * FileVault — Unified Backend Server
 * Handles: Auth (register/login/OTP), File ops (upload/download/delete/share)
 * Storage: users.json, permissions.json, files saved to storage/files/
 */

'use strict';

require('dotenv').config();

const express    = require('express');
const cors       = require('cors');
const bcrypt     = require('bcryptjs');
const multer     = require('multer');
const nodemailer = require('nodemailer');
const path       = require('path');
const fs         = require('fs');
const crypto     = require('crypto');

const app  = express();
const PORT = 5000;

// ─── Paths ───────────────────────────────────────────────────
const DATA_DIR    = path.join(__dirname, 'data');
const STORAGE_DIR = path.join(__dirname, 'storage', 'files');
const TEMP_DIR    = path.join(__dirname, 'storage', 'temp');
const USERS_FILE  = path.join(DATA_DIR, 'users.json');
const PERMS_FILE  = path.join(DATA_DIR, 'permissions.json');
const FILES_FILE  = path.join(DATA_DIR, 'files.json');

// Ensure dirs exist
[DATA_DIR, STORAGE_DIR, TEMP_DIR].forEach(d => fs.mkdirSync(d, { recursive: true }));
[USERS_FILE, PERMS_FILE, FILES_FILE].forEach(f => {
  if (!fs.existsSync(f)) fs.writeFileSync(f, '{}');
});

// ─── Middleware ───────────────────────────────────────────────
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Root redirect
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontened', 'login.html'));
});

// Static files — frontened folder served at root, storage at /storage
app.use(express.static(path.join(__dirname, 'frontened')));
app.use('/css', express.static(path.join(__dirname, 'css')));
app.use('/js', express.static(path.join(__dirname, 'js')));
app.use('/storage', express.static(STORAGE_DIR));
app.use('/frontend', express.static(path.join(__dirname, 'frontened')));

// ─── DB helpers ───────────────────────────────────────────────
function readJSON(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return {}; }
}
function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// ─── Session store (in-memory, keyed by token) ───────────────
const sessions = {};   // token → { username, email, expires }
const otpStore = {};   // email  → { otp, expires }

function genToken() { return crypto.randomBytes(32).toString('hex'); }
function authMiddleware(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token || !sessions[token] || sessions[token].expires < Date.now()) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
  req.user = sessions[token];
  next();
}

// ─── Multer: file upload ──────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, STORAGE_DIR),
  filename: (req, file, cb) => {
    const id  = crypto.randomBytes(12).toString('hex');
    const ext = path.extname(file.originalname);
    cb(null, `${id}${ext}`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 500 * 1024 * 1024 }, // 500 MB
  fileFilter: (req, file, cb) => {
    // Block dangerous types
    const blocked = ['.exe','.bat','.cmd','.sh','.ps1','.vbs','.js','.jar','.msi','.dll'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (blocked.includes(ext)) return cb(new Error('File type not allowed'), false);
    cb(null, true);
  },
});

// ─── Email setup ──────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});
async function sendOTP(email, otp) {
  await transporter.sendMail({
    from: `"FileVault" <${process.env.EMAIL_USER || 'filevault.secure@gmail.com'}>`,
    to: email,
    subject: '🔐 Your FileVault OTP Code',
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:auto;background:#07090d;color:#f0f4ff;padding:36px;border-radius:16px">
        <h2 style="color:#4f8bff;margin-bottom:8px">FileVault Security Code</h2>
        <p style="color:#6b7899;margin-bottom:24px">Use the code below to verify your identity.</p>
        <div style="background:#161b24;border:1px solid rgba(255,255,255,.08);border-radius:12px;padding:24px;text-align:center">
          <span style="font-size:42px;font-weight:800;letter-spacing:12px;color:#4f8bff">${otp}</span>
        </div>
        <p style="color:#6b7899;font-size:13px;margin-top:20px">Valid for <strong style="color:#f0f4ff">5 minutes</strong>. Never share this code with anyone.</p>
        <p style="color:#3d4a65;font-size:11px;margin-top:24px">If you didn't request this, ignore this email.</p>
      </div>`,
  });
}

// ─── Helpers ─────────────────────────────────────────────────
function fmtBytes(b) {
  if (b < 1024)       return b + ' B';
  if (b < 1048576)    return (b / 1024).toFixed(0) + ' KB';
  if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
  return (b / 1073741824).toFixed(2) + ' GB';
}
function catOf(name) {
  const e = path.extname(name).slice(1).toLowerCase();
  if (['jpg','jpeg','png','gif','webp','svg','bmp'].includes(e)) return 'image';
  if (['mp4','mov','avi','mkv','webm'].includes(e))             return 'video';
  if (['zip','rar','7z','tar','gz'].includes(e))                return 'archive';
  if (['pdf','doc','docx','xls','xlsx','ppt','pptx','txt','csv','md'].includes(e)) return 'document';
  return 'other';
}

// ─────────────────────────────────────────────────────────────
//  AUTH ROUTES
// ─────────────────────────────────────────────────────────────

// Check username availability
app.get('/api/auth/check-username', (req, res) => {
  const { username } = req.query;
  if (!username) return res.json({ available: false });
  const users = readJSON(USERS_FILE);
  const taken = Object.values(users).some(u => u.username?.toLowerCase() === username.toLowerCase());
  res.json({ available: !taken });
});

// Register → send OTP
app.post('/api/auth/register', async (req, res) => {
  const { firstName, lastName, username, email, password } = req.body;
  if (!firstName || !lastName || !username || !email || !password)
    return res.status(400).json({ success: false, message: 'All fields required' });

  const users = readJSON(USERS_FILE);

  if (users[email])
    return res.status(409).json({ success: false, message: 'Email already registered' });
  if (Object.values(users).some(u => u.username?.toLowerCase() === username.toLowerCase()))
    return res.status(409).json({ success: false, message: 'Username already taken' });

  // Hash password
  const hash = await bcrypt.hash(password, 12);

  // Save pending user (not verified yet)
  users[email] = {
    firstName, lastName, username, email,
    passwordHash: hash,
    verified: false,
    createdAt: new Date().toISOString(),
    storageUsed: 0,
  };
  writeJSON(USERS_FILE, users);

  // Generate + store OTP (stored first so dev-mode works even if email fails)
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otpStore[email] = { otp, expires: Date.now() + 5 * 60 * 1000 };

  try {
    await sendOTP(email, otp);
    console.log(`📩 OTP sent to ${email}: ${otp}`);
    const masked = email[0] + '***@' + email.split('@')[1];
    res.json({ success: true, maskedEmail: masked, message: 'OTP sent' });
  } catch (err) {
    console.error('Email error:', err.message);
    // Still succeed so dev can test without email
    console.log(`🔧 DEV MODE OTP for ${email}: ${otp}`);
    res.json({ success: true, maskedEmail: email[0] + '***@' + email.split('@')[1], message: 'OTP sent (check console in dev)' });
  }
});

// Verify OTP → activate account
app.post('/api/auth/verify-otp', (req, res) => {
  const { email, code } = req.body;
  const record = otpStore[email];

  if (!record)
    return res.json({ success: false, message: 'No OTP found. Please register again.' });
  if (Date.now() > record.expires) {
    delete otpStore[email];
    return res.json({ success: false, message: 'OTP expired. Request a new one.' });
  }
  if (record.otp !== String(code)) {
    return res.json({ success: false, message: 'Incorrect code. Try again.' });
  }

  delete otpStore[email];

  // Mark user as verified
  const users = readJSON(USERS_FILE);
  if (users[email]) { users[email].verified = true; writeJSON(USERS_FILE, users); }

  // Create session
  const token = genToken();
  const user  = users[email];
  sessions[token] = { username: user.username, email, firstName: user.firstName, expires: Date.now() + 7 * 24 * 60 * 60 * 1000 };

  res.json({ success: true, token, user: { firstName: user.firstName, username: user.username, email } });
});

// Resend OTP
app.post('/api/auth/resend-otp', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ success: false });

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otpStore[email] = { otp, expires: Date.now() + 5 * 60 * 1000 };

  try {
    await sendOTP(email, otp);
    console.log(`🔁 OTP resent to ${email}: ${otp}`);
    res.json({ success: true });
  } catch (err) {
    console.log(`🔧 DEV OTP: ${otp}`);
    res.json({ success: true });
  }
});

// Login → send OTP (step 1)
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ success: false, message: 'Username and password required' });

  const users = readJSON(USERS_FILE);
  const user  = Object.values(users).find(u => u.username?.toLowerCase() === username.toLowerCase() || u.email?.toLowerCase() === username.toLowerCase());

  if (!user)
    return res.status(401).json({ success: false, message: 'User not found' });
  if (!user.verified)
    return res.status(401).json({ success: false, message: 'Account not verified. Please complete OTP.' });

  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match)
    return res.status(401).json({ success: false, message: 'Incorrect password' });

  // Send OTP for 2FA
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otpStore[user.email] = { otp, expires: Date.now() + 5 * 60 * 1000, isLogin: true };

  try {
    await sendOTP(user.email, otp);
    console.log(`🔐 Login OTP for ${user.email}: ${otp}`);
  } catch (err) {
    console.log(`🔧 DEV Login OTP: ${otp}`);
  }

  const masked = user.email[0] + '***@' + user.email.split('@')[1];
  res.json({ success: true, maskedEmail: masked, email: user.email, isLogin: true, message: 'OTP sent for 2FA' });
});

// Login OTP verify (step 2)
app.post('/api/auth/login-verify', (req, res) => {
  const { email, code } = req.body;
  const record = otpStore[email];

  if (!record || !record.isLogin)
    return res.json({ success: false, message: 'No login OTP found' });
  if (Date.now() > record.expires) {
    delete otpStore[email];
    return res.json({ success: false, message: 'OTP expired' });
  }
  if (record.otp !== String(code))
    return res.json({ success: false, message: 'Incorrect code' });

  delete otpStore[email];

  const users = readJSON(USERS_FILE);
  const user  = users[email];
  const token = genToken();
  sessions[token] = { username: user.username, email, firstName: user.firstName, expires: Date.now() + 7 * 24 * 60 * 60 * 1000 };

  res.json({ success: true, token, user: { firstName: user.firstName, username: user.username, email } });
});

// Get current user info
app.get('/api/auth/me', authMiddleware, (req, res) => {
  const users = readJSON(USERS_FILE);
  const user  = users[req.user.email];
  if (!user) return res.status(404).json({ success: false });
  res.json({ success: true, user: { firstName: user.firstName, lastName: user.lastName, username: user.username, email: user.email, storageUsed: user.storageUsed || 0 } });
});

// Logout
app.post('/api/auth/logout', authMiddleware, (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  delete sessions[token];
  res.json({ success: true });
});

// ─────────────────────────────────────────────────────────────
//  FILE ROUTES
// ─────────────────────────────────────────────────────────────

// Upload file
app.post('/api/files/upload', authMiddleware, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ success: false, message: 'No file uploaded' });

  const meta    = req.body.meta ? JSON.parse(req.body.meta) : {};
  const allFiles = readJSON(FILES_FILE);
  const users   = readJSON(USERS_FILE);

  const fileId  = crypto.randomBytes(12).toString('hex');
  const ext     = path.extname(req.file.originalname).slice(1).toLowerCase();
  const cat     = catOf(req.file.originalname);

  const fileRecord = {
    id:          fileId,
    name:        req.file.originalname,
    ext,
    size:        req.file.size,
    fmt:         fmtBytes(req.file.size),
    cat,
    owner:       req.user.username,
    ownerEmail:  req.user.email,
    storedAs:    req.file.filename,
    encrypted:   meta.encrypted || false,
    uploadedAt:  new Date().toISOString(),
    shared:      [],
  };

  allFiles[fileId] = fileRecord;
  writeJSON(FILES_FILE, allFiles);

  // Update user storage
  if (users[req.user.email]) {
    users[req.user.email].storageUsed = (users[req.user.email].storageUsed || 0) + req.file.size;
    writeJSON(USERS_FILE, users);
  }

  res.json({ success: true, file: fileRecord });
});

// List files for current user
app.get('/api/files', authMiddleware, (req, res) => {
  const allFiles = readJSON(FILES_FILE);
  const perms    = readJSON(PERMS_FILE);

  // Files owned by user
  const owned = Object.values(allFiles).filter(f => f.ownerEmail === req.user.email);

  // Files shared with user
  const sharedWithMe = Object.values(allFiles).filter(f => {
    if (f.ownerEmail === req.user.email) return false;
    const p = perms[f.id];
    return p && (p[req.user.username] || p[req.user.email]);
  }).map(f => ({ ...f, sharedWithMe: true, permission: (perms[f.id]?.[req.user.username] || perms[f.id]?.[req.user.email] || 'read') }));

  res.json({ success: true, files: [...owned, ...sharedWithMe] });
});

// Download / stream file
app.get('/api/files/:id/download', authMiddleware, (req, res) => {
  const allFiles = readJSON(FILES_FILE);
  const perms    = readJSON(PERMS_FILE);
  const file     = allFiles[req.params.id];

  if (!file) return res.status(404).json({ success: false, message: 'File not found' });

  // Permission check
  const isOwner  = file.ownerEmail === req.user.email;
  const perm     = perms[file.id]?.[req.user.username] || perms[file.id]?.[req.user.email];
  if (!isOwner && !perm) return res.status(403).json({ success: false, message: 'No permission' });

  const filePath = path.join(STORAGE_DIR, file.storedAs);
  if (!fs.existsSync(filePath)) return res.status(404).json({ success: false, message: 'File data missing' });

  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(file.name)}"`);
  res.setHeader('Content-Type', 'application/octet-stream');
  fs.createReadStream(filePath).pipe(res);
});

// Preview file (inline)
app.get('/api/files/:id/preview', authMiddleware, (req, res) => {
  const allFiles = readJSON(FILES_FILE);
  const perms    = readJSON(PERMS_FILE);
  const file     = allFiles[req.params.id];

  if (!file) return res.status(404).json({ success: false });

  const isOwner = file.ownerEmail === req.user.email;
  const perm    = perms[file.id]?.[req.user.username] || perms[file.id]?.[req.user.email];
  if (!isOwner && !perm) return res.status(403).json({ success: false });

  const filePath = path.join(STORAGE_DIR, file.storedAs);
  if (!fs.existsSync(filePath)) return res.status(404).json({ success: false });

  const MIME = {
    jpg:'image/jpeg',jpeg:'image/jpeg',png:'image/png',gif:'image/gif',
    webp:'image/webp',svg:'image/svg+xml',pdf:'application/pdf',
    mp4:'video/mp4',webm:'video/webm',txt:'text/plain',
    csv:'text/csv',json:'application/json',md:'text/plain',
  };
  const mime = MIME[file.ext] || 'application/octet-stream';
  res.setHeader('Content-Type', mime);
  res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(file.name)}"`);
  fs.createReadStream(filePath).pipe(res);
});

// Delete file
app.delete('/api/files/:id', authMiddleware, (req, res) => {
  const allFiles = readJSON(FILES_FILE);
  const file     = allFiles[req.params.id];

  if (!file) return res.status(404).json({ success: false, message: 'Not found' });
  if (file.ownerEmail !== req.user.email)
    return res.status(403).json({ success: false, message: 'Not your file' });

  // Delete from disk
  const filePath = path.join(STORAGE_DIR, file.storedAs);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

  // Update user storage
  const users = readJSON(USERS_FILE);
  if (users[req.user.email]) {
    users[req.user.email].storageUsed = Math.max(0, (users[req.user.email].storageUsed || 0) - file.size);
    writeJSON(USERS_FILE, users);
  }

  delete allFiles[req.params.id];
  writeJSON(FILES_FILE, allFiles);

  res.json({ success: true });
});

// Rename file
app.patch('/api/files/:id/rename', authMiddleware, (req, res) => {
  const { name } = req.body;
  const allFiles  = readJSON(FILES_FILE);
  const file      = allFiles[req.params.id];

  if (!file) return res.status(404).json({ success: false });
  if (file.ownerEmail !== req.user.email) return res.status(403).json({ success: false });
  if (!name?.trim()) return res.status(400).json({ success: false, message: 'Name required' });

  file.name = name.trim();
  writeJSON(FILES_FILE, allFiles);
  res.json({ success: true, file });
});

// Share file
app.post('/api/files/:id/share', authMiddleware, (req, res) => {
  const { shareWith, permission } = req.body; // shareWith = username or email, permission = 'read' | 'write'
  const allFiles = readJSON(FILES_FILE);
  const file     = allFiles[req.params.id];
  const perms    = readJSON(PERMS_FILE);

  if (!file) return res.status(404).json({ success: false });
  if (file.ownerEmail !== req.user.email) return res.status(403).json({ success: false, message: 'Not your file' });

  if (!perms[req.params.id]) perms[req.params.id] = {};
  perms[req.params.id][shareWith] = permission || 'read';

  if (!file.shared) file.shared = [];
  if (!file.shared.includes(shareWith)) file.shared.push(shareWith);

  writeJSON(PERMS_FILE, perms);
  writeJSON(FILES_FILE, allFiles);

  res.json({ success: true, message: `Shared with ${shareWith}` });
});

// File metadata
app.get('/api/files/:id/meta', authMiddleware, (req, res) => {
  const allFiles = readJSON(FILES_FILE);
  const file     = allFiles[req.params.id];
  if (!file) return res.status(404).json({ success: false });
  const isOwner  = file.ownerEmail === req.user.email;
  const perms    = readJSON(PERMS_FILE);
  const perm     = perms[file.id]?.[req.user.username] || perms[file.id]?.[req.user.email];
  if (!isOwner && !perm) return res.status(403).json({ success: false });
  res.json({ success: true, file });
});

// Storage stats
app.get('/api/stats', authMiddleware, (req, res) => {
  const allFiles = readJSON(FILES_FILE);
  const users    = readJSON(USERS_FILE);
  const owned    = Object.values(allFiles).filter(f => f.ownerEmail === req.user.email);
  const perms    = readJSON(PERMS_FILE);
  const shared   = Object.values(allFiles).filter(f => {
    const p = perms[f.id];
    return p && (p[req.user.username] || p[req.user.email]);
  });

  const totalSize = owned.reduce((s, f) => s + (f.size || 0), 0);
  const u = users[req.user.email];

  // Category breakdown for donut chart
  const cats = { document: 0, image: 0, video: 0, other: 0 };
  owned.forEach(f => {
    if (cats[f.cat] !== undefined) cats[f.cat] += f.size || 0;
    else cats.other += f.size || 0;
  });

  res.json({
    success: true,
    stats: {
      total:     owned.length,
      shared:    shared.length,
      encrypted: owned.filter(f => f.encrypted).length,
      storageUsed: totalSize,
      storageUsedFmt: fmtBytes(totalSize),
      storageLimit: 100 * 1024 * 1024 * 1024, // 100 GB
      storagePct: ((totalSize / (100 * 1024 * 1024 * 1024)) * 100).toFixed(2),
      categories: cats,
    }
  });
});

// ─── Error handler ────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('Server error:', err.message);
  if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ success: false, message: 'File too large (max 500 MB)' });
  if (err.message === 'File type not allowed') return res.status(415).json({ success: false, message: err.message });
  res.status(500).json({ success: false, message: 'Internal server error' });
});

// ─── Start ────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`
  ╔══════════════════════════════════╗
  ║  FileVault Server running        ║
  ║  http://localhost:${PORT}           ║
  ╚══════════════════════════════════╝
  `);
});