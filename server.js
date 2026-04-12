/**
 * FileVault — Unified Backend Server
 * Database: SQLite
 * Handles: Auth (register/login/OTP), File ops (upload/download/delete/share)
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
const Database   = require('better-sqlite3');

const app  = express();
const PORT = 5000;

// ─── Paths ───────────────────────────────────────────────────
const DATA_DIR    = path.join(__dirname, 'data');
const STORAGE_DIR = path.join(__dirname, 'storage', 'files');
const TEMP_DIR    = path.join(__dirname, 'storage', 'temp');

// Ensure dirs exist
[DATA_DIR, STORAGE_DIR, TEMP_DIR].forEach(d => fs.mkdirSync(d, { recursive: true }));

// ─── Database Setup ─────────────────────────────────────────
const db = new Database(path.join(DATA_DIR, 'filevault.db'));

// Initialize tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    firstName TEXT NOT NULL,
    lastName TEXT NOT NULL,
    passwordHash TEXT NOT NULL,
    verified INTEGER DEFAULT 0,
    storageUsed INTEGER DEFAULT 0,
    createdAt TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    ext TEXT,
    size INTEGER,
    fmt TEXT,
    cat TEXT,
    owner TEXT NOT NULL,
    ownerEmail TEXT NOT NULL,
    storedAs TEXT NOT NULL,
    encrypted INTEGER DEFAULT 0,
    uploadedAt TEXT DEFAULT CURRENT_TIMESTAMP,
    shared TEXT DEFAULT '[]'
  );

  CREATE TABLE IF NOT EXISTS permissions (
    fileId TEXT NOT NULL,
    sharedWith TEXT NOT NULL,
    permission TEXT DEFAULT 'read',
    PRIMARY KEY (fileId, sharedWith)
  );

  CREATE INDEX IF NOT EXISTS idx_files_owner ON files(ownerEmail);
  CREATE INDEX IF NOT EXISTS idx_perms_file ON permissions(fileId);
`);

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

  const stmt = db.prepare('SELECT id FROM users WHERE LOWER(username) = LOWER(?)');
  const user = stmt.get(username);
  res.json({ available: !user });
});

// Register → send OTP
app.post('/api/auth/register', async (req, res) => {
  const { firstName, lastName, username, email, password } = req.body;
  if (!firstName || !lastName || !username || !email || !password)
    return res.status(400).json({ success: false, message: 'All fields required' });

  // Check if email exists
  const checkEmail = db.prepare('SELECT id FROM users WHERE LOWER(email) = LOWER(?)');
  if (checkEmail.get(email))
    return res.status(409).json({ success: false, message: 'Email already registered' });

  // Check if username exists
  const checkUser = db.prepare('SELECT id FROM users WHERE LOWER(username) = LOWER(?)');
  if (checkUser.get(username))
    return res.status(409).json({ success: false, message: 'Username already taken' });

  // Hash password
  const hash = await bcrypt.hash(password, 12);

  // Insert user
  const insert = db.prepare(`
    INSERT INTO users (firstName, lastName, username, email, passwordHash, verified, storageUsed)
    VALUES (?, ?, ?, ?, ?, 0, 0)
  `);
  insert.run(firstName, lastName, username, email, hash);

  // Generate + store OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otpStore[email] = { otp, expires: Date.now() + 5 * 60 * 1000 };

  try {
    await sendOTP(email, otp);
    console.log(`📩 OTP sent to ${email}: ${otp}`);
    const masked = email[0] + '***@' + email.split('@')[1];
    res.json({ success: true, maskedEmail: masked, message: 'OTP sent' });
  } catch (err) {
    console.error('Email error:', err.message);
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
  const update = db.prepare('UPDATE users SET verified = 1 WHERE LOWER(email) = LOWER(?)');
  update.run(email);

  // Get user info
  const getUser = db.prepare('SELECT * FROM users WHERE LOWER(email) = LOWER(?)');
  const user = getUser.get(email);

  if (!user) {
    return res.json({ success: false, message: 'User not found' });
  }

  // Create session
  const token = genToken();
  sessions[token] = {
    username: user.username,
    email: user.email,
    firstName: user.firstName,
    expires: Date.now() + 7 * 24 * 60 * 60 * 1000
  };

  res.json({
    success: true,
    token,
    user: {
      firstName: user.firstName,
      username: user.username,
      email: user.email
    }
  });
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

  // Find user by username or email
  const getUser = db.prepare(`
    SELECT * FROM users
    WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)
  `);
  const user = getUser.get(username, username);

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

  const getUser = db.prepare('SELECT * FROM users WHERE LOWER(email) = LOWER(?)');
  const user = getUser.get(email);

  if (!user) {
    return res.json({ success: false, message: 'User not found' });
  }

  const token = genToken();
  sessions[token] = {
    username: user.username,
    email: user.email,
    firstName: user.firstName,
    expires: Date.now() + 7 * 24 * 60 * 60 * 1000
  };

  res.json({
    success: true,
    token,
    user: {
      firstName: user.firstName,
      username: user.username,
      email: user.email
    }
  });
});

// Get current user info
app.get('/api/auth/me', authMiddleware, (req, res) => {
  const getUser = db.prepare('SELECT * FROM users WHERE LOWER(email) = LOWER(?)');
  const user = getUser.get(req.user.email);

  if (!user) return res.status(404).json({ success: false });
  res.json({
    success: true,
    user: {
      firstName: user.firstName,
      lastName: user.lastName,
      username: user.username,
      email: user.email,
      storageUsed: user.storageUsed || 0
    }
  });
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
    shared:      '[]',
  };

  // Insert file record
  const insertFile = db.prepare(`
    INSERT INTO files (id, name, ext, size, fmt, cat, owner, ownerEmail, storedAs, encrypted, uploadedAt, shared)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  insertFile.run(
    fileRecord.id,
    fileRecord.name,
    fileRecord.ext,
    fileRecord.size,
    fileRecord.fmt,
    fileRecord.cat,
    fileRecord.owner,
    fileRecord.ownerEmail,
    fileRecord.storedAs,
    fileRecord.encrypted ? 1 : 0,
    fileRecord.uploadedAt,
    fileRecord.shared
  );

  // Update user storage
  const updateStorage = db.prepare('UPDATE users SET storageUsed = storageUsed + ? WHERE LOWER(email) = LOWER(?)');
  updateStorage.run(req.file.size, req.user.email);

  res.json({ success: true, file: fileRecord });
});

// List files for current user
app.get('/api/files', authMiddleware, (req, res) => {
  // Files owned by user
  const getOwned = db.prepare('SELECT * FROM files WHERE LOWER(ownerEmail) = LOWER(?)');
  const owned = getOwned.all(req.user.email);

  // Files shared with user
  const getShared = db.prepare(`
    SELECT f.*, p.permission
    FROM files f
    JOIN permissions p ON f.id = p.fileId
    WHERE LOWER(p.sharedWith) = LOWER(?) AND LOWER(f.ownerEmail) != LOWER(?)
  `);
  const sharedWithMe = getShared.all(req.user.email, req.user.email);

  // Add sharedWithMe flag
  const shared = sharedWithMe.map(f => ({ ...f, sharedWithMe: true, permission: f.permission }));

  res.json({ success: true, files: [...owned, ...shared] });
});

// Download / stream file
app.get('/api/files/:id/download', authMiddleware, (req, res) => {
  const getFile = db.prepare('SELECT * FROM files WHERE id = ?');
  const file = getFile.get(req.params.id);

  if (!file) return res.status(404).json({ success: false, message: 'File not found' });

  // Permission check
  const isOwner  = file.ownerEmail.toLowerCase() === req.user.email.toLowerCase();

  if (!isOwner) {
    const getPerm = db.prepare('SELECT permission FROM permissions WHERE fileId = ? AND (LOWER(sharedWith) = LOWER(?) OR LOWER(sharedWith) = LOWER(?))');
    const perm = getPerm.get(req.params.id, req.user.username, req.user.email);
    if (!perm) return res.status(403).json({ success: false, message: 'No permission' });
  }

  const filePath = path.join(STORAGE_DIR, file.storedAs);
  if (!fs.existsSync(filePath)) return res.status(404).json({ success: false, message: 'File data missing' });

  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(file.name)}"`);
  res.setHeader('Content-Type', 'application/octet-stream');
  fs.createReadStream(filePath).pipe(res);
});

// Preview file (inline)
app.get('/api/files/:id/preview', authMiddleware, (req, res) => {
  const getFile = db.prepare('SELECT * FROM files WHERE id = ?');
  const file = getFile.get(req.params.id);

  if (!file) return res.status(404).json({ success: false });

  const isOwner = file.ownerEmail.toLowerCase() === req.user.email.toLowerCase();

  if (!isOwner) {
    const getPerm = db.prepare('SELECT permission FROM permissions WHERE fileId = ? AND (LOWER(sharedWith) = LOWER(?) OR LOWER(sharedWith) = LOWER(?))');
    const perm = getPerm.get(req.params.id, req.user.username, req.user.email);
    if (!perm) return res.status(403).json({ success: false });
  }

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
  const getFile = db.prepare('SELECT * FROM files WHERE id = ?');
  const file = getFile.get(req.params.id);

  if (!file) return res.status(404).json({ success: false, message: 'Not found' });
  if (file.ownerEmail.toLowerCase() !== req.user.email.toLowerCase())
    return res.status(403).json({ success: false, message: 'Not your file' });

  // Delete from disk
  const filePath = path.join(STORAGE_DIR, file.storedAs);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

  // Update user storage
  const updateStorage = db.prepare('UPDATE users SET storageUsed = MAX(0, storageUsed - ?) WHERE LOWER(email) = LOWER(?)');
  updateStorage.run(file.size, req.user.email);

  // Delete from DB
  const deleteFile = db.prepare('DELETE FROM files WHERE id = ?');
  deleteFile.run(req.params.id);

  // Delete permissions
  const deletePerms = db.prepare('DELETE FROM permissions WHERE fileId = ?');
  deletePerms.run(req.params.id);

  res.json({ success: true });
});

// Rename file
app.patch('/api/files/:id/rename', authMiddleware, (req, res) => {
  const { name } = req.body;
  const getFile = db.prepare('SELECT * FROM files WHERE id = ?');
  const file = getFile.get(req.params.id);

  if (!file) return res.status(404).json({ success: false });
  if (file.ownerEmail.toLowerCase() !== req.user.email.toLowerCase())
    return res.status(403).json({ success: false });
  if (!name?.trim()) return res.status(400).json({ success: false, message: 'Name required' });

  const update = db.prepare('UPDATE files SET name = ? WHERE id = ?');
  update.run(name.trim(), req.params.id);

  const updatedFile = getFile.get(req.params.id);
  res.json({ success: true, file: updatedFile });
});

// Share file
app.post('/api/files/:id/share', authMiddleware, (req, res) => {
  const { shareWith, permission } = req.body;
  const getFile = db.prepare('SELECT * FROM files WHERE id = ?');
  const file = getFile.get(req.params.id);

  if (!file) return res.status(404).json({ success: false });
  if (file.ownerEmail.toLowerCase() !== req.user.email.toLowerCase())
    return res.status(403).json({ success: false, message: 'Not your file' });

  // Check if user exists
  const getTargetUser = db.prepare('SELECT username FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)');
  const targetUser = getTargetUser.get(shareWith, shareWith);

  if (!targetUser)
    return res.status(404).json({ success: false, message: 'User not found' });

  // Insert or update permission
  const upsertPerm = db.prepare(`
    INSERT INTO permissions (fileId, sharedWith, permission) VALUES (?, ?, ?)
    ON CONFLICT(fileId, sharedWith) DO UPDATE SET permission = ?
  `);
  upsertPerm.run(req.params.id, shareWith, permission || 'read', permission || 'read');

  res.json({ success: true, message: `Shared with ${shareWith}` });
});

// File metadata
app.get('/api/files/:id/meta', authMiddleware, (req, res) => {
  const getFile = db.prepare('SELECT * FROM files WHERE id = ?');
  const file = getFile.get(req.params.id);

  if (!file) return res.status(404).json({ success: false });

  const isOwner = file.ownerEmail.toLowerCase() === req.user.email.toLowerCase();

  if (!isOwner) {
    const getPerm = db.prepare('SELECT permission FROM permissions WHERE fileId = ? AND (LOWER(sharedWith) = LOWER(?) OR LOWER(sharedWith) = LOWER(?))');
    const perm = getPerm.get(req.params.id, req.user.username, req.user.email);
    if (!perm) return res.status(403).json({ success: false });
  }

  res.json({ success: true, file });
});

// Storage stats
app.get('/api/stats', authMiddleware, (req, res) => {
  const getOwned = db.prepare('SELECT * FROM files WHERE LOWER(ownerEmail) = LOWER(?)');
  const owned = getOwned.all(req.user.email);

  const getShared = db.prepare(`
    SELECT f.* FROM files f
    JOIN permissions p ON f.id = p.fileId
    WHERE LOWER(p.sharedWith) = LOWER(?) AND LOWER(f.ownerEmail) != LOWER(?)
  `);
  const shared = getShared.all(req.user.email, req.user.email);

  const getUser = db.prepare('SELECT storageUsed FROM users WHERE LOWER(email) = LOWER(?)');
  const user = getUser.get(req.user.email);

  const totalSize = owned.reduce((s, f) => s + (f.size || 0), 0);

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
  ║  Database: SQLite                 ║
  ╚══════════════════════════════════╝
  `);
});