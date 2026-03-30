const express = require('express');
const cors = require('cors');

const app = express();

app.use(cors());
app.use(express.json());

// 🔥 TEMP STORAGE
let userOTP = {};

// ✅ REGISTER (GENERATE OTP)
app.post('/api/auth/register', (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ success: false, message: 'Email required' });
  }

  const otp = Math.floor(100000 + Math.random() * 900000);

  console.log("📩 OTP for", email, ":", otp);

  userOTP[email] = otp;

  res.json({ success: true });
});

// ✅ VERIFY OTP
app.post('/api/auth/verify-otp', (req, res) => {
  const { email, code } = req.body;

  if (userOTP[email] && userOTP[email] == code) {
    delete userOTP[email];
    return res.json({ success: true });
  }

  res.json({ success: false, message: 'Invalid OTP' });
});

// ✅ RESEND OTP
app.post('/api/auth/resend-otp', (req, res) => {
  const { email } = req.body;

  const otp = Math.floor(100000 + Math.random() * 900000);
  userOTP[email] = otp;

  console.log("🔁 Resent OTP for", email, ":", otp);

  res.json({ success: true });
});

// ✅ USERNAME CHECK
app.get('/api/auth/check-username', (req, res) => {
  res.json({ available: true });
});

// ✅ LOGIN (TEMP)
app.post('/api/auth/login', (req, res) => {
  const { username, email, password } = req.body;

  console.log("🔐 Login:", username || email);

  if (password && password.length >= 8) {
    return res.json({ success: true });
  }

  res.json({ success: false, message: 'Invalid credentials' });
});

// ✅ ROOT
app.get('/', (req, res) => {
  res.send('Server is running 🚀');
});

// 🚀 START SERVER
app.listen(5000, () => {
  console.log('Server running on http://localhost:5000');
});