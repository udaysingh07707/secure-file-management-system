const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');

const app = express();

app.use(cors());
app.use(express.json());

// 🔥 TEMP STORAGE (OTP + expiry)
let userOTP = {};

// ✅ EMAIL SETUP (SENDER = YOUR EMAIL)
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "filevault.secure@gmail.com",      // 👈 YOUR GMAIL (sender)
    pass: "cgrwrnxwkeiswzhf"          // 👈 APP PASSWORD (NOT normal password)
  }
});

// ✅ FUNCTION TO SEND OTP
async function sendOTP(email, otp) {
  const mailOptions = {
    from: "filevault.secure@gmail.com",   // sender
    to: email,                      // 👈 RECEIVER (user input)
    subject: "OTP Verification - FileVault",
    html: `
      <h2>Your OTP Code</h2>
      <p>Your OTP is:</p>
      <h1>${otp}</h1>
      <p>This OTP is valid for 5 minutes.</p>
    `
  };

  await transporter.sendMail(mailOptions);
}

// ✅ REGISTER → GENERATE OTP + SEND EMAIL
app.post('/api/auth/register', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ success: false, message: 'Email required' });
  }

  const otp = Math.floor(100000 + Math.random() * 900000);

  // store OTP with expiry
  userOTP[email] = {
    otp,
    expires: Date.now() + 5 * 60 * 1000
  };

  try {
    await sendOTP(email, otp);
    console.log("📩 OTP sent to:", email);

    res.json({
      success: true,
      message: "OTP sent to your email"
    });
  } catch (err) {
    console.error("❌ Email error:", err);
    res.status(500).json({
      success: false,
      message: "Failed to send OTP"
    });
  }
});

// ✅ VERIFY OTP
app.post('/api/auth/verify-otp', (req, res) => {
  const { email, code } = req.body;

  const record = userOTP[email];

  if (!record) {
    return res.json({ success: false, message: "No OTP found" });
  }

  if (Date.now() > record.expires) {
    delete userOTP[email];
    return res.json({ success: false, message: "OTP expired" });
  }

  if (record.otp == code) {
    delete userOTP[email];
    return res.json({ success: true });
  }

  return res.json({ success: false, message: "Invalid OTP" });
});

// ✅ RESEND OTP
app.post('/api/auth/resend-otp', async (req, res) => {
  const { email } = req.body;

  const otp = Math.floor(100000 + Math.random() * 900000);

  userOTP[email] = {
    otp,
    expires: Date.now() + 5 * 60 * 1000
  };

  try {
    await sendOTP(email, otp);
    console.log("🔁 OTP resent to:", email);

    res.json({ success: true });
  } catch (err) {
    console.error("❌ Email error:", err);
    res.status(500).json({ success: false });
  }
});

// ✅ LOGIN (TEMP)
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;

  if (password && password.length >= 8) {
    return res.json({ success: true });
  }

  res.json({ success: false, message: "Invalid credentials" });
});

// ✅ ROOT
app.get('/', (req, res) => {
  res.send('Server running 🚀');
});

// 🚀 START SERVER
app.listen(5000, () => {
  console.log('Server running on http://localhost:5000');
});