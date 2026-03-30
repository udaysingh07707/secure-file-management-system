/* ============================================================
   FileVault — auth.js
   Handles: Login, Register, OTP verification logic
   ============================================================ */

'use strict';

/* ── UTILS ── */

function showToast(msg, type = 'success') {
  const toast    = document.getElementById('toast');
  const toastMsg = document.getElementById('toastMsg');
  const toastIcon = document.getElementById('toastIcon');
  if (!toast) return;
  toast.className = 'toast ' + type;
  toastIcon.textContent = type === 'success' ? '✓' : '✕';
  toastMsg.textContent  = msg;
  toast.classList.add('show');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => toast.classList.remove('show'), 3500);
}

function setLoading(btn, on) {
  if (!btn) return;
  btn.disabled = on;
  btn.classList.toggle('loading', on);
}

function setError(id, msg) {
  const el = document.getElementById(id);
  if (el) el.textContent = msg;
}

function clearError(id) { setError(id, ''); }

function markInput(inputEl, state) {
  if (!inputEl) return;
  inputEl.classList.remove('valid', 'invalid');
  if (state) inputEl.classList.add(state);
}

/* ── FIELD VALIDATORS ── */

const Validators = {
  name:     v => v.trim().length >= 2,
  username: v => /^[a-zA-Z0-9_]{3,20}$/.test(v.trim()),
  email:    v => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v.trim()),
  password: v => v.length >= 8,
  match:    (a, b) => a === b,
};

/* ── PASSWORD STRENGTH ── */

function getStrength(pw) {
  let score = 0;
  if (pw.length >= 8)  score++;
  if (pw.length >= 12) score++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^a-zA-Z0-9]/.test(pw)) score++;
  if (score <= 1) return { level: 1, label: 'Weak',    color: 'var(--error)' };
  if (score <= 2) return { level: 2, label: 'Fair',    color: 'var(--warning)' };
  if (score <= 3) return { level: 3, label: 'Good',    color: 'var(--accent)' };
  return              { level: 4, label: 'Strong',  color: 'var(--success)' };
}

function updateStrength(pw) {
  const bars  = [1,2,3,4].map(i => document.getElementById('sb' + i));
  const label = document.getElementById('strengthLabel');
  if (!bars[0] || !label) return;
  if (!pw) {
    bars.forEach(b => { if(b) b.style.background = ''; });
    label.textContent = 'Enter a password';
    label.style.color = '';
    return;
  }
  const s = getStrength(pw);
  bars.forEach((b, i) => {
    if (!b) return;
    b.style.background = i < s.level ? s.color : 'var(--border)';
  });
  label.textContent = s.label;
  label.style.color = s.color;
}

/* ══════════════════════════════════════
   LOGIN PAGE
══════════════════════════════════════ */
(function initLogin() {
  const form     = document.getElementById('loginForm');
  if (!form) return;

  const uInput   = document.getElementById('username');
  const eInput   = document.getElementById('email');
  const pInput   = document.getElementById('password');
  const eyeBtn   = document.getElementById('eyeToggle');
  const eyeIcon  = document.getElementById('eyeIcon');
  const checkBox = document.getElementById('checkBox');
  const remember = document.getElementById('remember');
  const signInBtn = document.getElementById('signInBtn');

  /* Eye toggle */
  if (eyeBtn) {
    eyeBtn.addEventListener('click', () => {
      const show = pInput.type === 'password';
      pInput.type     = show ? 'text' : 'password';
      eyeIcon.textContent = show ? '🙈' : '👁';
    });
  }

  /* Custom checkbox */
  if (checkBox && remember) {
    checkBox.addEventListener('click', () => {
      remember.checked = !remember.checked;
      checkBox.classList.toggle('checked', remember.checked);
    });
  }

  /* Restore remembered username */
  const saved = localStorage.getItem('fv_remember');
  if (saved && uInput) {
    uInput.value = saved;
    if (checkBox && remember) {
      remember.checked = true;
      checkBox.classList.add('checked');
    }
  }

  /* Form submit */
  form.addEventListener('submit', async e => {
    e.preventDefault();

    const username = uInput ? uInput.value.trim() : '';
    const email    = eInput ? eInput.value.trim() : '';
    const password = pInput ? pInput.value : '';

    /* Basic validation */
    let ok = true;
    if (!username && !email) {
      showToast('Enter your username or email.', 'error');
      ok = false;
    }
    if (!password) {
      showToast('Password is required.', 'error');
      ok = false;
    }
    if (!ok) return;

    setLoading(signInBtn, true);

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email, password }),
      });
      const data = await res.json();

      if (res.ok && data.success) {
        if (remember.checked && username) {
          localStorage.setItem('fv_remember', username);
        } else {
          localStorage.removeItem('fv_remember');
        }
        /* Store masked email for OTP page */
        sessionStorage.setItem('fv_otp_email', data.maskedEmail || email);
        showToast('Logged in! Redirecting…', 'success');
        setTimeout(() => window.location.href = 'otp.html', 1000);
      } else {
        showToast(data.message || 'Invalid credentials. Try again.', 'error');
      }
    } catch (err) {
      showToast('Network error. Please try again.', 'error');
    } finally {
      setLoading(signInBtn, false);
    }
  });
})();

/* ══════════════════════════════════════
   REGISTER PAGE
══════════════════════════════════════ */
(function initRegister() {
  const form = document.getElementById('registerForm');
  if (!form) return;

  /* Inputs */
  const fnInput  = document.getElementById('firstName');
  const lnInput  = document.getElementById('lastName');
  const unInput  = document.getElementById('username');
  const emInput  = document.getElementById('email');
  const pwInput  = document.getElementById('password');
  const cpInput  = document.getElementById('confirmPassword');
  const regBtn   = document.getElementById('regBtn');
  const termBox  = document.getElementById('termBox');
  const terms    = document.getElementById('terms');
  const eye1     = document.getElementById('eyeToggle1');
  const eye2     = document.getElementById('eyeToggle2');
  const userAvail = document.getElementById('userAvail');

  /* Eye toggles */
  if (eye1 && pwInput) {
    eye1.addEventListener('click', () => {
      const show = pwInput.type === 'password';
      pwInput.type = show ? 'text' : 'password';
      document.getElementById('eyeIcon1').textContent = show ? '🙈' : '👁';
    });
  }
  if (eye2 && cpInput) {
    eye2.addEventListener('click', () => {
      const show = cpInput.type === 'password';
      cpInput.type = show ? 'text' : 'password';
      document.getElementById('eyeIcon2').textContent = show ? '🙈' : '👁';
    });
  }

  /* Terms checkbox */
if (terms && termBox) {
  terms.addEventListener('change', () => {
    if (terms.checked) {
      termBox.classList.add('checked-purple');
    } else {
      termBox.classList.remove('checked-purple');
    }
  });
}

  /* Real-time: first name */
  if (fnInput) {
    fnInput.addEventListener('input', () => {
      const ok = Validators.name(fnInput.value);
      markInput(fnInput, fnInput.value ? (ok ? 'valid' : 'invalid') : null);
      const st = document.getElementById('fnStatus');
      if (st) { st.textContent = fnInput.value ? (ok ? '✓' : '✕') : ''; st.classList.toggle('show', !!fnInput.value); }
      setError('fnError', (!ok && fnInput.value) ? 'At least 2 characters.' : '');
    });
  }

  /* Real-time: last name */
  if (lnInput) {
    lnInput.addEventListener('input', () => {
      const ok = Validators.name(lnInput.value);
      markInput(lnInput, lnInput.value ? (ok ? 'valid' : 'invalid') : null);
      const st = document.getElementById('lnStatus');
      if (st) { st.textContent = lnInput.value ? (ok ? '✓' : '✕') : ''; st.classList.toggle('show', !!lnInput.value); }
      setError('lnError', (!ok && lnInput.value) ? 'At least 2 characters.' : '');
    });
  }

  /* Real-time: username with debounced availability check */
let unTimer;

unInput.addEventListener('input', () => {
  clearTimeout(unTimer);

  const val = unInput.value.trim();

  // 1️⃣ Empty input
  if (!val) {
    markInput(unInput, null);
    userAvail.textContent = '';
    clearError('unError');
    return;
  }

  // 2️⃣ Format validation FIRST
  if (!Validators.username(val)) {
    markInput(unInput, 'invalid');
    setError('unError', '3–20 chars, letters/numbers/underscore only.');
    userAvail.textContent = '';
    return;
  }

  // ✅ Format is correct → show neutral/checking
  markInput(unInput, null);
  userAvail.textContent = 'Checking...';

  // 3️⃣ Backend check (debounced)
  unTimer = setTimeout(async () => {
    try {
      const res = await fetch(`http://localhost:5000/api/auth/check-username?username=${encodeURIComponent(val)}`);
      const data = await res.json();

      if (data.available) {
        markInput(unInput, 'valid');
        userAvail.textContent = '✓ Available';
        clearError('unError');
      } else {
        markInput(unInput, 'invalid');
        userAvail.textContent = '✕ Taken';
        setError('unError', 'Username already taken.');
      }

    } catch (err) {
      // 🔥 IMPORTANT FIX
      markInput(unInput, 'valid');   // don't punish user for server issue
      userAvail.textContent = '✓ Looks good';
      clearError('unError');
    }
  }, 500);
});

  /* Real-time: email */
  if (emInput) {
    emInput.addEventListener('input', () => {
      const ok = Validators.email(emInput.value);
      markInput(emInput, emInput.value ? (ok ? 'valid' : 'invalid') : null);
      const st = document.getElementById('emStatus');
      if (st) { st.textContent = emInput.value ? (ok ? '✓' : '✕') : ''; st.classList.toggle('show', !!emInput.value); }
      setError('emError', (!ok && emInput.value) ? 'Enter a valid email address.' : '');
    });
  }

  /* Real-time: password */
  if (pwInput) {
    pwInput.addEventListener('input', () => {
      updateStrength(pwInput.value);
      const ok = Validators.password(pwInput.value);
      setError('pwError', (!ok && pwInput.value) ? 'Password must be at least 8 characters.' : '');
      /* Also re-check confirm */
      if (cpInput && cpInput.value) {
        const match = Validators.match(pwInput.value, cpInput.value);
        markInput(cpInput, match ? 'valid' : 'invalid');
        setError('cpError', match ? '' : 'Passwords do not match.');
      }
    });
  }

  /* Real-time: confirm password */
  if (cpInput && pwInput) {
    cpInput.addEventListener('input', () => {
      const match = Validators.match(pwInput.value, cpInput.value);
      markInput(cpInput, cpInput.value ? (match ? 'valid' : 'invalid') : null);
      setError('cpError', (!match && cpInput.value) ? 'Passwords do not match.' : '');
    });
  }

  /* Form submit */
  form.addEventListener('submit', async e => {
    e.preventDefault();

    const firstName = fnInput ? fnInput.value.trim() : '';
    const lastName  = lnInput ? lnInput.value.trim() : '';
    const username  = unInput ? unInput.value.trim() : '';
    const email     = emInput ? emInput.value.trim() : '';
    const password  = pwInput ? pwInput.value : '';
    const confirm   = cpInput ? cpInput.value : '';
    const agreed    = terms   ? terms.checked : false;

    /* Validate all */
    let ok = true;
    if (!Validators.name(firstName))      { setError('fnError', 'First name is required.'); ok = false; }
    if (!Validators.name(lastName))       { setError('lnError', 'Last name is required.'); ok = false; }
    if (!Validators.username(username))   { setError('unError', '3–20 chars, letters/numbers/underscore.'); ok = false; }
    if (!Validators.email(email))         { setError('emError', 'Valid email required.'); ok = false; }
    if (!Validators.password(password))   { setError('pwError', 'At least 8 characters.'); ok = false; }
    if (!Validators.match(password, confirm)) { setError('cpError', 'Passwords do not match.'); ok = false; }
    if (!agreed) { showToast('Please accept the Terms of Service.', 'error'); ok = false; }
    if (!ok) return;

    setLoading(regBtn, true);

    try {
      const res = await fetch('http://localhost:5000/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ firstName, lastName, username, email, password }),
      });
      const data = await res.json();

      if (res.ok && data.success) {
        /* Mask email for OTP display: j***@company.com */
        const parts  = email.split('@');
        const masked = parts[0][0] + '***@' + parts[1];
        sessionStorage.setItem('fv_otp_email', masked);
        sessionStorage.setItem('fv_reg_email', email);
        showToast('Account created! Sending verification code…', 'success');
        setTimeout(() => window.location.href = 'otp.html', 1200);
      } else {
        showToast(data.message || 'Registration failed. Try again.', 'error');
      }
    } catch (err) {
      showToast('Network error. Please try again.', 'error');
    } finally {
      setLoading(regBtn, false);
    }
  });
})();

/* ══════════════════════════════════════
   OTP PAGE
══════════════════════════════════════ */
(function initOTP() {
  const otpGroup  = document.getElementById('otpGroup');
  if (!otpGroup) return;

  const boxes      = Array.from(otpGroup.querySelectorAll('.otp-box'));
  const verifyBtn  = document.getElementById('verifyBtn');
  const resendBtn  = document.getElementById('resendBtn');
  const countdownEl = document.getElementById('countdown');
  const otpError   = document.getElementById('otpError');
  const emailDisp  = document.getElementById('emailDisplay');

  /* Show masked email */
  const storedEmail = sessionStorage.getItem('fv_otp_email');
  if (emailDisp && storedEmail) emailDisp.textContent = storedEmail;

  /* ── OTP Box Logic ── */
  boxes.forEach((box, idx) => {
    box.addEventListener('keydown', e => {
      /* Allow: backspace, arrows, tab */
      if (e.key === 'Backspace') {
        e.preventDefault();
        box.value = '';
        box.classList.remove('filled');
        if (idx > 0) boxes[idx - 1].focus();
        updateVerifyBtn();
        return;
      }
      if (e.key === 'ArrowLeft'  && idx > 0) { e.preventDefault(); boxes[idx - 1].focus(); return; }
      if (e.key === 'ArrowRight' && idx < boxes.length - 1) { e.preventDefault(); boxes[idx + 1].focus(); return; }
    });

    box.addEventListener('input', e => {
      const val = e.target.value.replace(/\D/g, '');
      box.value = val ? val[0] : '';

      if (box.value) {
        box.classList.add('filled');
        box.classList.remove('invalid');
        if (idx < boxes.length - 1) boxes[idx + 1].focus();
      } else {
        box.classList.remove('filled');
      }
      updateVerifyBtn();
    });

    /* Handle paste on any box */
    box.addEventListener('paste', e => {
      e.preventDefault();
      const pasted = (e.clipboardData || window.clipboardData).getData('text').replace(/\D/g, '');
      if (!pasted) return;
      boxes.forEach((b, i) => {
        b.value = pasted[i] || '';
        b.classList.toggle('filled', !!b.value);
      });
      const next = Math.min(pasted.length, boxes.length - 1);
      boxes[next].focus();
      updateVerifyBtn();
    });
  });

  function getCode() { return boxes.map(b => b.value).join(''); }

  function updateVerifyBtn() {
    const code = getCode();
    if (verifyBtn) verifyBtn.disabled = code.length < boxes.length;
  }

  /* ── Countdown Timer ── */
  let secondsLeft = 5 * 60; // 5 minutes
  let timerInterval;

  function startCountdown() {
    clearInterval(timerInterval);
    secondsLeft = 5 * 60;
    updateCountdownDisplay();
    timerInterval = setInterval(() => {
      secondsLeft--;
      updateCountdownDisplay();
      if (secondsLeft <= 0) {
        clearInterval(timerInterval);
        if (verifyBtn) verifyBtn.disabled = true;
        boxes.forEach(b => { b.disabled = true; b.classList.add('invalid'); });
        if (otpError) otpError.textContent = 'Code expired. Please request a new one.';
        if (resendBtn) resendBtn.disabled = false;
      }
    }, 1000);
  }

  function updateCountdownDisplay() {
    if (!countdownEl) return;
    const m = Math.floor(secondsLeft / 60);
    const s = secondsLeft % 60;
    countdownEl.textContent = `${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
    countdownEl.classList.toggle('urgent', secondsLeft <= 60);
  }

  /* Resend cooldown: 60 seconds */
  let resendCooldown = 0;
  let resendInterval;

  function startResendCooldown(secs = 60) {
    resendCooldown = secs;
    if (resendBtn) resendBtn.disabled = true;
    const timerSpan = document.getElementById('resendTimer');
    resendInterval = setInterval(() => {
      resendCooldown--;
      if (timerSpan) timerSpan.textContent = resendCooldown > 0 ? `(${resendCooldown}s)` : '';
      if (resendCooldown <= 0) {
        clearInterval(resendInterval);
        if (resendBtn) resendBtn.disabled = false;
        if (timerSpan) timerSpan.textContent = '';
      }
    }, 1000);
  }

  /* Start on load */
  startCountdown();
  startResendCooldown(60);

  /* ── Verify Button ── */
  if (verifyBtn) {
    verifyBtn.addEventListener('click', async () => {
      const code  = getCode();
      const email = sessionStorage.getItem('fv_reg_email') || '';

      if (code.length < boxes.length) {
        if (otpError) otpError.textContent = 'Please enter all 6 digits.';
        return;
      }

      setLoading(verifyBtn, true);
      if (otpError) otpError.textContent = '';

      try {
        const res = await fetch('http://localhost:5000/api/auth/verify-otp', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, code }),
        });
        const data = await res.json();

        if (res.ok && data.success) {
          /* Visual: all boxes go green */
          boxes.forEach(b => { b.classList.add('valid'); b.classList.remove('filled'); });
          clearInterval(timerInterval);
          showToast('Email verified! Welcome to FileVault 🎉', 'success');
          setTimeout(() => window.location.href = 'dashboard.html', 1400);
        } else {
          boxes.forEach(b => b.classList.add('invalid'));
          if (otpError) otpError.textContent = data.message || 'Incorrect code. Try again.';
          /* Shake + clear after delay */
          setTimeout(() => {
            boxes.forEach(b => { b.classList.remove('invalid'); b.value = ''; b.classList.remove('filled'); });
            boxes[0].focus();
            updateVerifyBtn();
          }, 1200);
          showToast('Incorrect code. Try again.', 'error');
        }
      } catch (err) {
        showToast('Network error. Please try again.', 'error');
      } finally {
        setLoading(verifyBtn, false);
      }
    });
  }

  /* ── Resend Button ── */
  if (resendBtn) {
    resendBtn.addEventListener('click', async () => {
      const email = sessionStorage.getItem('fv_reg_email') || '';
      resendBtn.disabled = true;

      try {
        const res = await fetch('http://localhost:5000/api/auth/resend-otp', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email }),
        });
        const data = await res.json();

        if (res.ok && data.success) {
          /* Reset boxes */
          boxes.forEach(b => {
            b.value = ''; b.disabled = false;
            b.classList.remove('invalid', 'valid', 'filled');
          });
          boxes[0].focus();
          if (otpError) otpError.textContent = '';
          updateVerifyBtn();
          startCountdown();
          startResendCooldown(60);
          showToast('New code sent! Check your inbox.', 'success');
        } else {
          showToast(data.message || 'Could not resend. Try again.', 'error');
          resendBtn.disabled = false;
        }
      } catch (err) {
        showToast('Network error. Please try again.', 'error');
        resendBtn.disabled = false;
      }
    });
  }

  /* Auto-focus first box */
  if (boxes[0]) boxes[0].focus();
})();