/* ============================================================
   FileVault — auth.js
   Shared JS for login.html and register.html
   ============================================================ */

/* ── TOAST ── */
function showToast(msg, type = 'error') {
  const t    = document.getElementById('toast');
  const icon = document.getElementById('toastIcon');
  const m    = document.getElementById('toastMsg');
  if (!t) return;
  t.className = `toast ${type}`;
  icon.textContent = type === 'success' ? '✅' : '❌';
  m.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3500);
}

/* ── EYE TOGGLE (password show/hide) ── */
function initEyeToggle(btnId, iconId, inputId) {
  const btn   = document.getElementById(btnId);
  const input = document.getElementById(inputId);
  const icon  = document.getElementById(iconId);
  if (!btn) return;
  let visible = false;
  btn.addEventListener('click', () => {
    visible = !visible;
    input.type = visible ? 'text' : 'password';
    icon.textContent = visible ? '🔒' : '👁';
  });
}

/* ── CUSTOM CHECKBOX ── */
function initCheckbox(boxId, inputId, checkedClass = 'checked') {
  const box = document.getElementById(boxId);
  const chk = document.getElementById(inputId);
  if (!box || !chk) return;
 box.addEventListener('click', (e) => {
  e.preventDefault(); // stop default behavior
  chk.checked = !chk.checked;
  box.classList.toggle(checkedClass, chk.checked);
});
}

/* ── FIELD STATUS (valid/invalid icon + border) ── */
function setFieldStatus(inputId, statusId, errorId, valid, msg = '') {
  const inp = document.getElementById(inputId);
  const st  = statusId ? document.getElementById(statusId) : null;
  const er  = errorId  ? document.getElementById(errorId)  : null;
  if (!inp) return;
  inp.classList.remove('valid', 'invalid');
  if (st) { st.textContent = ''; st.classList.remove('show'); }
  if (valid === true)  {
    inp.classList.add('valid');
    if (st) { st.textContent = '✅'; st.classList.add('show'); }
  }
  if (valid === false) {
    inp.classList.add('invalid');
    if (st) { st.textContent = '❌'; st.classList.add('show'); }
  }
  if (er) er.textContent = msg;
}

/* ── PASSWORD STRENGTH ── */
const STRENGTH_COLORS = ['#ff5370', '#f5a623', '#4f8bff', '#22d3a5'];
const STRENGTH_NAMES  = ['Weak', 'Fair', 'Good', 'Strong'];

function calcPasswordStrength(pwd) {
  let score = 0;
  if (pwd.length >= 8)  score++;
  if (pwd.length >= 12) score++;
  if (/[A-Z]/.test(pwd) && /[a-z]/.test(pwd)) score++;
  if (/[0-9]/.test(pwd)) score++;
  if (/[^A-Za-z0-9]/.test(pwd)) score++;
  return Math.min(Math.floor(score * 4 / 5), 4);
}

function initStrengthMeter(inputId, barIds, labelId) {
  const input = document.getElementById(inputId);
  const label = document.getElementById(labelId);
  if (!input) return;

  input.addEventListener('input', function () {
    const s = calcPasswordStrength(this.value);
    barIds.forEach((id, i) => {
      const el = document.getElementById(id);
      if (el) el.style.background = i < s ? STRENGTH_COLORS[s - 1] : 'var(--border)';
    });
    if (label) {
      if (!this.value) {
        label.textContent = 'Enter a password';
        label.style.color = 'var(--text-dim)';
      } else {
        label.textContent = STRENGTH_NAMES[s - 1] || 'Too weak';
        label.style.color = s > 0 ? STRENGTH_COLORS[s - 1] : 'var(--error)';
      }
    }
  });
}

/* ── USERNAME AVAILABILITY (simulated) ── */
const TAKEN_USERNAMES = ['admin', 'root', 'user', 'test', 'filevault', 'john_doe'];
let _unTimer = null;

function initUsernameCheck(inputId, badgeId, statusId, errorId) {
  const input = document.getElementById(inputId);
  const badge = document.getElementById(badgeId);
  if (!input) return;

  input.addEventListener('input', function () {
    clearTimeout(_unTimer);
    const v = this.value.trim();
    if (!v) {
      badge.className = 'availability';
      setFieldStatus(inputId, statusId, errorId, null);
      return;
    }
    badge.className = 'availability checking';
    badge.textContent = '⌛ checking…';

    _unTimer = setTimeout(() => {
      if (TAKEN_USERNAMES.includes(v.toLowerCase())) {
        badge.className = 'availability taken';
        badge.textContent = '✗ Taken';
        setFieldStatus(inputId, statusId, errorId, false, 'This username is already taken.');
      } else if (v.length < 3) {
        badge.className = 'availability';
        setFieldStatus(inputId, statusId, errorId, false, 'Username must be at least 3 characters.');
      } else if (!/^[a-zA-Z0-9_.-]+$/.test(v)) {
        badge.className = 'availability';
        setFieldStatus(inputId, statusId, errorId, false, 'Only letters, numbers, _ . - allowed.');
      } else {
        badge.className = 'availability available';
        badge.textContent = '✓ Available';
        setFieldStatus(inputId, statusId, errorId, true);
      }
    }, 600);
  });
}

/* ── LOGIN FORM ── */
function initLoginForm() {
  const form = document.getElementById('loginForm');
  if (!form) return;

  initEyeToggle('eyeToggle', 'eyeIcon', 'password');
  initCheckbox('checkBox', 'remember');

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    const username = document.getElementById('username').value.trim();
    const email    = document.getElementById('email').value.trim();
    const pwd      = document.getElementById('password').value;
    const btn      = document.getElementById('signInBtn');

    if (!username)                                       { showToast('Please enter your username.'); return; }
    if (username.length < 3)                             { showToast('Username must be at least 3 characters.'); return; }
    if (!/^[a-zA-Z0-9_.-]+$/.test(username))            { showToast('Username can only contain letters, numbers, _ . -'); return; }
    if (!email)                                          { showToast('Please enter your email address.'); return; }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))      { showToast('Please enter a valid email address.'); return; }
    if (pwd.length < 8)                                  { showToast('Password must be at least 8 characters.'); return; }

    btn.classList.add('loading');
    await new Promise(r => setTimeout(r, 1800));
    btn.classList.remove('loading');

    showToast('Signed in! Sending OTP…', 'success');
    // TODO: window.location.href = 'otp.html';
  });
}

/* ── REGISTER FORM ── */
function initRegisterForm() {
  const form = document.getElementById('registerForm');
  if (!form) return;

  initEyeToggle('eyeToggle1', 'eyeIcon1', 'password');
  initEyeToggle('eyeToggle2', 'eyeIcon2', 'confirmPassword');
  initCheckbox('termBox', 'terms', 'checked-purple');
  initStrengthMeter('password', ['sb1','sb2','sb3','sb4'], 'strengthLabel');
  initUsernameCheck('username', 'userAvail', 'unStatus', 'unError');

  // Blur validators
  document.getElementById('firstName')?.addEventListener('blur', function () {
    setFieldStatus('firstName', 'fnStatus', 'fnError',
      this.value.trim() ? true : false,
      this.value.trim() ? '' : 'First name is required.');
  });
  document.getElementById('lastName')?.addEventListener('blur', function () {
    setFieldStatus('lastName', 'lnStatus', 'lnError',
      this.value.trim() ? true : false,
      this.value.trim() ? '' : 'Last name is required.');
  });
  document.getElementById('email')?.addEventListener('blur', function () {
    const v = this.value.trim();
    const ok = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
    setFieldStatus('email', 'emStatus', 'emError',
      v ? (ok ? true : false) : false,
      !v ? 'Email is required.' : ok ? '' : 'Enter a valid email address.');
  });

  // Confirm password
  function validateConfirm() {
    const pw = document.getElementById('password').value;
    const cp = document.getElementById('confirmPassword').value;
    const er = document.getElementById('cpError');
    const inp = document.getElementById('confirmPassword');
    if (!cp) { er.textContent = ''; return false; }
    if (pw !== cp) {
      er.textContent = 'Passwords do not match.';
      inp.classList.add('invalid'); inp.classList.remove('valid');
      return false;
    }
    er.textContent = '';
    inp.classList.remove('invalid'); inp.classList.add('valid');
    return true;
  }
  document.getElementById('confirmPassword')?.addEventListener('input', validateConfirm);
  document.getElementById('password')?.addEventListener('input', () => {
    if (document.getElementById('confirmPassword').value) validateConfirm();
  });

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    const fn  = document.getElementById('firstName').value.trim();
    const ln  = document.getElementById('lastName').value.trim();
    const un  = document.getElementById('username').value.trim();
    const em  = document.getElementById('email').value.trim();
    const pw  = document.getElementById('password').value;
    const cp  = document.getElementById('confirmPassword').value;
    const btn = document.getElementById('regBtn');
    const termsChk = document.getElementById('terms');

    if (!fn)                                             { showToast('First name is required.'); return; }
    if (!ln)                                             { showToast('Last name is required.'); return; }
    if (!un || un.length < 3)                            { showToast('Enter a valid username (min 3 chars).'); return; }
    if (!/^[a-zA-Z0-9_.-]+$/.test(un))                  { showToast('Username has invalid characters.'); return; }
    if (TAKEN_USERNAMES.includes(un.toLowerCase()))      { showToast('That username is already taken.'); return; }
    if (!em || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em))  { showToast('Enter a valid email address.'); return; }
    if (pw.length < 8)                                   { showToast('Password must be at least 8 characters.'); return; }
    if (calcPasswordStrength(pw) < 2)                    { showToast('Please use a stronger password.'); return; }
    if (pw !== cp)                                       { showToast('Passwords do not match.'); return; }
    if (!termsChk?.checked)                              { showToast('Please accept the Terms of Service.'); return; }

    btn.classList.add('loading');
    await new Promise(r => setTimeout(r, 2000));
    btn.classList.remove('loading');

    showToast(`Welcome, ${fn}! Account created. Sending OTP…`, 'success');
    // TODO: setTimeout(() => { window.location.href = 'otp.html'; }, 1800);
  });
}

/* ── AUTO INIT on DOM ready ── */
document.addEventListener('DOMContentLoaded', () => {
  initLoginForm();
  initRegisterForm();
});
