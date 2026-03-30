
  // Password toggle
  const eyeBtn = document.getElementById('eyeToggle');
  const pwdInput = document.getElementById('password');
  const eyeIcon = document.getElementById('eyeIcon');
  let visible = false;
  eyeBtn.addEventListener('click', () => {
    visible = !visible;
    pwdInput.type = visible ? 'text' : 'password';
    eyeIcon.textContent = visible ? '🔒' : '👁';
  });
 
  // Checkbox
  const chk = document.getElementById('remember');
  const box = document.getElementById('checkBox');
  box.addEventListener('click', () => { chk.checked = !chk.checked; });
 
  // Toast helper
  function showToast(msg, type='error') {
    const t = document.getElementById('toast');
    const icon = document.getElementById('toastIcon');
    const m = document.getElementById('toastMsg');
    t.className = `toast ${type}`;
    icon.textContent = type === 'success' ? '✅' : '❌';
    m.textContent = msg;
    t.classList.add('show');
    setTimeout(() => t.classList.remove('show'), 3500);
  }
 
  // Form submit
  document.getElementById('loginForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    const username = document.getElementById('username').value.trim();
    const email = document.getElementById('email').value.trim();
    const pwd   = document.getElementById('password').value;
    const btn   = document.getElementById('signInBtn');
 
    if (!username) { showToast('Please enter your username.'); return; }
    if (username.length < 3) { showToast('Username must be at least 3 characters.'); return; }
    if (!/^[a-zA-Z0-9_.-]+$/.test(username)) { showToast('Username can only contain letters, numbers, _ . -'); return; }
    if (!email) { showToast('Please enter your email address.'); return; }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { showToast('Please enter a valid email address.'); return; }
    if (pwd.length < 8) { showToast('Password must be at least 8 characters.'); return; }
 
    // Simulate API call
    btn.classList.add('loading');
    await new Promise(r => setTimeout(r, 1800));
    btn.classList.remove('loading');
 
    showToast('Signed in successfully! Redirecting…', 'success');
    // window.location.href = '/dashboard'; // connect your route here
  });
