const form = document.getElementById('login-form');
const errEl = document.getElementById('login-error');
const submitBtn = document.getElementById('login-submit');
const passwordInput = document.getElementById('password');
const tabsEl = document.getElementById('login-tabs');
const registerTab = document.getElementById('tab-register');

let mode = 'login';

function setMode(next) {
  mode = next;
  errEl.textContent = '';
  for (const btn of tabsEl.querySelectorAll('.login-tab')) {
    btn.classList.toggle('active', btn.dataset.mode === mode);
  }
  if (mode === 'register') {
    submitBtn.textContent = 'Create account';
    passwordInput.autocomplete = 'new-password';
    passwordInput.placeholder = 'min 8 characters';
  } else {
    submitBtn.textContent = 'Sign in';
    passwordInput.autocomplete = 'current-password';
    passwordInput.placeholder = '';
  }
}

tabsEl.addEventListener('click', (e) => {
  const btn = e.target.closest('.login-tab');
  if (btn) setMode(btn.dataset.mode);
});

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  errEl.textContent = '';
  submitBtn.disabled = true;

  const username = document.getElementById('username').value.trim();
  const password = passwordInput.value;
  const endpoint = mode === 'register' ? '/api/auth/register' : '/api/auth/login';

  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ username, password }),
    });

    if (res.ok) {
      window.location.href = '/';
      return;
    }

    const data = await res.json().catch(() => ({}));
    errEl.textContent = data.error || `${mode === 'register' ? 'registration' : 'sign-in'} failed (${res.status})`;
  } catch (err) {
    errEl.textContent = 'network error — is the server running?';
  } finally {
    submitBtn.disabled = false;
  }
});

fetch('/api/auth/config')
  .then((r) => r.json())
  .then((cfg) => { if (!cfg.allow_registration) registerTab.style.display = 'none'; })
  .catch(() => {});

fetch('/api/auth/me', { credentials: 'same-origin' })
  .then((r) => { if (r.ok) window.location.href = '/'; })
  .catch(() => {});
