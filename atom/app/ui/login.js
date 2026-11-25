'use strict';

const form = document.getElementById('f');
const err = document.getElementById('err');
const go = document.getElementById('go');
let timer = null;

function showError(msg) {
  err.textContent = msg;
  err.hidden = !msg;
}

function lockFor(seconds) {
  clearInterval(timer);
  let left = seconds;
  go.disabled = true;
  const tick = () => {
    if (left <= 0) {
      clearInterval(timer);
      go.disabled = false;
      go.textContent = 'Se connecter';
      showError('');
      return;
    }
    go.textContent = `Réessaie dans ${left} s`;
    showError('Trop de tentatives. Cette adresse est bloquée temporairement.');
    left -= 1;
  };
  tick();
  timer = setInterval(tick, 1000);
}

// Déjà connecté (ou accès via l'ingress de Home Assistant) : on va directement à l'interface.
fetch('api/auth/me', { headers: { 'x-atom': '1' } })
  .then(r => r.json())
  .then(j => { if (j.authenticated) location.replace('./'); })
  .catch(() => {});

form.addEventListener('submit', async e => {
  e.preventDefault();
  showError('');
  go.disabled = true;
  try {
    const r = await fetch('api/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-atom': '1' },
      body: JSON.stringify({ username: form.username.value, password: form.password.value }),
    });
    let j = {};
    try { j = await r.json(); } catch { /* corps vide */ }
    if (r.ok) { location.replace('./'); return; }
    form.password.value = '';
    form.password.focus();
    if (r.status === 429) { lockFor(j.retry_after || 60); return; }
    showError(j.error || 'Connexion impossible');
  } catch {
    showError('Atom ne répond pas. Vérifie que le nœud est démarré.');
  }
  go.disabled = false;
});

// Bascule clair / sombre.
(function () {
  const btn = document.getElementById('theme');
  const root = document.documentElement;
  const dark = () => (root.getAttribute('data-theme') || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')) === 'dark';
  const label = () => { btn.textContent = dark() ? '☀ Clair' : '☾ Sombre'; };
  btn.addEventListener('click', () => {
    const next = dark() ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    try { localStorage.setItem('atom-theme', next); } catch (e) { /* ignoré */ }
    label();
  });
  label();
})();
