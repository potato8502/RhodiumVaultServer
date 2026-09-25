import * as C from './crypto.js';
import { api, ApiError } from './api.js';

const $ = (id) => document.getElementById(id);
const IDLE_MS = 5 * 60 * 1000;
const CLIPBOARD_MS = 25 * 1000;
const MIN_PASSWORD = 10;

const state = {
  salt: null,        // Uint8Array
  kdf: null,
  revision: 0,
  encKey: null,      // non-extractable CryptoKey, memory only
  entries: [],
  revealed: new Set(),
  idleTimer: null,
  copyToken: null,
};

// ---------- tiny DOM helpers (all user data goes through textContent, never innerHTML) ----------

function el(tag, props = {}, ...kids) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else if (k === 'on') for (const [ev, fn] of Object.entries(v)) node.addEventListener(ev, fn);
    else node.setAttribute(k, v);
  }
  for (const kid of kids) if (kid) node.append(kid);
  return node;
}

function show(view) {
  for (const id of ['fatal', 'viewSetup', 'viewUnlock', 'viewVault']) $(id).hidden = id !== view;
}

let toastTimer;
function toast(message, isError = false) {
  const t = $('toast');
  t.textContent = message;
  t.className = isError ? 'toast error' : 'toast';
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, isError ? 7000 : 3500);
}

function setError(id, message) {
  const node = $(id);
  node.textContent = message || '';
  node.hidden = !message;
}

async function busy(button, label, fn) {
  const original = button.textContent;
  button.disabled = true;
  if (label) button.textContent = label;
  try { return await fn(); } finally { button.disabled = false; button.textContent = original; }
}

function explain(e) {
  if (!(e instanceof ApiError)) return 'Something went wrong. Please try again.';
  if (e.code === 'network-error') return 'Cannot reach the server.';
  if (e.status === 429) return `Too many attempts. Try again in ${e.retryAfterSeconds ?? 60} seconds.`;
  if (e.code === 'https-required') return 'This server must be opened via HTTPS (or localhost).';
  if (e.code === 'bad-setup-token') return 'That setup token is wrong. Check the server log.';
  if (e.code === 'already-setup') return 'This server already has a vault. Reload the page.';
  if (e.code === 'invalid-credentials') return 'Wrong master password.';
  if (e.status === 400) return 'The server rejected the request.';
  return `Server error (${e.status}).`;
}

function showStrength(nodeId, password) {
  const node = $(nodeId);
  if (!password) { node.hidden = true; return; }
  const s = C.describeStrength(password);
  node.textContent = s.label;
  node.className = `hint strength ${s.level}`;
  node.hidden = false;
}

// ---------- start ----------

async function init() {
  if (!globalThis.crypto?.subtle || !globalThis.hashwasm) {
    return fatal('This page needs a secure browser context (HTTPS or localhost). Open the vault through your HTTPS address.');
  }
  try {
    const status = await api.status();
    if (!status.secureContext) return fatal('This server must be opened via HTTPS (or localhost). Browsers block the cryptography needed here on plain HTTP.');
    show(status.setupRequired ? 'viewSetup' : 'viewUnlock');
    ($(status.setupRequired ? 'setupToken' : 'unlockPw')).focus();
  } catch {
    fatal('Cannot reach the server.');
  }
}

function fatal(text) {
  $('fatalText').textContent = text;
  show('fatal');
}

// ---------- setup ----------

$('setupPw').addEventListener('input', (e) => showStrength('setupStrength', e.target.value));

$('setupForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  setError('setupError', '');
  const token = $('setupToken').value.trim();
  const pw = $('setupPw').value;
  if (!token) return setError('setupError', 'Enter the setup token from the server log.');
  if (pw.length < MIN_PASSWORD) return setError('setupError', `Use at least ${MIN_PASSWORD} characters for your master password.`);
  if (pw !== $('setupPw2').value) return setError('setupError', "Passwords don't match.");

  await busy($('setupBtn'), 'Creating...', async () => {
    try {
      const salt = C.randomBytes(C.SALT_BYTES);
      const kdf = { ...C.DEFAULT_KDF };
      const { authKey, encKey } = await C.deriveKeys(pw, salt, kdf);
      const blob = await C.encryptVault(encKey, { entries: [] }, salt, kdf);
      await api.setup({ setupToken: token, authKey, salt: C.toBase64(salt), kdf, blob });
      Object.assign(state, { salt, kdf, encKey, revision: 1, entries: [] });
      enterVault();
    } catch (err) {
      setError('setupError', explain(err));
    }
  });
});

$('restoreBtn').addEventListener('click', async () => {
  setError('setupError', '');
  const file = $('restoreFile').files[0];
  const token = $('setupToken').value.trim();
  const pw = $('setupPw').value;
  if (!file) return setError('setupError', 'Choose a backup file first.');
  if (!token || !pw) return setError('setupError', 'Enter the setup token and the master password of that backup above.');

  await busy($('restoreBtn'), 'Restoring...', async () => {
    try {
      const backup = JSON.parse(await file.text());
      if (backup.format !== 'rhodium-vault-server-backup' || backup.formatVersion !== 1 || !C.validateKdf(backup.kdf)) {
        return setError('setupError', 'This is not a valid Rhodium Vault Server backup.');
      }
      const salt = C.fromBase64(backup.salt);
      const { authKey, encKey } = await C.deriveKeys(pw, salt, backup.kdf);
      let vault;
      try { vault = await C.decryptVault(encKey, backup.blob, salt, backup.kdf); }
      catch { return setError('setupError', 'That master password does not open this backup.'); }

      await api.setup({ setupToken: token, authKey, salt: backup.salt, kdf: backup.kdf, blob: backup.blob });
      Object.assign(state, { salt, kdf: backup.kdf, encKey, revision: 1, entries: vault.entries ?? [] });
      enterVault();
    } catch (err) {
      setError('setupError', err instanceof ApiError ? explain(err) : 'The backup file could not be read.');
    }
  });
});

// ---------- unlock / lock ----------

$('unlockForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  setError('unlockError', '');
  const pw = $('unlockPw').value;
  if (!pw) return;

  await busy($('unlockBtn'), 'Unlocking...', async () => {
    try {
      const pre = await api.prelogin();
      const salt = C.fromBase64(pre.salt);
      if (!C.validateKdf(pre.kdf)) throw new ApiError(400, 'invalid-kdf');
      const { authKey, encKey } = await C.deriveKeys(pw, salt, pre.kdf);
      await api.login(authKey);
      const v = await api.getVault();
      let vault;
      try { vault = await C.decryptVault(encKey, v.blob, C.fromBase64(v.salt), v.kdf); }
      catch { await api.logout().catch(() => {}); return setError('unlockError', 'The vault could not be decrypted.'); }

      Object.assign(state, { salt: C.fromBase64(v.salt), kdf: v.kdf, encKey, revision: v.revision, entries: vault.entries ?? [] });
      $('unlockPw').value = '';
      enterVault();
    } catch (err) {
      $('unlockPw').value = '';
      setError('unlockError', explain(err));
    }
  });
});

function lock(message) {
  clearTimeout(state.idleTimer);
  state.encKey = null;
  state.entries = [];
  state.revealed.clear();
  state.salt = null;
  for (const d of document.querySelectorAll('dialog[open]')) d.close();
  for (const id of ['entryForm', 'changeForm']) $(id).reset();
  $('entries').replaceChildren();
  $('search').value = '';
  clearClipboardIfOurs();
  api.logout().catch(() => {});
  $('unlockNote').textContent = message || 'Enter your master password to unlock.';
  show('viewUnlock');
  $('unlockPw').focus();
}

function sessionExpired() { lock('Your session expired. Please unlock again.'); }

$('btnLock').addEventListener('click', () => lock());

function resetIdle() {
  if (!state.encKey) return;
  clearTimeout(state.idleTimer);
  state.idleTimer = setTimeout(() => lock('Locked after 5 minutes of inactivity.'), IDLE_MS);
}
for (const ev of ['pointerdown', 'keydown', 'wheel', 'touchstart']) window.addEventListener(ev, resetIdle, { passive: true });

function enterVault() {
  show('viewVault');
  render();
  resetIdle();
}

// ---------- clipboard (best effort: see SECURITY.md) ----------

async function copySecret(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    return toast('Copying was blocked by the browser.', true);
  }
  const token = Symbol('copy');
  state.copyToken = token;
  toast('Copied. The clipboard is cleared in 25 seconds.');
  setTimeout(() => { if (state.copyToken === token) clearClipboardIfOurs(); }, CLIPBOARD_MS);
}

function clearClipboardIfOurs() {
  if (!state.copyToken) return;
  state.copyToken = null;
  navigator.clipboard?.writeText('').catch(() => {});
}

// ---------- persistence ----------

async function saveEntries(newEntries) {
  try {
    const blob = await C.encryptVault(state.encKey, { entries: newEntries }, state.salt, state.kdf);
    const r = await api.putVault(state.revision, blob);
    state.revision = r.revision;
    state.entries = newEntries;
    return true;
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) { sessionExpired(); return false; }
    if (err instanceof ApiError && err.status === 409) {
      toast('This vault was changed somewhere else. The latest version was loaded - please redo your change.', true);
      await reloadVault();
      return false;
    }
    toast(`Could not save: ${explain(err)}`, true);
    return false;
  }
}

async function reloadVault() {
  try {
    const v = await api.getVault();
    if (C.toBase64(state.salt) !== v.salt) return lock('The master password was changed elsewhere. Please unlock again.');
    const vault = await C.decryptVault(state.encKey, v.blob, C.fromBase64(v.salt), v.kdf);
    state.revision = v.revision;
    state.entries = vault.entries ?? [];
    render();
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) sessionExpired();
    else toast('Could not reload the vault.', true);
  }
}

// ---------- list ----------

function formatAge(iso) {
  const days = (Date.now() - new Date(iso).getTime()) / 86400000;
  if (days < 1) return 'Changed today';
  if (days < 2) return 'Changed yesterday';
  if (days < 30) return `Changed ${Math.floor(days)} days ago`;
  if (days < 365) return `Changed ${Math.floor(days / 30)} months ago`;
  const years = days / 365;
  return years < 2 ? 'Changed over a year ago' : `Changed ${Math.floor(years)} years ago`;
}

function render() {
  const q = $('search').value.trim().toLowerCase();
  const list = state.entries
    .filter((e) => !q || e.Title?.toLowerCase().includes(q) || e.Username?.toLowerCase().includes(q))
    .sort((a, b) => (b.IsFavorite - a.IsFavorite) || a.Title.localeCompare(b.Title, undefined, { sensitivity: 'base' }));

  const box = $('entries');
  if (list.length === 0) {
    box.replaceChildren(el('p', { class: 'empty', text: state.entries.length === 0 ? 'No entries yet - add your first one above.' : 'No entries match your search.' }));
    return;
  }
  box.replaceChildren(...list.map(card));
}

function card(entry) {
  const shown = state.revealed.has(entry.Id);
  const days = (Date.now() - new Date(entry.PasswordChangedAt).getTime()) / 86400000;
  const stale = days > 365;

  return el('article', { class: 'entry' },
    el('div', {},
      el('div', { class: 'title' },
        el('button', {
          class: entry.IsFavorite ? 'star on' : 'star', type: 'button', 'aria-label': entry.IsFavorite ? 'Remove from favorites' : 'Add to favorites',
          text: entry.IsFavorite ? '★' : '☆',
          on: { click: () => toggleFavorite(entry.Id) },
        }),
        el('span', { text: entry.Title }),
      ),
      el('div', { class: 'sub', text: entry.Username }),
      el('div', { class: 'pw', text: shown ? entry.Password : '•'.repeat(Math.min(entry.Password.length, 14)) }),
      el('div', { class: stale ? 'age stale' : 'age', text: formatAge(entry.PasswordChangedAt) + (stale ? ' - consider updating' : '') }),
    ),
    el('div', { class: 'buttons' },
      el('button', { class: 'btn ghost', type: 'button', text: shown ? 'Hide' : 'Show', on: { click: () => { shown ? state.revealed.delete(entry.Id) : state.revealed.add(entry.Id); render(); } } }),
      el('button', { class: 'btn ghost', type: 'button', text: 'Copy user', on: { click: () => copySecret(entry.Username) } }),
      el('button', { class: 'btn primary', type: 'button', text: 'Copy password', on: { click: () => copySecret(entry.Password) } }),
      el('button', { class: 'btn ghost', type: 'button', text: 'Edit', on: { click: () => openEntry(entry) } }),
      el('button', { class: 'btn ghost danger-btn', type: 'button', text: 'Delete', on: { click: () => removeEntry(entry) } }),
    ),
  );
}

$('search').addEventListener('input', render);

async function toggleFavorite(id) {
  const next = state.entries.map((e) => (e.Id === id ? { ...e, IsFavorite: !e.IsFavorite } : e));
  if (await saveEntries(next)) render();
}

async function removeEntry(entry) {
  if (!confirm(`Delete "${entry.Title}"? This can't be undone (older versions stay in History for a while).`)) return;
  if (await saveEntries(state.entries.filter((e) => e.Id !== entry.Id))) { state.revealed.delete(entry.Id); render(); }
}

// ---------- entry dialog ----------

let editing = null;

function openEntry(entry) {
  editing = entry;
  $('entryHeading').textContent = entry ? 'Edit entry' : 'Add entry';
  $('eTitle').value = entry?.Title ?? '';
  $('eUser').value = entry?.Username ?? '';
  $('ePw').value = entry?.Password ?? '';
  $('ePw').type = 'password';
  $('eReveal').textContent = 'Show';
  $('eUrl').value = entry?.Url ?? '';
  $('eNotes').value = entry?.Notes ?? '';
  setError('entryError', '');
  $('dlgEntry').showModal();
  $('eTitle').focus();
}

$('btnAdd').addEventListener('click', () => openEntry(null));
$('entryCancel').addEventListener('click', () => $('dlgEntry').close());
$('genLen').addEventListener('input', (e) => { $('genLenVal').textContent = e.target.value; });

$('eReveal').addEventListener('click', () => {
  const hidden = $('ePw').type === 'password';
  $('ePw').type = hidden ? 'text' : 'password';
  $('eReveal').textContent = hidden ? 'Hide' : 'Show';
});

$('eGenerate').addEventListener('click', () => {
  $('ePw').value = C.generatePassword(Number($('genLen').value), {
    upper: $('genUpper').checked, lower: $('genLower').checked, digits: $('genDigits').checked, symbols: $('genSymbols').checked,
  });
  $('ePw').type = 'text';
  $('eReveal').textContent = 'Hide';
});

$('entryForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const title = $('eTitle').value.trim();
  if (!title) return setError('entryError', 'Please enter a title.');

  const now = new Date().toISOString();
  const password = $('ePw').value;
  const updated = {
    Id: editing?.Id ?? crypto.randomUUID().replaceAll('-', ''),
    Title: title,
    Username: $('eUser').value.trim(),
    Password: password,
    Url: $('eUrl').value.trim(),
    Notes: $('eNotes').value,
    CreatedAt: editing?.CreatedAt ?? now,
    ModifiedAt: now,
    PasswordChangedAt: !editing || editing.Password !== password ? now : editing.PasswordChangedAt,
    IsFavorite: editing?.IsFavorite ?? false,
  };
  const next = editing ? state.entries.map((x) => (x.Id === editing.Id ? updated : x)) : [...state.entries, updated];

  if (await saveEntries(next)) {
    $('dlgEntry').close();
    render();
  }
});

// ---------- change master password ----------

$('btnChangePw').addEventListener('click', () => { setError('changeError', ''); showStrength('cStrength', ''); $('dlgChange').showModal(); $('cCur').focus(); });
$('changeCancel').addEventListener('click', () => $('dlgChange').close());
$('cNew').addEventListener('input', (e) => showStrength('cStrength', e.target.value));

$('changeForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  setError('changeError', '');
  const cur = $('cCur').value, next = $('cNew').value;
  if (next.length < MIN_PASSWORD) return setError('changeError', `Use at least ${MIN_PASSWORD} characters for your new master password.`);
  if (next !== $('cNew2').value) return setError('changeError', "New passwords don't match.");

  await busy($('changeBtn'), 'Changing...', async () => {
    try {
      const current = await C.deriveKeys(cur, state.salt, state.kdf);
      const newSalt = C.randomBytes(C.SALT_BYTES);
      const newKdf = { ...C.DEFAULT_KDF }; // also upgrades the cost parameters
      const fresh = await C.deriveKeys(next, newSalt, newKdf);
      const blob = await C.encryptVault(fresh.encKey, { entries: state.entries }, newSalt, newKdf);

      const r = await api.changePassword({
        currentAuthKey: current.authKey, newAuthKey: fresh.authKey, salt: C.toBase64(newSalt), kdf: newKdf, expectedRevision: state.revision, blob,
      });
      Object.assign(state, { encKey: fresh.encKey, salt: newSalt, kdf: newKdf, revision: r.revision });
      $('dlgChange').close();
      $('changeForm').reset();
      toast('Master password changed. Other sessions were signed out.');
    } catch (err) {
      if (err instanceof ApiError && err.status === 401 && err.code === 'unauthorized') return sessionExpired();
      if (err instanceof ApiError && err.status === 409) { await reloadVault(); return setError('changeError', 'The vault changed in the meantime. Please try again.'); }
      setError('changeError', err instanceof ApiError && err.code === 'invalid-credentials' ? 'Current master password is wrong.' : explain(err));
    }
  });
});

// ---------- backup & history ----------

$('btnBackup').addEventListener('click', async () => {
  try {
    const data = await api.backup();
    const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
    const a = el('a', { href: url, download: `rhodium-vault-backup-${new Date().toISOString().slice(0, 10)}.json` });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
    toast('Encrypted backup downloaded. Keep it and your master password safe.');
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) return sessionExpired();
    toast(`Backup failed: ${explain(err)}`, true);
  }
});

$('btnHistory').addEventListener('click', async () => {
  const list = $('historyList');
  list.replaceChildren(el('li', { class: 'muted', text: 'Loading...' }));
  $('dlgHistory').showModal();
  try {
    const items = await api.history();
    list.replaceChildren(...(items.length === 0
      ? [el('li', { class: 'muted', text: 'No previous versions yet.' })]
      : items.map((h) => el('li', {},
        el('span', { text: `Version ${h.revision} - ${new Date(h.createdUtc).toLocaleString()}` }),
        el('button', { class: 'btn ghost', type: 'button', text: 'Restore', on: { click: () => restoreVersion(h.revision) } }),
      ))));
  } catch (err) {
    $('dlgHistory').close();
    if (err instanceof ApiError && err.status === 401) return sessionExpired();
    toast(`Could not load history: ${explain(err)}`, true);
  }
});
$('historyClose').addEventListener('click', () => $('dlgHistory').close());

async function restoreVersion(revision) {
  try {
    const h = await api.historyItem(revision);
    if (h.salt !== C.toBase64(state.salt)) {
      return toast('That version was encrypted with a previous master password and cannot be restored here.', true);
    }
    const old = await C.decryptVault(state.encKey, h.blob, C.fromBase64(h.salt), h.kdf);
    if (!confirm(`Restore version ${revision} (${(old.entries ?? []).length} entries)? It is saved as a new version.`)) return;
    if (await saveEntries(old.entries ?? [])) { $('dlgHistory').close(); render(); toast('Version restored.'); }
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) return sessionExpired();
    toast('That version could not be restored.', true);
  }
}

init();
