// Rhodium Vault Server - browser-side cryptography.
//
// Everything that touches the master password or the vault contents happens here, in the browser.
// The server only ever receives the *auth key* (a one-way derivative) and ciphertext.
//
//   masterKey = Argon2id(NFKC(password), salt, memory, iterations, parallelism)   -> 32 bytes
//   authKey   = HKDF-SHA256(masterKey, info = "rhodium-vault/auth/v1")           -> sent to the server
//   encKey    = HKDF-SHA256(masterKey, info = "rhodium-vault/enc/v1")            -> never leaves the browser,
//                                                                                   imported as a non-extractable AES-GCM CryptoKey
//
// HKDF is one-way: holding the auth key (or its server-side hash) does not reveal the encryption key.

export const FORMAT_VERSION = 1;
export const DEFAULT_KDF = Object.freeze({ memoryKiB: 65536, iterations: 3, parallelism: 4 });
export const SALT_BYTES = 16;

const enc = new TextEncoder();
const dec = new TextDecoder();

function argon2() {
  const lib = globalThis.hashwasm;
  if (!lib || typeof lib.argon2id !== 'function') {
    throw new Error('Argon2 library is not loaded (js/vendor/argon2.umd.min.js).');
  }
  return lib.argon2id;
}

// ---------- small helpers ----------

export function toBase64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

export function fromBase64(b64) {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function randomBytes(n) {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

/** Best effort only: JavaScript cannot guarantee that memory is really wiped. */
export function wipe(bytes) {
  if (bytes && bytes.fill) bytes.fill(0);
}

export function validateKdf(kdf) {
  return Number.isInteger(kdf?.memoryKiB) && kdf.memoryKiB >= 8192 && kdf.memoryKiB <= 1048576
    && Number.isInteger(kdf?.iterations) && kdf.iterations >= 1 && kdf.iterations <= 20
    && Number.isInteger(kdf?.parallelism) && kdf.parallelism >= 1 && kdf.parallelism <= 16;
}

// ---------- key derivation ----------

/** Raw Argon2id output (exported so the .NET side can be cross-checked against the same vector). */
export async function argon2Raw(password, salt, kdf) {
  if (!validateKdf(kdf)) throw new Error('Invalid KDF parameters.');
  return argon2()({
    password: enc.encode(password.normalize('NFKC')),
    salt,
    parallelism: kdf.parallelism,
    iterations: kdf.iterations,
    memorySize: kdf.memoryKiB,
    hashLength: 32,
    outputType: 'binary',
  });
}

async function hkdf(masterKey, label) {
  const base = await crypto.subtle.importKey('raw', masterKey, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode(label) },
    base,
    256,
  );
  return new Uint8Array(bits);
}

/** Exposed for tests only: both derived keys as raw bytes. Callers must wipe them. */
export async function deriveRawKeys(password, salt, kdf) {
  const master = await argon2Raw(password, salt, kdf);
  try {
    return {
      auth: await hkdf(master, 'rhodium-vault/auth/v1'),
      enc: await hkdf(master, 'rhodium-vault/enc/v1'),
    };
  } finally {
    wipe(master);
  }
}

/**
 * Derives the two independent keys from the master password.
 * Returns { authKey: base64 string (send to server), encKey: non-extractable CryptoKey (keep in memory) }.
 */
export async function deriveKeys(password, salt, kdf) {
  const raw = await deriveRawKeys(password, salt, kdf);
  try {
    const encKey = await crypto.subtle.importKey('raw', raw.enc, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    return { authKey: toBase64(raw.auth), encKey };
  } finally {
    wipe(raw.auth);
    wipe(raw.enc);
  }
}

// ---------- vault encryption ----------

/**
 * Associated data that binds the ciphertext to the salt and KDF parameters it was created with,
 * so a server (or attacker) cannot swap parameters or replay a blob under different credentials.
 */
export function buildAad(salt, kdf) {
  return enc.encode(`RVS|${FORMAT_VERSION}|${kdf.memoryKiB}|${kdf.iterations}|${kdf.parallelism}|${toBase64(salt)}`);
}

/** Encrypts a JSON-serialisable vault object. Fresh random 96-bit nonce on every call. */
export async function encryptVault(encKey, vaultObject, salt, kdf) {
  const nonce = randomBytes(12);
  const plaintext = enc.encode(JSON.stringify(vaultObject));
  try {
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: buildAad(salt, kdf), tagLength: 128 },
      encKey,
      plaintext,
    );
    return { v: FORMAT_VERSION, nonce: toBase64(nonce), ciphertext: toBase64(new Uint8Array(ct)) };
  } finally {
    wipe(plaintext);
  }
}

/** Decrypts a blob. Throws Error('decrypt-failed') for a wrong key, tampering or mismatching parameters. */
export async function decryptVault(encKey, blob, salt, kdf) {
  if (!blob || blob.v !== FORMAT_VERSION) throw new Error('unsupported-format');
  let plain;
  try {
    plain = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64(blob.nonce), additionalData: buildAad(salt, kdf), tagLength: 128 },
      encKey,
      fromBase64(blob.ciphertext),
    ));
  } catch {
    throw new Error('decrypt-failed');
  }
  try {
    return JSON.parse(dec.decode(plain));
  } finally {
    wipe(plain);
  }
}

// ---------- password generator (no modulo bias) ----------

const SETS = {
  upper: 'ABCDEFGHJKLMNPQRSTUVWXYZ',
  lower: 'abcdefghijkmnopqrstuvwxyz',
  digits: '23456789',
  symbols: '!@#$%^&*()-_=+[]{}?',
};

/** Uniform random integer in [0, max) using rejection sampling. */
export function randomInt(max) {
  if (!Number.isInteger(max) || max <= 0 || max > 0x100000000) throw new Error('bad range');
  const limit = Math.floor(0x100000000 / max) * max;
  const buf = new Uint32Array(1);
  do {
    crypto.getRandomValues(buf);
  } while (buf[0] >= limit);
  return buf[0] % max;
}

export function generatePassword(length, options = { upper: true, lower: true, digits: true, symbols: true }) {
  length = Math.min(128, Math.max(4, Math.trunc(length)));
  const chosen = Object.keys(SETS).filter((k) => options[k]);
  if (chosen.length === 0) chosen.push('lower');

  const pool = chosen.map((k) => SETS[k]).join('');
  const chars = [];
  for (const k of chosen) {
    if (chars.length < length) chars.push(SETS[k][randomInt(SETS[k].length)]);
  }
  while (chars.length < length) chars.push(pool[randomInt(pool.length)]);

  for (let i = chars.length - 1; i > 0; i--) { // Fisher-Yates
    const j = randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}

// ---------- password strength hint (port of the desktop app's PasswordStrength) ----------

const COMMON = ['password', 'passwort', '123456', '12345678', 'qwerty', 'abc123', 'letmein', 'iloveyou', 'admin', 'welcome', 'monkey', 'dragon'];

export function estimateBits(password) {
  if (!password) return 0;
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^A-Za-z0-9]/.test(password)) pool += 32;
  if (pool === 0) return 0;

  let bits = [...password].length * Math.log2(pool);
  if (new Set(password).size < password.length / 2) bits *= 0.6;
  const lower = password.toLowerCase();
  if (COMMON.some((c) => lower.includes(c))) bits *= 0.4;
  return bits;
}

export function describeStrength(password) {
  const bits = estimateBits(password);
  if (bits < 40) return { label: 'Weak - easy to guess. Try a longer passphrase.', level: 'weak' };
  if (bits < 60) return { label: 'Fair - longer would be better.', level: 'fair' };
  if (bits < 80) return { label: 'Good', level: 'good' };
  return { label: 'Strong', level: 'strong' };
}
