import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
globalThis.hashwasm = require(join(here, '../../src/Web/js/vendor/argon2.umd.min.js'));

const C = await import('../../src/Web/js/crypto.js');

const CHEAP = { memoryKiB: 8192, iterations: 1, parallelism: 1 };
const salt = new Uint8Array(16).map((_, i) => i + 1);

test('key derivation is deterministic and sensitive to every input', async () => {
  const a = await C.deriveRawKeys('correct horse', salt, CHEAP);
  const b = await C.deriveRawKeys('correct horse', salt, CHEAP);
  assert.deepEqual(a.auth, b.auth);
  assert.deepEqual(a.enc, b.enc);

  const otherPw = await C.deriveRawKeys('correct horsf', salt, CHEAP);
  const otherSalt = await C.deriveRawKeys('correct horse', salt.map((x) => x ^ 1), CHEAP);
  const otherParams = await C.deriveRawKeys('correct horse', salt, { ...CHEAP, iterations: 2 });
  for (const other of [otherPw, otherSalt, otherParams]) {
    assert.notDeepEqual(a.auth, other.auth);
    assert.notDeepEqual(a.enc, other.enc);
  }
});

test('auth key and encryption key are independent (HKDF domain separation)', async () => {
  const k = await C.deriveRawKeys('pw', salt, CHEAP);
  assert.equal(k.auth.length, 32);
  assert.equal(k.enc.length, 32);
  assert.notDeepEqual(k.auth, k.enc);
});

test('password is NFKC-normalised so equivalent unicode gives the same keys', async () => {
  const a = await C.deriveRawKeys('café', salt, CHEAP);        // precomposed e-acute
  const b = await C.deriveRawKeys('café', salt, CHEAP);       // e + combining accent
  assert.deepEqual(a.auth, b.auth);
});

test('the encryption key is a non-extractable CryptoKey', async () => {
  const { encKey, authKey } = await C.deriveKeys('pw', salt, CHEAP);
  assert.equal(encKey.extractable, false);
  await assert.rejects(() => crypto.subtle.exportKey('raw', encKey));
  assert.equal(C.fromBase64(authKey).length, 32);
});

test('vault encrypt/decrypt roundtrip with fresh nonces', async () => {
  const { encKey } = await C.deriveKeys('pw', salt, CHEAP);
  const vault = { entries: [{ Id: '1', Title: 'GitHub', Password: 'hunter2' }] };
  const a = await C.encryptVault(encKey, vault, salt, CHEAP);
  const b = await C.encryptVault(encKey, vault, salt, CHEAP);
  assert.notEqual(a.nonce, b.nonce);
  assert.notEqual(a.ciphertext, b.ciphertext);
  assert.deepEqual(await C.decryptVault(encKey, a, salt, CHEAP), vault);
  assert.ok(!Buffer.from(a.ciphertext, 'base64').includes(Buffer.from('hunter2')));
});

test('wrong key is rejected', async () => {
  const { encKey } = await C.deriveKeys('pw', salt, CHEAP);
  const { encKey: wrong } = await C.deriveKeys('other', salt, CHEAP);
  const blob = await C.encryptVault(encKey, { entries: [] }, salt, CHEAP);
  await assert.rejects(() => C.decryptVault(wrong, blob, salt, CHEAP), { message: 'decrypt-failed' });
});

test('tampered ciphertext and nonce are rejected', async () => {
  const { encKey } = await C.deriveKeys('pw', salt, CHEAP);
  const blob = await C.encryptVault(encKey, { entries: [1, 2, 3] }, salt, CHEAP);

  const ct = C.fromBase64(blob.ciphertext);
  ct[0] ^= 0xff;
  await assert.rejects(() => C.decryptVault(encKey, { ...blob, ciphertext: C.toBase64(ct) }, salt, CHEAP), { message: 'decrypt-failed' });

  const nonce = C.fromBase64(blob.nonce);
  nonce[0] ^= 0xff;
  await assert.rejects(() => C.decryptVault(encKey, { ...blob, nonce: C.toBase64(nonce) }, salt, CHEAP), { message: 'decrypt-failed' });
});

test('ciphertext is bound to salt and KDF parameters (associated data)', async () => {
  const { encKey } = await C.deriveKeys('pw', salt, CHEAP);
  const blob = await C.encryptVault(encKey, { entries: [] }, salt, CHEAP);
  await assert.rejects(() => C.decryptVault(encKey, blob, salt.map((x) => x ^ 1), CHEAP), { message: 'decrypt-failed' });
  await assert.rejects(() => C.decryptVault(encKey, blob, salt, { ...CHEAP, iterations: 2 }), { message: 'decrypt-failed' });
});

test('unknown format versions are refused instead of guessed at', async () => {
  const { encKey } = await C.deriveKeys('pw', salt, CHEAP);
  const blob = await C.encryptVault(encKey, { entries: [] }, salt, CHEAP);
  await assert.rejects(() => C.decryptVault(encKey, { ...blob, v: 99 }, salt, CHEAP), { message: 'unsupported-format' });
});

test('KDF parameters outside sane bounds are refused', async () => {
  await assert.rejects(() => C.argon2Raw('pw', salt, { memoryKiB: 1, iterations: 1, parallelism: 1 }));
  await assert.rejects(() => C.argon2Raw('pw', salt, { memoryKiB: 8192, iterations: 0, parallelism: 1 }));
  assert.equal(C.validateKdf(C.DEFAULT_KDF), true);
});

test('default parameters (64 MiB / 3 / 4) finish in a usable time', async () => {
  const t0 = performance.now();
  await C.deriveKeys('pw', salt, C.DEFAULT_KDF);
  const ms = performance.now() - t0;
  console.log(`   default KDF took ${Math.round(ms)} ms in Node`);
  assert.ok(ms < 8000, `took ${ms} ms`);
});

test('password generator: length, every selected category, no repeats across runs', () => {
  const seen = new Set();
  for (let i = 0; i < 200; i++) {
    const p = C.generatePassword(20);
    assert.equal(p.length, 20);
    assert.match(p, /[A-Z]/); assert.match(p, /[a-z]/); assert.match(p, /[0-9]/); assert.match(p, /[^A-Za-z0-9]/);
    seen.add(p);
  }
  assert.equal(seen.size, 200);
  assert.match(C.generatePassword(30, { digits: true }), /^[0-9]+$/);
});

test('randomInt is uniform enough (chi-square) for a non-power-of-two range', () => {
  const n = 7, draws = 70000, counts = new Array(n).fill(0);
  for (let i = 0; i < draws; i++) counts[C.randomInt(n)]++;
  const expected = draws / n;
  const chi = counts.reduce((s, c) => s + (c - expected) ** 2 / expected, 0);
  assert.ok(chi < 22.46, `chi-square ${chi} (df=6, p=0.001)`); // critical value for p = 0.001
});

test('strength hint orders obvious cases sensibly', () => {
  assert.ok(C.estimateBits('password') < C.estimateBits('Tr0ub4dor&3xQ!zP9'));
  assert.equal(C.describeStrength('abc12345').level, 'weak');
  assert.equal(C.describeStrength('k9$Lm2#vQx7!pZr4Wt8&').level, 'strong');
});

test('cross-language vector is unchanged (the .NET tests verify the same file against Konscious Argon2id)', async () => {
  const v = JSON.parse(readFileSync(join(here, '../contract/argon2-vector.json'), 'utf8'));
  const master = await C.argon2Raw(v.password, C.fromBase64(v.saltB64), v.kdf);
  assert.equal(C.toHex(master), v.masterKeyHex);
  const keys = await C.deriveRawKeys(v.password, C.fromBase64(v.saltB64), v.kdf);
  assert.equal(C.toBase64(keys.auth), v.authKeyB64);
});
