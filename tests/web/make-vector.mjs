import { createRequire } from 'node:module';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
const here = dirname(fileURLToPath(import.meta.url));
globalThis.hashwasm = createRequire(import.meta.url)(join(here, '../../src/Web/js/vendor/argon2.umd.min.js'));
const C = await import('../../src/Web/js/crypto.js');
const salt = Uint8Array.from({ length: 16 }, (_, i) => 0xa0 + i);
const kdf = { memoryKiB: 65536, iterations: 3, parallelism: 4 };
const password = 'correct horse battery staple';
const master = await C.argon2Raw(password, salt, kdf);
const keys = await C.deriveRawKeys(password, salt, kdf);
writeFileSync(join(here, '../contract/argon2-vector.json'), JSON.stringify({
  password, saltB64: C.toBase64(salt), kdf, masterKeyHex: C.toHex(master), authKeyB64: C.toBase64(keys.auth),
}, null, 2));
console.log('vector written');
