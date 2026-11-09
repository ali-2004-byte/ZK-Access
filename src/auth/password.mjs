import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scryptAsync = promisify(scrypt);
const CURRENT_N = 131072;
const R = 8;
const P = 1;
const SALT_BYTES = 16;
const KEY_BYTES = 64;
const MAXMEM_BYTES = 256 * 1024 * 1024;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;

function decodeCanonicalBase64url(value, length) {
  if (!BASE64URL.test(value)) throw new TypeError('Invalid password record encoding');
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length !== length || bytes.toString('base64url') !== value) {
    throw new TypeError('Invalid password record encoding');
  }
  return bytes;
}

export function parsePasswordRecord(record) {
  if (typeof record !== 'string' || record.length > 256) throw new TypeError('Invalid password record');
  const parts = record.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt' ||
      !DECIMAL.test(parts[1]) || !DECIMAL.test(parts[2]) || !DECIMAL.test(parts[3])) {
    throw new TypeError('Invalid password record');
  }
  const N = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  if (!Number.isSafeInteger(N) || N < 16384 || N > 131072 || (N & (N - 1)) !== 0 || r !== R || p !== P) {
    throw new RangeError('Password record scrypt parameters are outside the accepted range');
  }
  const salt = decodeCanonicalBase64url(parts[4], SALT_BYTES);
  const hash = decodeCanonicalBase64url(parts[5], KEY_BYTES);
  return { N, r, p, salt, hash };
}

export async function hashPassword(password) {
  if (typeof password !== 'string' || !password.isWellFormed() || [...password].length < 12) {
    throw new TypeError('Password must contain at least 12 characters');
  }
  const salt = randomBytes(SALT_BYTES);
  const hash = await scryptAsync(password, salt, KEY_BYTES, {
    N: CURRENT_N, r: R, p: P, maxmem: MAXMEM_BYTES,
  });
  return `scrypt$${CURRENT_N}$${R}$${P}$${salt.toString('base64url')}$${hash.toString('base64url')}`;
}

export async function verifyPassword(password, record) {
  if (typeof password !== 'string' || !password.isWellFormed()) throw new TypeError('Password must be a well-formed string');
  const { N, r, p, salt, hash } = parsePasswordRecord(record);
  const candidate = await scryptAsync(password, salt, KEY_BYTES, { N, r, p, maxmem: MAXMEM_BYTES });
  return timingSafeEqual(candidate, hash);
}
