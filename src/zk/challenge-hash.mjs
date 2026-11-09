import { createHash, randomBytes } from 'node:crypto';

/** Derive a 248-bit public input from a transient 32-byte random nonce. */
export function challengeHashFromNonce(nonce) {
  if (!(nonce instanceof Uint8Array) || nonce.length !== 32) {
    throw new TypeError('nonce must be exactly 32 bytes');
  }
  const digest = createHash('sha256').update(nonce).digest();
  return BigInt(`0x${digest.subarray(0, 31).toString('hex')}`).toString(10);
}

/** The raw nonce exists only during derivation and is never returned or persisted. */
export function createChallengeHash() {
  const nonce = randomBytes(32);
  try {
    return challengeHashFromNonce(nonce);
  } finally {
    nonce.fill(0);
  }
}
