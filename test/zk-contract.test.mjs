import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { challengeHashFromNonce, createChallengeHash } from '../src/zk/challenge-hash.mjs';
import { BN254_FIELD_MODULUS, credentialCommitment, requestTag } from '../src/zk/poseidon.mjs';

test('challenge hash uses the first 31 SHA-256 bytes and fits 248 bits', () => {
  const nonce = Buffer.alloc(32, 7);
  const expected = BigInt(`0x${createHash('sha256').update(nonce).digest('hex').slice(0, 62)}`);
  assert.equal(BigInt(challengeHashFromNonce(nonce)), expected);
  assert.ok(expected < 1n << 248n);
  assert.ok(BigInt(createChallengeHash()) < 1n << 248n);
  assert.throws(() => challengeHashFromNonce(Buffer.alloc(31)));
});

test('commitment and request tag bind distinct values', () => {
  const commitment = credentialCommitment(20081109, 123456789n);
  assert.notEqual(credentialCommitment(20081110, 123456789n), commitment);
  assert.notEqual(credentialCommitment(20081109, 123456790n), commitment);
  assert.notEqual(requestTag(17n, commitment), requestTag(18n, commitment));
  assert.throws(() => requestTag(1n << 248n, commitment));
  assert.throws(() => credentialCommitment(20081109, BN254_FIELD_MODULUS));
});
