import assert from 'node:assert/strict';
import test from 'node:test';
import { parseVerificationRequest, publicSignalsMatchChallenge } from '../src/app/verification-request.mjs';
import { requestTag } from '../src/zk/poseidon.mjs';

const credential = {
  credentialId: 'synthetic-1',
  commitment: '123',
  issuedAt: '1794268800',
  expiresAt: '1802044800',
  issuerName: 'ZK Access Demo Issuer',
  signature: Buffer.alloc(64, 0x5a).toString('base64url'),
};
const challenge = { credentialId: 'synthetic-1', cutoff: '20081109', challengeHash: '7' };
const submission = {
  version: '1',
  challengeId: 'opaque-challenge-id',
  credential,
  proof: {
    pi_a: ['1', '2', '1'],
    pi_b: [['3', '4'], ['5', '6'], ['1', '0']],
    pi_c: ['7', '8', '1'],
    protocol: 'groth16',
    curve: 'bn128',
  },
  publicSignals: [requestTag('7', '123'), '123', '20081109', '7'],
};

test('strict public request has the exact shape and snarkjs signal order', () => {
  const parsed = parseVerificationRequest(JSON.stringify(submission));
  assert.equal(publicSignalsMatchChallenge(parsed, challenge), true);
  assert.equal(publicSignalsMatchChallenge(parsed, { ...challenge, challengeHash: '8' }), false);
  assert.equal(publicSignalsMatchChallenge(parsed, { ...challenge, cutoff: '20081108' }), false);
  assert.equal(publicSignalsMatchChallenge(parsed, { ...challenge, credentialId: 'other' }), false);
  const changed = { ...submission, publicSignals: [submission.publicSignals[1], submission.publicSignals[0], '20081109', '7'] };
  assert.equal(publicSignalsMatchChallenge(parseVerificationRequest(JSON.stringify(changed)), challenge), false);
});

test('duplicate keys at every depth and private fields are rejected', () => {
  const json = JSON.stringify(submission);
  assert.throws(() => parseVerificationRequest(json.replace('"version":"1"', '"version":"1","version":"1"')));
  assert.throws(() => parseVerificationRequest(json.replace('"credentialId":"synthetic-1"', '"credentialId":"synthetic-1","credentialId":"other"')));
  assert.throws(() => parseVerificationRequest(json.replace('"protocol":"groth16"', '"protocol":"groth16","protocol":"groth16"')));
  assert.throws(() => parseVerificationRequest(JSON.stringify({ ...submission, birthDate: '2008-11-09' })), /PRIVATE_FIELD_SUBMITTED/);
  assert.throws(() => parseVerificationRequest(JSON.stringify({ ...submission, credential: { ...credential, salt: '1' } })), /PRIVATE_FIELD_SUBMITTED/);
  assert.throws(() => parseVerificationRequest(JSON.stringify({ ...submission, proof: { ...submission.proof, salt: '1' } })), /PRIVATE_FIELD_SUBMITTED/);
});

test('missing, extra, wrongly typed, and oversized request bodies are rejected', () => {
  const { challengeId: _challengeId, ...missing } = submission;
  assert.throws(() => parseVerificationRequest(JSON.stringify(missing)));
  assert.throws(() => parseVerificationRequest(JSON.stringify({ ...submission, extra: true })));
  assert.throws(() => parseVerificationRequest(JSON.stringify({ ...submission, challengeId: 7 })));
  assert.throws(() => parseVerificationRequest(JSON.stringify({ ...submission, version: '2' })));
  assert.throws(() => parseVerificationRequest(JSON.stringify({ ...submission, credential: { ...credential, extra: 'x' } })));
  assert.throws(() => parseVerificationRequest(JSON.stringify({ ...submission, proof: { ...submission.proof, extra: 'x' } })));
  assert.throws(() => parseVerificationRequest(JSON.stringify({ ...submission, publicSignals: ['1', '2', '3'] })));
  assert.throws(() => parseVerificationRequest(JSON.stringify({ ...submission, publicSignals: ['1', '2', 3, '4'] })));
  assert.throws(() => parseVerificationRequest(JSON.stringify(submission) + ' '.repeat(16 * 1024)));
});
