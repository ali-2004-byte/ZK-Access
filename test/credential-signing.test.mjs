import assert from 'node:assert/strict';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import test from 'node:test';
import { encodeCredentialSigningBytes, signCredentialFields, verifyCredentialFields } from '../src/credential-signing.mjs';

const fields = ['cred-1', '123', '0', '90', 'ZK Access Demo Issuer'];
const expectedBytes =
  '5a4b4143434553532d435245442d5631' +
  '00000006637265642d31' +
  '00000003313233' +
  '0000000130' +
  '000000023930' +
  '000000155a4b204163636573732044656d6f20497373756572';

test('signed bytes use the domain tag, fixed order, big-endian lengths, and UTF-8', () => {
  assert.equal(encodeCredentialSigningBytes(fields).toString('hex'), expectedBytes);
  assert.equal(
    encodeCredentialSigningBytes(['é', '0', '1', '2', 'X']).toString('hex'),
    '5a4b4143434553532d435245442d5631' +
      '00000002c3a9' +
      '0000000130' +
      '0000000131' +
      '0000000132' +
      '0000000158',
  );
});

test('fixed Ed25519 vector verifies and every signed field is covered', () => {
  const seed = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex');
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = createPublicKey(privateKey);
  const signature = signCredentialFields(fields, privateKey);
  assert.equal(
    signature.toString('hex'),
    '51e9aa4fc6868edc78852282528b8d610dc2296935011c274aca8f12a6c61381917bc504defe842416e94664da5b6499268ff14dc09c070b3c7b0bf248ec7c09',
  );
  assert.equal(verifyCredentialFields(fields, signature, publicKey), true);
  for (const index of fields.keys()) {
    const changed = [...fields];
    changed[index] += 'x';
    if (index === 1 || index === 2 || index === 3) changed[index] = String(BigInt(fields[index]) + 1n);
    assert.equal(verifyCredentialFields(changed, signature, publicKey), false);
  }
});

test('encoder rejects absent, extra, or noncanonical signing fields', () => {
  assert.throws(() => encodeCredentialSigningBytes(fields.slice(0, 4)));
  assert.throws(() => encodeCredentialSigningBytes([...fields, 'extra']));
  assert.throws(() => encodeCredentialSigningBytes({ ...fields }));
  assert.throws(() => encodeCredentialSigningBytes(['cred-1', '0123', '0', '90', 'issuer']));
  assert.throws(() => encodeCredentialSigningBytes(['cred-1', '123', '0.5', '90', 'issuer']));
  assert.throws(() => encodeCredentialSigningBytes(['\ud800', '123', '0', '90', 'issuer']));
});
