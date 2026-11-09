import assert from 'node:assert/strict';
import test from 'node:test';
import { birthDateNumberForProof, decodeCredentialSignature, parsePrivateCredentialJson } from '../src/credential-json.mjs';
import { BN254_FIELD_MODULUS } from '../src/zk/field.mjs';

const credential = {
  version: '1',
  credentialId: 'synthetic-1',
  birthDate: '2008-02-29',
  salt: '7',
  commitment: '123',
  issuedAt: '1794268800',
  expiresAt: '1802044800',
  issuerName: 'ZK Access Demo Issuer',
  signature: Buffer.alloc(64, 0x5a).toString('base64url'),
};

test('private credential import validates the nine-field schema and browser date conversion', () => {
  const parsed = parsePrivateCredentialJson(JSON.stringify(credential));
  assert.deepEqual(Object.keys(parsed), Object.keys(credential));
  assert.equal(birthDateNumberForProof(parsed), 20080229);
  assert.equal(decodeCredentialSignature(parsed.signature).length, 64);
  assert.equal(Object.isFrozen(parsed), true);
});

test('duplicate keys, including escaped duplicates, are rejected before JSON.parse can overwrite them', () => {
  const json = JSON.stringify(credential);
  assert.throws(() => parsePrivateCredentialJson(json.replace('"version":"1"', '"version":"1","version":"1"')));
  assert.throws(() => parsePrivateCredentialJson(json.replace('"version":"1"', '"version":"1","\\u0076ersion":"1"')));
});

test('missing, extra, wrongly typed, and nested fields are rejected', () => {
  const { salt: _salt, ...withoutSalt } = credential;
  assert.throws(() => parsePrivateCredentialJson(JSON.stringify(withoutSalt)));
  assert.throws(() => parsePrivateCredentialJson(JSON.stringify({ ...credential, extra: 'x' })));
  assert.throws(() => parsePrivateCredentialJson(JSON.stringify({ ...credential, salt: 7 })));
  assert.throws(() => parsePrivateCredentialJson(JSON.stringify({ ...credential, commitment: 123 })));
  assert.throws(() => parsePrivateCredentialJson(JSON.stringify({ ...credential, issuedAt: 1794268800 })));
  assert.throws(() => parsePrivateCredentialJson(JSON.stringify({ ...credential, credentialId: ['synthetic-1'] })));
  assert.throws(() => parsePrivateCredentialJson(JSON.stringify({ ...credential, salt: { value: '7' } })));
  assert.throws(() => parsePrivateCredentialJson(JSON.stringify([credential])));
});

test('version, calendar date, field values, and signature encoding are checked', () => {
  const invalid = [
    { version: '2' },
    { birthDate: '2008-02-30' },
    { salt: BN254_FIELD_MODULUS.toString(10) },
    { salt: '-1' },
    { commitment: '0123' },
    { commitment: BN254_FIELD_MODULUS.toString(10) },
    { issuedAt: '2026-11-10T00:00:00Z' },
    { issuerName: 'Other Issuer' },
    { signature: Buffer.alloc(63).toString('base64url') },
    { signature: credential.signature + '=' },
  ];
  for (const changed of invalid) {
    assert.throws(() => parsePrivateCredentialJson(JSON.stringify({ ...credential, ...changed })));
  }
});

test('file size is limited to 4 KB of UTF-8, including whitespace', () => {
  const json = JSON.stringify(credential);
  const atLimit = json + ' '.repeat(4096 - Buffer.byteLength(json));
  assert.doesNotThrow(() => parsePrivateCredentialJson(atLimit));
  assert.throws(() => parsePrivateCredentialJson(atLimit + ' '));
});
