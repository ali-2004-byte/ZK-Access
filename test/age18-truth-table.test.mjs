// Synthetic truth-table and edge-fixture tests for B1 (age-18 boundaries, leap days, malformed dates, invalid witnesses).
import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { groth16 } from 'snarkjs';
import { age18CutoffForUtcDate } from '../src/age-policy.mjs';
import { closeProofEngine, verifyAgeProof } from '../src/app/proof-engine.mjs';
import { encodeBirthDate } from '../src/issuer/birth-date.mjs';
import { challengeHashFromNonce } from '../src/zk/challenge-hash.mjs';
import { credentialCommitment, requestTag } from '../src/zk/poseidon.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const WASM = path.join(root, 'zk', 'artifacts', 'age18.wasm');
const ZKEY = path.join(root, 'zk', 'artifacts', 'age18_final.zkey');
const SYNTHETIC_SALT = '9876543210123456789';
const SYNTHETIC_CHALLENGE_HASH = challengeHashFromNonce(Buffer.alloc(32, 0x11));

test.after(closeProofEngine);

async function proveSynthetic(birthDateIso, challengeDateIso) {
  const cutoffIso = age18CutoffForUtcDate(challengeDateIso);
  const cutoff = String(Number(cutoffIso.replaceAll('-', '')));
  const birthDate = String(encodeBirthDate(birthDateIso));
  const commitment = credentialCommitment(birthDate, SYNTHETIC_SALT);
  const input = {
    birthDate,
    salt: SYNTHETIC_SALT,
    commitment,
    cutoff,
    challengeHash: SYNTHETIC_CHALLENGE_HASH,
  };
  const { proof, publicSignals } = await groth16.fullProve(input, WASM, ZKEY, undefined, undefined, { singleThread: true });
  return { proof, publicSignals, commitment, cutoff };
}

test('B1 truth table AGE-01 through AGE-07 with real Groth16 proofs', async () => {
  const allowCases = [
    ['AGE-01', '2008-11-09', '2026-11-09'], // exact 18th birthday
    ['AGE-03', '2008-11-08', '2026-11-09'], // day after 18th birthday
    ['AGE-05', '2008-02-29', '2026-03-01'], // Feb 29 birth observed Mar 1 in non-leap year
    ['AGE-06', '2006-02-28', '2024-02-29'], // leap-day challenge uses Feb 28 cutoff
  ];
  for (const [id, birthDate, challengeDate] of allowCases) {
    const { proof, publicSignals, commitment, cutoff } = await proveSynthetic(birthDate, challengeDate);
    assert.deepEqual(
      publicSignals,
      [requestTag(SYNTHETIC_CHALLENGE_HASH, commitment), commitment, cutoff, SYNTHETIC_CHALLENGE_HASH],
      `${id} signal order`,
    );
    assert.equal(await verifyAgeProof(publicSignals, proof), true, `${id} should verify`);
  }

  const denyCases = [
    ['AGE-02', '2008-11-10', '2026-11-09'], // day before 18th birthday
    ['AGE-04', '2008-02-29', '2026-02-28'], // Feb 29 birth before Mar 1 observation
    ['AGE-07', '2006-03-01', '2024-02-29'], // day after Feb 28 cutoff on leap-day challenge
  ];
  for (const [id, birthDate, challengeDate] of denyCases) {
    await assert.rejects(
      () => proveSynthetic(birthDate, challengeDate),
      `${id} should fail witness generation`,
    );
  }
});

test('B1 leap-year and century calendar rules in cutoff and birth date encoding', () => {
  assert.equal(age18CutoffForUtcDate('2024-02-29'), '2006-02-28');
  assert.equal(age18CutoffForUtcDate('2020-02-29'), '2002-02-28');
  assert.equal(age18CutoffForUtcDate('2026-02-28'), '2008-02-28');
  assert.equal(age18CutoffForUtcDate('2026-03-01'), '2008-03-01');
  assert.equal(encodeBirthDate('2000-02-29'), 20000229);
  assert.throws(() => encodeBirthDate('1900-02-29'));
});

test('B1 malformed and impossible dates are rejected', () => {
  const badDates = [
    '2007-02-29',
    '2026-02-29',
    '2026-11-31',
    '2026-04-31',
    '2026-13-01',
    '2026-00-01',
    '2026-01-00',
    '2026-1-1',
    '2008/11/09',
    'not-a-date',
    '',
  ];
  for (const bad of badDates) {
    assert.throws(() => encodeBirthDate(bad), `encodeBirthDate should reject ${bad}`);
    assert.throws(() => age18CutoffForUtcDate(bad), `age18CutoffForUtcDate should reject ${bad}`);
  }
});

test('B1 invalid witnesses and mutated public signals fail', async () => {
  const { proof, publicSignals, commitment, cutoff } = await proveSynthetic('2008-11-09', '2026-11-09');

  // Wrong birthDate (does not open commitment, even if <= cutoff)
  await assert.rejects(() => groth16.fullProve({
    birthDate: '20081108',
    salt: SYNTHETIC_SALT,
    commitment,
    cutoff,
    challengeHash: SYNTHETIC_CHALLENGE_HASH,
  }, WASM, ZKEY, undefined, undefined, { singleThread: true }));

  // Wrong salt (does not open commitment)
  await assert.rejects(() => groth16.fullProve({
    birthDate: '20081109',
    salt: '1',
    commitment,
    cutoff,
    challengeHash: SYNTHETIC_CHALLENGE_HASH,
  }, WASM, ZKEY, undefined, undefined, { singleThread: true }));

  // Out-of-range 32-bit cutoff and 248-bit challengeHash
  await assert.rejects(() => groth16.fullProve({
    birthDate: '20081109',
    salt: SYNTHETIC_SALT,
    commitment,
    cutoff: String(1n << 32n),
    challengeHash: SYNTHETIC_CHALLENGE_HASH,
  }, WASM, ZKEY, undefined, undefined, { singleThread: true }));

  await assert.rejects(() => groth16.fullProve({
    birthDate: '20081109',
    salt: SYNTHETIC_SALT,
    commitment,
    cutoff,
    challengeHash: String(1n << 248n),
  }, WASM, ZKEY, undefined, undefined, { singleThread: true }));

  // Mutating any of the 4 public signals invalidates Groth16 verification
  for (let index = 0; index < 4; index++) {
    const mutated = [...publicSignals];
    mutated[index] = (BigInt(mutated[index]) + 1n).toString();
    assert.equal(await verifyAgeProof(mutated, proof), false, `mutated signal ${index} must fail`);
  }
});
