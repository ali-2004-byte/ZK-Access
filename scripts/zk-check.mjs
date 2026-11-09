import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { groth16 } from 'snarkjs';
import { challengeHashFromNonce } from '../src/zk/challenge-hash.mjs';
import { credentialCommitment, requestTag } from '../src/zk/poseidon.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const artifacts = path.join(root, 'zk', 'artifacts');

async function check() {
  const commitment = credentialCommitment(20081109, 123456789n);
  const challengeHash = challengeHashFromNonce(Buffer.alloc(32, 7));
  const input = {
    birthDate: '20081109',
    salt: '123456789',
    commitment,
    cutoff: '20081109',
    challengeHash,
  };
  const wasm = path.join(artifacts, 'age18.wasm');
  const zkey = path.join(artifacts, 'age18_final.zkey');
  const verificationKey = JSON.parse(await readFile(path.join(artifacts, 'verification_key.json'), 'utf8'));

  const { proof, publicSignals } = await groth16.fullProve(input, wasm, zkey, undefined, undefined, { singleThread: true });
  assert.deepEqual(publicSignals, [requestTag(challengeHash, commitment), commitment, input.cutoff, challengeHash]);
  assert.equal(await groth16.verify(verificationKey, publicSignals, proof), true);

  const changedHash = [...publicSignals];
  changedHash[3] = (BigInt(challengeHash) + 1n).toString();
  assert.equal(await groth16.verify(verificationKey, changedHash, proof), false);

  const changedCutoff = [...publicSignals];
  changedCutoff[2] = '20081108';
  assert.equal(await groth16.verify(verificationKey, changedCutoff, proof), false);

  await assert.rejects(() => groth16.fullProve({ ...input, birthDate: '20081110' }, wasm, zkey, undefined, undefined, { singleThread: true }));
  await assert.rejects(() => groth16.fullProve({ ...input, salt: '123456790' }, wasm, zkey, undefined, undefined, { singleThread: true }));

  console.log(`Groth16 checks passed. Proof JSON size: ${Buffer.byteLength(JSON.stringify(proof))} bytes.`);
}

try {
  await check();
  // snarkjs worker handles can stay open after the checks complete.
  process.exit(0);
} catch (error) {
  console.error(error);
  process.exit(1);
}
