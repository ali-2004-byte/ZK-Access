// Groth16 verifier over the committed verification key, kept separate so it can be tested and swapped.
import { readFileSync } from 'node:fs';
import { groth16 } from 'snarkjs';

export const ENGINE_VERSION = 'age18-groth16-v1';
const verificationKey = JSON.parse(readFileSync(new URL('../../zk/artifacts/verification_key.json', import.meta.url), 'utf8'));

// True only when the proof verifies; malformed points count as invalid rather than as errors.
export async function verifyAgeProof(publicSignals, proof) {
  try {
    return await groth16.verify(verificationKey, publicSignals, proof) === true;
  } catch {
    return false;
  }
}

// Stop the worker threads snarkjs keeps on its cached curve so short-lived processes can exit.
export async function closeProofEngine() {
  await globalThis.curve_bn128?.terminate();
  globalThis.curve_bn128 = null;
}
