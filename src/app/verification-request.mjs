import { decodeCredentialSignature } from '../credential-json.mjs';
import { parseStrictJson } from '../strict-json.mjs';
import { BN254_FIELD_MODULUS } from '../zk/field.mjs';
import { requestTag } from '../zk/poseidon.mjs';

const MAX_BODY_BYTES = 16 * 1024;
const TOP_KEYS = ['version', 'challengeId', 'credential', 'proof', 'publicSignals'];
const CREDENTIAL_KEYS = ['credentialId', 'commitment', 'issuedAt', 'expiresAt', 'issuerName', 'signature'];
const PROOF_KEYS = ['pi_a', 'pi_b', 'pi_c', 'protocol', 'curve'];
const DECIMAL = /^[0-9]+$/;
const CANONICAL_DECIMAL = /^(0|[1-9][0-9]*)$/;

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value, keys) {
  return isObject(value) && Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key));
}

function containsPrivateKey(value) {
  if (!isObject(value) && !Array.isArray(value)) return false;
  if (Array.isArray(value)) return value.some(containsPrivateKey);
  return Object.entries(value).some(([key, child]) =>
    key === 'birthDate' || key === 'salt' || containsPrivateKey(child));
}

function decimalString(value) {
  return typeof value === 'string' && DECIMAL.test(value);
}

function coordinateArray(value, length) {
  return Array.isArray(value) && value.length === length && value.every(decimalString);
}

function validProof(proof) {
  return exactKeys(proof, PROOF_KEYS) && proof.protocol === 'groth16' && proof.curve === 'bn128' &&
    coordinateArray(proof.pi_a, 3) && coordinateArray(proof.pi_c, 3) &&
    Array.isArray(proof.pi_b) && proof.pi_b.length === 3 &&
    proof.pi_b.every((row) => coordinateArray(row, 2));
}

/** Parse the raw request body; middleware must not JSON.parse it first. */
export function parseVerificationRequest(text) {
  const request = parseStrictJson(text, MAX_BODY_BYTES);
  if (containsPrivateKey(request)) throw new TypeError('PRIVATE_FIELD_SUBMITTED');
  if (!exactKeys(request, TOP_KEYS) || request.version !== '1' ||
      typeof request.challengeId !== 'string' || request.challengeId.length === 0) {
    throw new TypeError('Invalid verification request');
  }

  const credential = request.credential;
  if (!exactKeys(credential, CREDENTIAL_KEYS) ||
      typeof credential.credentialId !== 'string' || credential.credentialId.length === 0 ||
      typeof credential.commitment !== 'string' || !CANONICAL_DECIMAL.test(credential.commitment) ||
      BigInt(credential.commitment) >= BN254_FIELD_MODULUS ||
      !decimalString(credential.issuedAt) || !decimalString(credential.expiresAt) ||
      credential.issuerName !== 'ZK Access Demo Issuer') {
    throw new TypeError('Invalid public credential');
  }
  decodeCredentialSignature(credential.signature);

  if (!validProof(request.proof)) throw new TypeError('Invalid Groth16 proof shape');
  const signals = request.publicSignals;
  if (!Array.isArray(signals) || signals.length !== 4 || !signals.every(decimalString) ||
      BigInt(signals[0]) >= BN254_FIELD_MODULUS ||
      BigInt(signals[1]) >= BN254_FIELD_MODULUS ||
      BigInt(signals[2]) >= (1n << 32n) ||
      BigInt(signals[3]) >= (1n << 248n)) {
    throw new TypeError('Invalid public signals');
  }
  return request;
}

/** Public signal order is requestTag, commitment, cutoff, challengeHash. */
export function publicSignalsMatchChallenge(request, challenge) {
  const signals = request.publicSignals;
  return request.credential.credentialId === challenge.credentialId &&
    signals[0] === requestTag(challenge.challengeHash, request.credential.commitment) &&
    signals[1] === request.credential.commitment &&
    signals[2] === String(challenge.cutoff) &&
    signals[3] === challenge.challengeHash;
}
