import { poseidon } from '@iden3/js-crypto';
import { BN254_FIELD_MODULUS } from './field.mjs';

export { BN254_FIELD_MODULUS } from './field.mjs';

function fieldElement(value, name) {
  let number;
  try {
    number = BigInt(value);
  } catch {
    throw new TypeError(`${name} must be an integer field element`);
  }
  if (number < 0n || number >= BN254_FIELD_MODULUS) {
    throw new RangeError(`${name} is outside the BN254 scalar field`);
  }
  return number;
}

export function credentialCommitment(birthDateNumber, salt) {
  return poseidon.hash([
    fieldElement(birthDateNumber, 'birthDateNumber'),
    fieldElement(salt, 'salt'),
  ]).toString(10);
}

export function requestTag(challengeHash, commitment) {
  const hash = fieldElement(challengeHash, 'challengeHash');
  if (hash >= (1n << 248n)) throw new RangeError('challengeHash exceeds 248 bits');
  return poseidon.hash([hash, fieldElement(commitment, 'commitment')]).toString(10);
}
