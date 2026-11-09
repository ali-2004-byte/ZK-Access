import { sign, verify } from 'node:crypto';

const DOMAIN_TAG = Buffer.from('ZKACCESS-CRED-V1', 'ascii');
const FIELD_COUNT = 5;
const DECIMAL = /^[0-9]+$/;
const CANONICAL_DECIMAL = /^(0|[1-9][0-9]*)$/;

/**
 * The five entries are, in order: credential ID, commitment, issue time,
 * expiry time, and issuer name. Times are Unix seconds represented as strings.
 * Both the issuer and verifier must call this function on the same five fields.
 */
export function encodeCredentialSigningBytes(fields) {
  if (!Array.isArray(fields) || fields.length !== FIELD_COUNT) {
    throw new TypeError('credential signing requires exactly five ordered fields');
  }

  const parts = [DOMAIN_TAG];
  for (const [index, value] of fields.entries()) {
    if (typeof value !== 'string' || !value.isWellFormed() || value.length === 0) {
      throw new TypeError(`credential field ${index} must be a nonempty UTF-8 string`);
    }
    if (index === 1 && !CANONICAL_DECIMAL.test(value)) {
      throw new TypeError('commitment must be a decimal string without leading zeros');
    }
    if ((index === 2 || index === 3) && !DECIMAL.test(value)) {
      throw new TypeError('credential times must be decimal Unix-second strings');
    }

    const bytes = Buffer.from(value, 'utf8');
    if (bytes.length > 0xffffffff) throw new RangeError('credential field exceeds four-byte length');
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    parts.push(length, bytes);
  }
  return Buffer.concat(parts);
}

export function signCredentialFields(fields, privateKey) {
  if (privateKey?.type !== 'private' || privateKey.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('credential signing requires an Ed25519 private key');
  }
  return sign(null, encodeCredentialSigningBytes(fields), privateKey);
}

export function verifyCredentialFields(fields, signature, publicKey) {
  if (publicKey?.type !== 'public' || publicKey.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('credential verification requires an Ed25519 public key');
  }
  if (!Buffer.isBuffer(signature) || signature.length !== 64) {
    throw new TypeError('Ed25519 signature must be 64 bytes');
  }
  return verify(null, encodeCredentialSigningBytes(fields), publicKey, signature);
}
