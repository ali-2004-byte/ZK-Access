import { parseIsoDate } from './calendar-date.mjs';
import { encodeBirthDate } from './issuer/birth-date.mjs';
import { BN254_FIELD_MODULUS } from './zk/field.mjs';

const MAX_BYTES = 4096;
const FIELD_NAMES = [
  'version', 'credentialId', 'birthDate', 'salt', 'commitment',
  'issuedAt', 'expiresAt', 'issuerName', 'signature',
];
const FIELD_SET = new Set(FIELD_NAMES);
const DECIMAL = /^[0-9]+$/;
const CANONICAL_DECIMAL = /^(0|[1-9][0-9]*)$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;

function parseFlatStringObject(text) {
  let offset = 0;
  const skipSpace = () => {
    while (offset < text.length && /[ \t\r\n]/.test(text[offset])) offset++;
  };
  const quotedString = () => {
    if (text[offset] !== '"') throw new SyntaxError('Expected a JSON string');
    const start = offset++;
    while (offset < text.length) {
      const code = text.charCodeAt(offset);
      if (code === 34) {
        const value = JSON.parse(text.slice(start, ++offset));
        if (!value.isWellFormed()) throw new SyntaxError('Invalid Unicode in JSON string');
        return value;
      }
      if (code < 32) throw new SyntaxError('Unescaped control character in JSON string');
      offset += code === 92 ? 2 : 1;
    }
    throw new SyntaxError('Unterminated JSON string');
  };

  skipSpace();
  if (text[offset++] !== '{') throw new SyntaxError('Credential must be a JSON object');
  const values = Object.create(null);
  skipSpace();
  if (text[offset] === '}') offset++;
  else {
    while (true) {
      const key = quotedString();
      if (Object.hasOwn(values, key)) throw new SyntaxError(`Duplicate credential field: ${key}`);
      skipSpace();
      if (text[offset++] !== ':') throw new SyntaxError('Expected colon after credential field');
      skipSpace();
      values[key] = quotedString();
      skipSpace();
      const separator = text[offset++];
      if (separator === '}') break;
      if (separator !== ',') throw new SyntaxError('Expected comma or closing brace');
      skipSpace();
    }
  }
  skipSpace();
  if (offset !== text.length) throw new SyntaxError('Unexpected data after credential object');
  return values;
}

export function decodeCredentialSignature(value) {
  if (typeof value !== 'string' || !BASE64URL.test(value)) {
    throw new TypeError('Signature must be unpadded base64url');
  }
  const padding = '='.repeat((4 - value.length % 4) % 4);
  let binary;
  try {
    binary = atob(value.replaceAll('-', '+').replaceAll('_', '/') + padding);
  } catch {
    throw new TypeError('Signature is not valid base64url');
  }
  if (binary.length !== 64 || btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '') !== value) {
    throw new TypeError('Signature must canonically encode exactly 64 bytes');
  }
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

/** Parse the private download in the operator browser, before proof generation. */
export function parsePrivateCredentialJson(text) {
  if (typeof text !== 'string' || !text.isWellFormed()) throw new TypeError('Credential must be UTF-8 JSON text');
  if (new TextEncoder().encode(text).length > MAX_BYTES) throw new RangeError('Credential exceeds 4 KB');

  const values = parseFlatStringObject(text);
  if (Object.keys(values).length !== FIELD_NAMES.length || Object.keys(values).some((key) => !FIELD_SET.has(key))) {
    throw new TypeError('Credential fields are missing or extra');
  }
  if (values.version !== '1') throw new TypeError('Unknown credential version');
  if (values.credentialId.length === 0 || values.issuerName !== 'ZK Access Demo Issuer') {
    throw new TypeError('Invalid credential identifier or issuer name');
  }
  parseIsoDate(values.birthDate);
  if (!DECIMAL.test(values.salt) || BigInt(values.salt) >= BN254_FIELD_MODULUS) {
    throw new TypeError('Salt must be a BN254 field element in decimal');
  }
  if (!CANONICAL_DECIMAL.test(values.commitment) || BigInt(values.commitment) >= BN254_FIELD_MODULUS) {
    throw new TypeError('Commitment must be a canonical BN254 field element');
  }
  if (!DECIMAL.test(values.issuedAt) || !DECIMAL.test(values.expiresAt)) {
    throw new TypeError('Credential times must be decimal Unix-second strings');
  }
  decodeCredentialSignature(values.signature);
  return Object.freeze(values);
}

/** Call in the operator browser after import, when assembling the private witness. */
export function birthDateNumberForProof(credential) {
  return encodeBirthDate(credential.birthDate);
}
