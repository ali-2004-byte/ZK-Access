// Verification result schema, reason codes, and role-based result projections.
const ISSUER_NAME = 'ZK Access Demo Issuer';

export const REASON_CODES = Object.freeze({
  PROOF_VALID: Object.freeze({ decision: 'allow', consumesChallenge: true, httpStatus: 200 }),
  PROOF_INVALID: Object.freeze({ decision: 'deny', consumesChallenge: true, httpStatus: 200 }),
  SIGNALS_MISMATCH: Object.freeze({ decision: 'deny', consumesChallenge: true, httpStatus: 200 }),
  SIGNATURE_INVALID: Object.freeze({ decision: 'deny', consumesChallenge: true, httpStatus: 200 }),
  CREDENTIAL_EXPIRED: Object.freeze({ decision: 'deny', consumesChallenge: true, httpStatus: 200 }),
  CREDENTIAL_REVOKED: Object.freeze({ decision: 'deny', consumesChallenge: true, httpStatus: 200 }),
  CREDENTIAL_UNKNOWN: Object.freeze({ decision: 'deny', consumesChallenge: true, httpStatus: 200 }),
  ISSUER_UNAVAILABLE: Object.freeze({ decision: 'deny', consumesChallenge: false, httpStatus: 503 }),
  CHALLENGE_REPLAYED: Object.freeze({ decision: 'deny', consumesChallenge: false, httpStatus: 200 }),
  CHALLENGE_EXPIRED: Object.freeze({ decision: 'deny', consumesChallenge: false, httpStatus: 200 }),
});

const NONCE_STATUS_BY_REASON = Object.freeze({
  CHALLENGE_REPLAYED: 'replayed',
  CHALLENGE_EXPIRED: 'expired',
});

const EXPIRY_STATUSES = new Set(['valid', 'expired', 'not_checked']);
const EXPIRY_NOT_CHECKED = new Set(['SIGNALS_MISMATCH', 'SIGNATURE_INVALID', 'CHALLENGE_REPLAYED', 'CHALLENGE_EXPIRED']);

export const SANITIZED_RESULT_FIELDS = Object.freeze([
  'resultId', 'decision', 'reasonCode', 'ruleName', 'ruleVersion', 'nonceStatus',
  'verifiedAt', 'credentialId', 'issuerName', 'credentialExpiryStatus',
]);
export const MEASUREMENT_FIELDS = Object.freeze([
  'proofSizeBytes', 'proofGenerationMs', 'verificationMs', 'decisionLatencyMs',
]);
export const INTERNAL_RESULT_FIELDS = Object.freeze(['actorAccountId', 'engineVersion']);

const STORED_FIELDS = [...SANITIZED_RESULT_FIELDS, 'measurements', ...INTERNAL_RESULT_FIELDS];
const OPAQUE_ID = /^[A-Za-z0-9_-]{1,64}$/;
const RULE_NAME = /^[a-z0-9][a-z0-9-]{0,47}$/;
const ENGINE_VERSION = /^[a-z0-9][a-z0-9.-]{0,47}$/;

// True for object literals and null-prototype objects only.
function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

// Throw unless the object has exactly the listed keys.
function requireExactKeys(value, keys, label) {
  if (!isPlainObject(value) || Object.keys(value).length !== keys.length ||
      !keys.every((key) => Object.hasOwn(value, key))) {
    throw new TypeError(`${label} must have exactly the agreed fields`);
  }
}

// Throw unless the value is a nonnegative safe integer (or null when allowed).
function requireNonnegativeInteger(value, label, { nullable = false } = {}) {
  if (nullable && value === null) return;
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${label} must be a nonnegative integer`);
}

// Validate the proof size and timing fields.
function validateMeasurements(measurements) {
  requireExactKeys(measurements, MEASUREMENT_FIELDS, 'measurements');
  requireNonnegativeInteger(measurements.proofSizeBytes, 'proofSizeBytes', { nullable: true });
  requireNonnegativeInteger(measurements.proofGenerationMs, 'proofGenerationMs', { nullable: true });
  requireNonnegativeInteger(measurements.verificationMs, 'verificationMs', { nullable: true });
  requireNonnegativeInteger(measurements.decisionLatencyMs, 'decisionLatencyMs');
}

// Build the stored result, rejecting extra fields so leaks fail where they start.
export function createVerificationResult(input) {
  requireExactKeys(input, STORED_FIELDS, 'Verification result');
  const reason = Object.hasOwn(REASON_CODES, input.reasonCode) ? REASON_CODES[input.reasonCode] : null;
  if (!reason) throw new TypeError('Unknown verification reason code');
  if (input.decision !== reason.decision) throw new TypeError('Decision does not match reason code');
  if (typeof input.resultId !== 'string' || !OPAQUE_ID.test(input.resultId)) throw new TypeError('Invalid resultId');
  if (typeof input.credentialId !== 'string' || !OPAQUE_ID.test(input.credentialId)) {
    throw new TypeError('Invalid credentialId');
  }
  if (typeof input.actorAccountId !== 'string' || !OPAQUE_ID.test(input.actorAccountId)) {
    throw new TypeError('Invalid actorAccountId');
  }
  if (typeof input.ruleName !== 'string' || !RULE_NAME.test(input.ruleName)) throw new TypeError('Invalid ruleName');
  if (!Number.isSafeInteger(input.ruleVersion) || input.ruleVersion < 1) throw new TypeError('Invalid ruleVersion');
  if (typeof input.engineVersion !== 'string' || !ENGINE_VERSION.test(input.engineVersion)) {
    throw new TypeError('Invalid engineVersion');
  }
  requireNonnegativeInteger(input.verifiedAt, 'verifiedAt');
  if (input.issuerName !== ISSUER_NAME) throw new TypeError('Unexpected issuer name');

  const expectedNonce = NONCE_STATUS_BY_REASON[input.reasonCode] ?? 'fresh';
  if (input.nonceStatus !== expectedNonce) throw new TypeError('Nonce status does not match reason code');

  const expiry = input.credentialExpiryStatus;
  if (!EXPIRY_STATUSES.has(expiry)) throw new TypeError('Invalid credential expiry status');
  if (EXPIRY_NOT_CHECKED.has(input.reasonCode) ? expiry !== 'not_checked' :
    expiry !== (input.reasonCode === 'CREDENTIAL_EXPIRED' ? 'expired' : 'valid')) {
    throw new TypeError('Credential expiry status does not match reason code');
  }

  validateMeasurements(input.measurements);
  return Object.freeze({ ...input, measurements: Object.freeze({ ...input.measurements }) });
}

// Project a result for a role; only admin and operator see measurements.
export function projectResult(result, role) {
  if (role !== 'admin' && role !== 'operator' && role !== 'viewer') {
    throw new TypeError('Role may not view verification results');
  }
  const view = {};
  for (const field of SANITIZED_RESULT_FIELDS) view[field] = result[field];
  if (role !== 'viewer') {
    for (const field of MEASUREMENT_FIELDS) view[field] = result.measurements[field];
  }
  return view;
}
