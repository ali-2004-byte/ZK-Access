// Error code, verification result, and audit event schema tests.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createAuditEvent } from '../src/contracts/audit-event.mjs';
import { API_ERRORS, sendApiError } from '../src/contracts/error-codes.mjs';
import {
  createVerificationResult,
  MEASUREMENT_FIELDS,
  projectResult,
  REASON_CODES,
  SANITIZED_RESULT_FIELDS,
} from '../src/contracts/verification-result.mjs';

const allowed = {
  resultId: 'result-1',
  decision: 'allow',
  reasonCode: 'PROOF_VALID',
  ruleName: 'age-at-least',
  ruleVersion: 1,
  nonceStatus: 'fresh',
  verifiedAt: 1794268800000,
  credentialId: 'synthetic-1',
  issuerName: 'ZK Access Demo Issuer',
  credentialExpiryStatus: 'valid',
  measurements: { proofSizeBytes: 805, proofGenerationMs: 1200, verificationMs: 14, decisionLatencyMs: 40 },
  actorAccountId: 'operator-1',
  engineVersion: 'age18-groth16-v1',
};

test('error codes map to fixed statuses and send only the code', () => {
  assert.equal(API_ERRORS.AUTH_DENIED, 403);
  assert.equal(API_ERRORS.AUTH_REQUIRED, 401);
  const sent = {};
  const response = {
    status(value) { sent.status = value; return this; },
    json(body) { sent.body = body; },
  };
  sendApiError(response, 'AUTH_DENIED');
  assert.deepEqual(sent, { status: 403, body: { code: 'AUTH_DENIED' } });
  assert.throws(() => sendApiError(response, 'Error: stack trace'), TypeError);
});

test('every reason code fixes its decision and challenge handling', () => {
  assert.equal(REASON_CODES.PROOF_VALID.decision, 'allow');
  for (const [code, reason] of Object.entries(REASON_CODES)) {
    if (code !== 'PROOF_VALID') assert.equal(reason.decision, 'deny', code);
  }
  assert.equal(REASON_CODES.ISSUER_UNAVAILABLE.consumesChallenge, false);
  assert.equal(REASON_CODES.ISSUER_UNAVAILABLE.httpStatus, 503);
  for (const code of ['SIGNATURE_INVALID', 'CREDENTIAL_REVOKED', 'CREDENTIAL_UNKNOWN', 'PROOF_INVALID', 'PROOF_VALID']) {
    assert.equal(REASON_CODES[code].consumesChallenge, true, code);
  }
});

test('stored results accept only agreed fields', () => {
  assert.equal(createVerificationResult(allowed).decision, 'allow');
  for (const leaked of ['commitment', 'signature', 'nonce', 'birthDate', 'salt', 'proof']) {
    assert.throws(() => createVerificationResult({ ...allowed, [leaked]: 'x' }), TypeError, leaked);
  }
  const { engineVersion: _omitted, ...missing } = allowed;
  assert.throws(() => createVerificationResult(missing), TypeError);
  assert.throws(() => createVerificationResult({ ...allowed, measurements: { ...allowed.measurements, raw: 1 } }));
});

test('decision, nonce status, and expiry status must agree with the reason code', () => {
  assert.throws(() => createVerificationResult({ ...allowed, decision: 'deny' }));
  assert.throws(() => createVerificationResult({ ...allowed, reasonCode: 'NOT_A_CODE' }));
  const replay = {
    ...allowed, decision: 'deny', reasonCode: 'CHALLENGE_REPLAYED', nonceStatus: 'replayed',
    credentialExpiryStatus: 'not_checked',
  };
  assert.equal(createVerificationResult(replay).nonceStatus, 'replayed');
  assert.throws(() => createVerificationResult({ ...replay, nonceStatus: 'fresh' }));
  assert.throws(() => createVerificationResult({ ...replay, credentialExpiryStatus: 'valid' }));
  const expired = { ...allowed, decision: 'deny', reasonCode: 'CREDENTIAL_EXPIRED', credentialExpiryStatus: 'expired' };
  assert.equal(createVerificationResult(expired).credentialExpiryStatus, 'expired');
  assert.throws(() => createVerificationResult({ ...expired, credentialExpiryStatus: 'valid' }));
});

test('viewer projection omits measurements and internal fields', () => {
  const result = createVerificationResult(allowed);
  const viewer = projectResult(result, 'viewer');
  assert.deepEqual(Object.keys(viewer), SANITIZED_RESULT_FIELDS);
  const operator = projectResult(result, 'operator');
  assert.deepEqual(Object.keys(operator), [...SANITIZED_RESULT_FIELDS, ...MEASUREMENT_FIELDS]);
  assert.equal(operator.proofSizeBytes, 805);
  for (const view of [viewer, operator, projectResult(result, 'admin')]) {
    assert.equal(Object.hasOwn(view, 'actorAccountId'), false);
    assert.equal(Object.hasOwn(view, 'engineVersion'), false);
  }
  assert.throws(() => projectResult(result, 'issuer_admin'), TypeError);
});

test('audit events allow only redacted context', () => {
  const event = createAuditEvent({
    service: 'app',
    type: 'authz.denied',
    actor: { kind: 'account', accountId: 'viewer-1', role: 'viewer' },
    outcome: 'denied',
    code: 'AUTH_DENIED',
    context: { action: 'export_report', method: 'GET', route: '/api/reports/export' },
    occurredAt: 1794268800000,
  });
  assert.equal(event.code, 'AUTH_DENIED');
  assert.match(event.eventId, /^[0-9a-f-]{36}$/);
  assert.equal(Object.isFrozen(event.context), true);

  const base = { service: 'app', type: 'auth.login_failed', actor: { kind: 'anonymous' }, outcome: 'failure', occurredAt: 1 };
  for (const key of ['username', 'password', 'birthDate', 'salt', 'commitment', 'signature', 'nonce', 'body', 'token']) {
    assert.throws(() => createAuditEvent({ ...base, context: { [key]: 'x' } }), TypeError, key);
  }
  assert.throws(() => createAuditEvent({ ...base, context: { route: '/api/results?id=1' } }), TypeError);
  assert.throws(() => createAuditEvent({ ...base, context: { usernameHash: 'alice' } }), TypeError);
  assert.ok(createAuditEvent({ ...base, code: 'LOGIN_FAILED', context: { usernameHash: 'a'.repeat(64) } }));
});

test('audit events are service-specific and codes are fixed', () => {
  const base = { actor: { kind: 'system' }, outcome: 'success', occurredAt: 1 };
  assert.throws(() => createAuditEvent({ ...base, service: 'issuer', type: 'verification.decided' }), TypeError);
  assert.throws(() => createAuditEvent({ ...base, service: 'app', type: 'credential.issued' }), TypeError);
  assert.throws(() => createAuditEvent({ ...base, service: 'app', type: 'retention.purged', code: 'free text' }));
  assert.throws(() => createAuditEvent({
    ...base, service: 'issuer', type: 'credential.revoked',
    actor: { kind: 'account', accountId: 'admin-1', role: 'admin' },
  }), TypeError);
  assert.ok(createAuditEvent({ ...base, service: 'app', type: 'verification.decided', code: 'CREDENTIAL_REVOKED' }));
});
