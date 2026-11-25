// Append-only audit event schema with allowlisted, redacted context.
import { randomUUID } from 'node:crypto';
import { isApiErrorCode } from './error-codes.mjs';
import { REASON_CODES } from './verification-result.mjs';

const SHARED_TYPES = [
  'auth.login_succeeded', 'auth.login_failed', 'auth.login_locked', 'auth.logout', 'auth.session_expired',
  'authz.denied', 'csrf.rejected', 'users.created', 'users.updated', 'retention.purged',
];

export const AUDIT_EVENT_TYPES = Object.freeze({
  app: new Set([
    ...SHARED_TYPES,
    'rules.changed', 'audit.viewed', 'challenge.issued', 'verification.rejected',
    'verification.decided', 'report.exported',
  ]),
  issuer: new Set([...SHARED_TYPES, 'credential.issued', 'credential.revoked', 'credential.issue_rejected']),
});

const OUTCOMES = new Set(['success', 'denied', 'failure']);
const ACCOUNT_ROLES = { app: new Set(['admin', 'operator', 'viewer']), issuer: new Set(['issuer_admin']) };
const OPAQUE_ID = /^[A-Za-z0-9_-]{1,64}$/;
const HEX_DIGEST = /^[0-9a-f]{64}$/;
const SAFE_TEXT = /^[\x20-\x7e]{0,128}$/;

const CONTEXT_FIELDS = Object.freeze({
  action: (value) => typeof value === 'string' && /^[a-z_]{1,48}$/.test(value),
  method: (value) => ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(value),
  route: (value) => typeof value === 'string' && /^\/[A-Za-z0-9_\-/:]{0,127}$/.test(value),
  role: (value) => typeof value === 'string' && /^[a-z_]{1,32}$/.test(value),
  targetAccountId: (value) => typeof value === 'string' && OPAQUE_ID.test(value),
  usernameHash: (value) => typeof value === 'string' && HEX_DIGEST.test(value),
  ipHash: (value) => typeof value === 'string' && HEX_DIGEST.test(value),
  lockoutSeconds: (value) => Number.isSafeInteger(value) && value >= 0,
  challengeId: (value) => typeof value === 'string' && OPAQUE_ID.test(value),
  resultId: (value) => typeof value === 'string' && OPAQUE_ID.test(value),
  credentialId: (value) => typeof value === 'string' && OPAQUE_ID.test(value),
  ruleName: (value) => typeof value === 'string' && /^[a-z0-9][a-z0-9-]{0,47}$/.test(value),
  ruleVersion: (value) => Number.isSafeInteger(value) && value >= 1,
  previousRuleVersion: (value) => Number.isSafeInteger(value) && value >= 1,
  confirmed: (value) => typeof value === 'boolean',
  format: (value) => value === 'csv' || value === 'json',
  rowCount: (value) => Number.isSafeInteger(value) && value >= 0,
  table: (value) => typeof value === 'string' && /^[a-z_]{1,32}$/.test(value),
  note: (value) => typeof value === 'string' && SAFE_TEXT.test(value),
});

// True for object literals and null-prototype objects only.
function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

// Validate the actor and return a frozen copy.
function validateActor(actor, service) {
  if (!isPlainObject(actor)) throw new TypeError('Audit actor must be an object');
  const keys = Object.keys(actor);
  if (actor.kind === 'account') {
    if (keys.length !== 3 || typeof actor.accountId !== 'string' || !OPAQUE_ID.test(actor.accountId) ||
        !ACCOUNT_ROLES[service].has(actor.role)) {
      throw new TypeError('Invalid audit account actor');
    }
    return Object.freeze({ kind: 'account', accountId: actor.accountId, role: actor.role });
  }
  if (['anonymous', 'system', 'service'].includes(actor.kind) && keys.length === 1) {
    return Object.freeze({ kind: actor.kind });
  }
  throw new TypeError('Invalid audit actor');
}

// Reject context keys outside the allowlist and invalid values.
function validateContext(context) {
  if (!isPlainObject(context)) throw new TypeError('Audit context must be an object');
  for (const [key, value] of Object.entries(context)) {
    if (!Object.hasOwn(CONTEXT_FIELDS, key)) throw new TypeError(`Audit context key not allowed: ${key}`);
    if (!CONTEXT_FIELDS[key](value)) throw new TypeError(`Invalid audit context value: ${key}`);
  }
  return Object.freeze({ ...context });
}

// Build one validated audit event; code is an API or reason code, or null.
export function createAuditEvent({
  service, type, actor, outcome, code = null, context = {}, occurredAt, eventId = randomUUID(),
}) {
  if (!Object.hasOwn(AUDIT_EVENT_TYPES, service)) throw new TypeError('Unknown audit service');
  if (!AUDIT_EVENT_TYPES[service].has(type)) throw new TypeError('Unknown audit event type for service');
  if (!OUTCOMES.has(outcome)) throw new TypeError('Invalid audit outcome');
  if (code !== null && !isApiErrorCode(code) && !Object.hasOwn(REASON_CODES, code)) {
    throw new TypeError('Unknown audit code');
  }
  if (!Number.isSafeInteger(occurredAt) || occurredAt < 0) throw new TypeError('occurredAt must be Unix milliseconds');
  if (typeof eventId !== 'string' || !OPAQUE_ID.test(eventId)) throw new TypeError('Invalid audit eventId');
  return Object.freeze({
    eventId,
    service,
    type,
    occurredAt,
    actor: validateActor(actor, service),
    outcome,
    code,
    context: validateContext(context),
  });
}
