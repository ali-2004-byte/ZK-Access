import test from 'node:test';
import assert from 'node:assert/strict';
import { mayUseAppAction, mayUseIssuerAction } from '../src/app/access-policy.mjs';
import {
  DEFAULT_CHALLENGE_MS,
  SESSION_ABSOLUTE_MS,
  SESSION_IDLE_MS,
  sessionCanIssueChallenge,
  sessionExpiresAt,
  sessionIsActive,
} from '../src/app/session-policy.mjs';

test('app and issuer roles stay separate', () => {
  assert.equal(mayUseAppAction('admin', 'configure_rules'), true);
  assert.equal(mayUseAppAction('admin', 'submit_proof'), false);
  assert.equal(mayUseAppAction('operator', 'submit_proof'), true);
  assert.equal(mayUseAppAction('operator', 'review_audit'), false);
  assert.equal(mayUseAppAction('viewer', 'view_results'), true);
  assert.equal(mayUseAppAction('viewer', 'export_report'), false);
  assert.equal(mayUseAppAction('issuer_admin', 'view_results'), false);
  assert.equal(mayUseIssuerAction('issuer_admin', 'issue_credential'), true);
  assert.equal(mayUseIssuerAction('admin', 'issue_credential'), false);
  assert.equal(mayUseIssuerAction('issuer_admin', 'submit_proof'), false);
});

test('unknown roles and actions deny by default', () => {
  assert.equal(mayUseAppAction('unknown', 'view_results'), false);
  assert.equal(mayUseAppAction('operator', 'unknown'), false);
  assert.equal(mayUseIssuerAction('unknown', 'issue_credential'), false);
});

test('session expires after 30 minutes of inactivity', () => {
  const session = { createdAt: 0, lastActivityAt: 0 };
  assert.equal(sessionExpiresAt(session), SESSION_IDLE_MS);
  assert.equal(sessionIsActive(session, SESSION_IDLE_MS - 1), true);
  assert.equal(sessionIsActive(session, SESSION_IDLE_MS), false);
});

test('absolute eight-hour lifetime limits active sessions', () => {
  const session = { createdAt: 0, lastActivityAt: SESSION_ABSOLUTE_MS - 60_000 };
  assert.equal(sessionExpiresAt(session), SESSION_ABSOLUTE_MS);
  assert.equal(sessionIsActive(session, SESSION_ABSOLUTE_MS), false);
});

test('challenge issuance stops before remaining session time is too short', () => {
  const session = { createdAt: 0, lastActivityAt: 0 };
  assert.equal(sessionCanIssueChallenge(session, 0), true);
  assert.equal(sessionCanIssueChallenge(session, SESSION_IDLE_MS - DEFAULT_CHALLENGE_MS), true);
  assert.equal(sessionCanIssueChallenge(session, SESSION_IDLE_MS), false);
  const nearAbsoluteEnd = { createdAt: 0, lastActivityAt: SESSION_ABSOLUTE_MS - 10 * 60_000 };
  assert.equal(sessionCanIssueChallenge(nearAbsoluteEnd, SESSION_ABSOLUTE_MS - DEFAULT_CHALLENGE_MS), false);
});

test('invalid session timestamps fail closed', () => {
  assert.throws(() => sessionExpiresAt({ createdAt: 10, lastActivityAt: 9 }));
  assert.throws(() => sessionIsActive({ createdAt: 0, lastActivityAt: 0 }, -1));
  assert.throws(() => sessionCanIssueChallenge({ createdAt: 0, lastActivityAt: 0 }, 0, 0));
});
