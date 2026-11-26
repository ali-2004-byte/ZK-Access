// Login, logout, and current-session handlers shared by the app and issuer services.
import { randomBytes } from 'node:crypto';
import { createAuditEvent } from '../contracts/audit-event.mjs';
import { sendApiError } from '../contracts/error-codes.mjs';
import { hasExactKeys, strictJsonBody } from '../http/json-body.mjs';
import { activeLoginLockout, clearLoginFailures, recordLoginFailure } from './login-limiter.mjs';
import { hashPassword, verifyPassword } from './password.mjs';
import { normalizeUsername } from './username.mjs';

const LOGIN_BODY_BYTES = 1024;

// Build the three session handlers; unknown usernames still pay for one scrypt verification.
export function createAuthHandlers({ service, db, sessions, audit, hashIdentifier, now = Date.now }) {
  const findAccount = db.prepare(
    'SELECT id, password_record, role FROM accounts WHERE username_normalized = ? AND disabled = 0');
  const dummyRecord = hashPassword(randomBytes(24).toString('base64url'));

  // Append one audit event for this service.
  async function record(type, actor, outcome, code, context = {}) {
    await audit(createAuditEvent({ service, type, actor, outcome, code, context, occurredAt: now() }));
  }

  // Verify credentials, apply the persisted lockout, and rotate the session on success.
  async function loginHandler(request, response) {
    const body = request.jsonBody;
    let username;
    try {
      if (!hasExactKeys(body, ['username', 'password']) || typeof body.password !== 'string' ||
          body.password.length === 0 || !body.password.isWellFormed()) {
        throw new TypeError('Invalid login body');
      }
      username = normalizeUsername(body.username);
    } catch {
      sendApiError(response, 'MALFORMED_INPUT');
      return;
    }
    const ip = request.socket.remoteAddress ?? 'unknown';
    const nowUnix = Math.floor(now() / 1000);
    const context = { usernameHash: hashIdentifier('username', username), ipHash: hashIdentifier('ip', ip) };

    const lockedUntil = activeLoginLockout(db, ip, username, nowUnix);
    if (lockedUntil !== null) {
      await record('auth.login_locked', { kind: 'anonymous' }, 'denied', 'LOGIN_LOCKED',
        { ...context, lockoutSeconds: lockedUntil - nowUnix });
      response.set('Retry-After', String(lockedUntil - nowUnix));
      sendApiError(response, 'LOGIN_LOCKED');
      return;
    }

    const account = findAccount.get(username);
    const verified = account ? await verifyPassword(body.password, account.password_record) :
      (await verifyPassword(body.password, await dummyRecord)) && false;
    if (!verified) {
      const failure = recordLoginFailure(db, ip, username, nowUnix);
      await record('auth.login_failed', { kind: 'anonymous' }, 'failure', 'LOGIN_FAILED', context);
      if (failure.extended) {
        await record('auth.login_locked', { kind: 'anonymous' }, 'denied', 'LOGIN_LOCKED',
          { ...context, lockoutSeconds: failure.untilUnix - nowUnix });
      }
      sendApiError(response, 'LOGIN_FAILED');
      return;
    }

    clearLoginFailures(db, ip, username);
    const { csrfToken } = sessions.start(request, response, account.id);
    await record('auth.login_succeeded', { kind: 'account', accountId: account.id, role: account.role },
      'success', null, { ipHash: context.ipHash });
    response.json({ accountId: account.id, role: account.role, csrfToken });
  }

  // Delete the current session; the route guard has already checked the session and CSRF token.
  async function logout(request, response) {
    sessions.end(request, response);
    await record('auth.logout', { kind: 'account', ...request.auth }, 'success', null);
    response.status(204).end();
  }

  // Return who is signed in and the CSRF token the browser must echo on writes.
  async function currentSession(request, response) {
    const session = await sessions.resolve(request);
    response.json({ accountId: session.accountId, role: session.role, csrfToken: session.csrfToken });
  }

  return { login: [...strictJsonBody(LOGIN_BODY_BYTES), loginHandler], logout, currentSession };
}
