// Persistent cookie sessions with login rotation, idle/absolute expiry, and per-session CSRF tokens.
import { createHash, randomBytes } from 'node:crypto';
import { SESSION_ABSOLUTE_MS, SESSION_IDLE_MS, sessionIsActive } from '../app/session-policy.mjs';
import { createAuditEvent } from '../contracts/audit-event.mjs';

export const SESSION_COOKIE_NAMES = Object.freeze({ app: 'zk_app_session', issuer: 'zk_issuer_session' });
const SESSION_ID = /^[A-Za-z0-9_-]{43}$/;
const RESOLVED = Symbol('resolvedSession');
const COOKIE_OPTIONS = Object.freeze({ httpOnly: true, sameSite: 'strict', path: '/' });

// SHA-256 of the cookie value, so a database copy cannot be replayed as a cookie.
function hashSessionId(sessionId) {
  return createHash('sha256').update(sessionId).digest('hex');
}

// Read one cookie value from the raw Cookie header without a parser dependency.
function readCookie(header, name) {
  if (typeof header !== 'string') return null;
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index > 0 && part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return null;
}

// Build the session manager for one service database; the cookie name differs per service.
export function createSessionManager({ db, service, audit, now = Date.now }) {
  const cookieName = SESSION_COOKIE_NAMES[service];
  if (!cookieName) throw new TypeError('Unknown session service');
  const select = db.prepare(`SELECT s.id_hash, s.account_id, s.csrf_token, s.created_at_ms, s.last_activity_ms,
    a.role, a.disabled FROM sessions s JOIN accounts a ON a.id = s.account_id WHERE s.id_hash = ?`);
  const touch = db.prepare('UPDATE sessions SET last_activity_ms = ? WHERE id_hash = ?');
  const insert = db.prepare(`INSERT INTO sessions (id_hash, account_id, csrf_token, created_at_ms, last_activity_ms)
    VALUES (?, ?, ?, ?, ?)`);
  const remove = db.prepare('DELETE FROM sessions WHERE id_hash = ?');
  const removeAccount = db.prepare('DELETE FROM sessions WHERE account_id = ?');
  const removeExpired = db.prepare('DELETE FROM sessions WHERE last_activity_ms <= ? OR created_at_ms <= ?');

  // Hash of the request's well-formed session cookie, or null.
  function cookieHash(request) {
    const value = readCookie(request.get('cookie'), cookieName);
    return value && SESSION_ID.test(value) ? hashSessionId(value) : null;
  }

  // Resolve and touch the request's session; expired or disabled sessions are deleted.
  async function resolve(request) {
    if (Object.hasOwn(request, RESOLVED)) return request[RESOLVED];
    request[RESOLVED] = null;
    const idHash = cookieHash(request);
    const row = idHash ? select.get(idHash) : undefined;
    if (!row) return null;
    const time = now();
    const lifetime = { createdAt: row.created_at_ms, lastActivityAt: row.last_activity_ms };
    if (row.disabled === 1 || !sessionIsActive(lifetime, time)) {
      remove.run(idHash);
      if (row.disabled === 0) {
        await audit(createAuditEvent({
          service, type: 'auth.session_expired', outcome: 'success', occurredAt: time,
          actor: { kind: 'account', accountId: row.account_id, role: row.role },
        }));
      }
      return null;
    }
    touch.run(time, idHash);
    request[RESOLVED] = Object.freeze({
      idHash, accountId: row.account_id, role: row.role, csrfToken: row.csrf_token,
      createdAt: row.created_at_ms, lastActivityAt: time,
    });
    return request[RESOLVED];
  }

  // Start a fresh session for a verified login, deleting any session the request already carried.
  function start(request, response, accountId) {
    const time = now();
    const previous = cookieHash(request);
    if (previous) remove.run(previous);
    removeExpired.run(time - SESSION_IDLE_MS, time - SESSION_ABSOLUTE_MS);
    const sessionId = randomBytes(32).toString('base64url');
    const csrfToken = randomBytes(32).toString('base64url');
    insert.run(hashSessionId(sessionId), accountId, csrfToken, time, time);
    response.cookie(cookieName, sessionId, COOKIE_OPTIONS);
    return { csrfToken };
  }

  // Delete the request's session row and clear its cookie.
  function end(request, response) {
    const idHash = cookieHash(request);
    if (idHash) remove.run(idHash);
    response.clearCookie(cookieName, COOKIE_OPTIONS);
  }

  // Sign an account out everywhere, used after it is disabled or its role changes.
  function endAllForAccount(accountId) {
    removeAccount.run(accountId);
  }

  return { cookieName, resolve, start, end, endAllForAccount };
}
