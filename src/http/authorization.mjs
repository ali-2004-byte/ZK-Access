// Server-side endpoint authorization and CSRF checks that return generic denials and audit each one.
import { timingSafeEqual } from 'node:crypto';
import { createAuditEvent } from '../contracts/audit-event.mjs';
import { sendApiError } from '../contracts/error-codes.mjs';

const SAFE_METHODS = new Set(['GET', 'HEAD']);
const SERVICE_ROLES = Object.freeze({
  app: new Set(['admin', 'operator', 'viewer']),
  issuer: new Set(['issuer_admin']),
});

// Constant-time comparison of the submitted CSRF header with the session's token.
function csrfMatches(submitted, expected) {
  if (typeof submitted !== 'string' || typeof expected !== 'string') return false;
  const a = Buffer.from(submitted);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

// Build a guard factory for one service; roles come only from the resolved server-side session.
export function createAuthorizer({ service, mayUse, resolveSession, audit, now = Date.now }) {
  if (!Object.hasOwn(SERVICE_ROLES, service) || typeof mayUse !== 'function' ||
      typeof resolveSession !== 'function' || typeof audit !== 'function' || typeof now !== 'function') {
    throw new TypeError('Authorizer requires service, mayUse, resolveSession, audit, and now');
  }

  // Record one denial and send its generic code.
  async function deny(response, code, session, context) {
    const known = session && SERVICE_ROLES[service].has(session.role);
    const actor = known ? { kind: 'account', accountId: session.accountId, role: session.role } : { kind: 'anonymous' };
    const type = code === 'CSRF_INVALID' ? 'csrf.rejected' : 'authz.denied';
    await audit(createAuditEvent({ service, type, actor, outcome: 'denied', code, context, occurredAt: now() }));
    sendApiError(response, code);
  }

  // Middleware for one endpoint; a null action admits any signed-in account of this service.
  return function requireAction(action, { method, route }) {
    const context = action === null ? { method, route } : { action, method, route };
    return async (request, response, next) => {
      const session = await resolveSession(request);
      if (!session) {
        await deny(response, 'AUTH_REQUIRED', null, context);
        return;
      }
      const allowed = SERVICE_ROLES[service].has(session.role) &&
        (action === null || mayUse(session.role, action));
      if (!allowed) {
        await deny(response, 'AUTH_DENIED', session, context);
        return;
      }
      if (!SAFE_METHODS.has(request.method) && !csrfMatches(request.get('x-csrf-token'), session.csrfToken)) {
        await deny(response, 'CSRF_INVALID', session, context);
        return;
      }
      request.auth = Object.freeze({ accountId: session.accountId, role: session.role });
      next();
    };
  };
}

// Session resolver used until cookie sessions exist; every guarded route fails closed.
export function noSession() {
  return null;
}

// Interim audit sink that writes redacted events as JSON lines until audit storage exists.
export function writeAuditToStdout(event) {
  process.stdout.write(`${JSON.stringify(event)}\n`);
}
