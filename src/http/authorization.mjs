// Server-side endpoint authorization that returns generic denials and audits each one.
import { createAuditEvent } from '../contracts/audit-event.mjs';
import { sendApiError } from '../contracts/error-codes.mjs';

const SERVICE_ROLES = Object.freeze({
  app: new Set(['admin', 'operator', 'viewer']),
  issuer: new Set(['issuer_admin']),
});

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
    await audit(createAuditEvent({
      service, type: 'authz.denied', actor, outcome: 'denied', code, context, occurredAt: now(),
    }));
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
