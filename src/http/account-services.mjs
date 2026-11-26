// Wires audit storage, sessions, login, and user management onto one service database.
import { createAuthHandlers } from '../auth/auth-handlers.mjs';
import { createIdentifierHasher } from '../auth/identifier-hash.mjs';
import { createSessionManager } from '../auth/session-manager.mjs';
import { createUserHandlers } from '../auth/user-handlers.mjs';
import { createAuditStore } from '../db/audit-store.mjs';

// Return the session resolver, audit sink, and account handlers for a service.
export function createAccountServices({ service, db, identifierKey, audit, now = Date.now }) {
  const auditStore = createAuditStore(db);
  const sink = audit ?? auditStore.append;
  const sessions = createSessionManager({ db, service, audit: sink, now });
  const shared = { service, db, sessions, audit: sink, now };
  return {
    auditStore,
    audit: sink,
    sessions,
    resolveSession: sessions.resolve,
    handlers: {
      ...createAuthHandlers({ ...shared, hashIdentifier: createIdentifierHasher(identifierKey) }),
      ...createUserHandlers(shared),
    },
  };
}
