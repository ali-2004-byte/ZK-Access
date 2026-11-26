// Admin audit-log read handler; each read is itself audited.
import { createAuditEvent } from '../contracts/audit-event.mjs';

// Build the list handler over an audit store.
export function createAuditHandlers({ auditStore, audit, now = Date.now }) {
  return {
    async listAuditEvents(request, response) {
      const limit = Number(request.query.limit ?? 100);
      const events = auditStore.list({ limit: Number.isSafeInteger(limit) && limit > 0 && limit <= 500 ? limit : 100 });
      await audit(createAuditEvent({
        service: 'app', type: 'audit.viewed', actor: { kind: 'account', ...request.auth }, outcome: 'success',
        context: { rowCount: events.length }, occurredAt: now(),
      }));
      response.json({ events });
    },
  };
}
