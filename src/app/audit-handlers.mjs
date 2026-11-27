// Admin audit-log read handler; each read is itself audited.
import { createAuditEvent } from '../contracts/audit-event.mjs';
import { sendApiError } from '../contracts/error-codes.mjs';
import { parseAuditFilters } from '../http/query-filters.mjs';

// Build the list handler over an audit store.
export function createAuditHandlers({ auditStore, audit, now = Date.now }) {
  return {
    async listAuditEvents(request, response) {
      let filters;
      try {
        filters = parseAuditFilters(request.query);
      } catch {
        sendApiError(response, 'MALFORMED_INPUT');
        return;
      }
      const events = auditStore.list(filters);
      await audit(createAuditEvent({
        service: 'app', type: 'audit.viewed', actor: { kind: 'account', ...request.auth }, outcome: 'success',
        context: { rowCount: events.length }, occurredAt: now(),
      }));
      response.json({ events });
    },
  };
}
