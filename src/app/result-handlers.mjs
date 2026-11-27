// Result history and sanitized report export, always through the caller's role projection.
import { createAuditEvent } from '../contracts/audit-event.mjs';
import { sendApiError } from '../contracts/error-codes.mjs';
import { MEASUREMENT_FIELDS, projectResult, SANITIZED_RESULT_FIELDS } from '../contracts/verification-result.mjs';
import { parseResultFilters } from '../http/query-filters.mjs';

export const EXPORT_COLUMNS = Object.freeze([...SANITIZED_RESULT_FIELDS, ...MEASUREMENT_FIELDS]);
const EXPORT_ROW_LIMIT = 10_000;

// Quote one CSV cell and neutralize leading characters spreadsheets would treat as formulas.
function csvCell(value) {
  if (value === null || value === undefined) return '';
  let text = String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

// Render projected rows as CSV with a fixed header.
export function toCsv(rows) {
  const lines = [EXPORT_COLUMNS.join(',')];
  for (const row of rows) lines.push(EXPORT_COLUMNS.map((column) => csvCell(row[column])).join(','));
  return `${lines.join('\r\n')}\r\n`;
}

// Build list, detail, and export handlers over an injected result store.
export function createResultHandlers({ resultStore, audit, now = Date.now }) {
  // Parse filters or send MALFORMED_INPUT and return null.
  function filtersOrReject(request, response, extra) {
    try {
      return parseResultFilters(request.query, extra);
    } catch {
      sendApiError(response, 'MALFORMED_INPUT');
      return null;
    }
  }

  return {
    async listResults(request, response) {
      const filters = filtersOrReject(request, response);
      if (!filters) return;
      const results = await resultStore.list(filters, 500);
      response.json({ results: results.map((result) => projectResult(result, request.auth.role)) });
    },
    async getResult(request, response) {
      const result = await resultStore.get(request.params.resultId);
      if (!result) {
        sendApiError(response, 'NOT_FOUND');
        return;
      }
      response.json(projectResult(result, request.auth.role));
    },
    // Admin/operator export with reason codes and measurements; the route guard already refused viewers.
    async exportReport(request, response) {
      const filters = filtersOrReject(request, response, ['format']);
      if (!filters) return;
      const format = request.query.format ?? 'json';
      if (format !== 'json' && format !== 'csv') {
        sendApiError(response, 'MALFORMED_INPUT');
        return;
      }
      const time = now();
      const rows = (await resultStore.list(filters, EXPORT_ROW_LIMIT)).map((result) => projectResult(result, request.auth.role));
      await audit(createAuditEvent({
        service: 'app', type: 'report.exported', actor: { kind: 'account', ...request.auth }, outcome: 'success',
        context: { format, rowCount: rows.length }, occurredAt: time,
      }));
      const stamp = new Date(time).toISOString().slice(0, 10);
      response.set('Cache-Control', 'no-store');
      response.attachment(`zk-access-report-${stamp}.${format}`);
      if (format === 'csv') {
        response.type('text/csv; charset=utf-8').send(toCsv(rows));
        return;
      }
      response.json({ generatedAt: time, filters, columns: EXPORT_COLUMNS, results: rows });
    },
  };
}
