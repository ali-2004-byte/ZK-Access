// Strict query-string filters for result history, exports, and the audit log.
import { AUDIT_EVENT_TYPES } from '../contracts/audit-event.mjs';
import { REASON_CODES } from '../contracts/verification-result.mjs';

const TIMESTAMP = /^(0|[1-9][0-9]{0,15})$/;

// Read one optional single-valued query parameter; repeated or non-string values are malformed.
function single(query, key) {
  const value = query[key];
  if (value === undefined) return undefined;
  if (typeof value !== 'string') throw new TypeError(`Invalid ${key}`);
  return value;
}

// Parse optional from/to Unix-millisecond bounds.
function timeRange(query) {
  const range = {};
  for (const key of ['from', 'to']) {
    const value = single(query, key);
    if (value === undefined) continue;
    if (!TIMESTAMP.test(value) || !Number.isSafeInteger(Number(value))) throw new TypeError(`Invalid ${key}`);
    range[key] = Number(value);
  }
  if (range.from !== undefined && range.to !== undefined && range.from > range.to) throw new TypeError('Empty range');
  return range;
}

// Parse result filters: decision, reasonCode, from, and to; unknown keys are refused.
export function parseResultFilters(query, allowedExtra = []) {
  const known = ['decision', 'reasonCode', 'from', 'to', ...allowedExtra];
  if (Object.keys(query).some((key) => !known.includes(key))) throw new TypeError('Unknown filter');
  const filters = timeRange(query);
  const decision = single(query, 'decision');
  if (decision !== undefined) {
    if (decision !== 'allow' && decision !== 'deny') throw new TypeError('Invalid decision');
    filters.decision = decision;
  }
  const reasonCode = single(query, 'reasonCode');
  if (reasonCode !== undefined) {
    if (!Object.hasOwn(REASON_CODES, reasonCode)) throw new TypeError('Invalid reasonCode');
    filters.reasonCode = reasonCode;
  }
  return filters;
}

// Parse audit-log filters: type, from, to, and a limit of 1 to 500.
export function parseAuditFilters(query) {
  if (Object.keys(query).some((key) => !['type', 'from', 'to', 'limit'].includes(key))) throw new TypeError('Unknown filter');
  const filters = timeRange(query);
  const type = single(query, 'type');
  if (type !== undefined) {
    if (!AUDIT_EVENT_TYPES.app.has(type)) throw new TypeError('Invalid type');
    filters.type = type;
  }
  const limit = single(query, 'limit') ?? '100';
  if (!/^[1-9][0-9]{0,2}$/.test(limit) || Number(limit) > 500) throw new TypeError('Invalid limit');
  filters.limit = Number(limit);
  return filters;
}
