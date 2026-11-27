// Scheduled D9 retention purge for both services; each run writes one audit event per table.
import { SESSION_ABSOLUTE_MS, SESSION_IDLE_MS } from '../app/session-policy.mjs';
import { createAuditEvent } from '../contracts/audit-event.mjs';

const DAY_MS = 24 * 60 * 60 * 1000;
export const RETENTION = Object.freeze({
  resultsMs: 90 * DAY_MS,
  auditMs: 90 * DAY_MS,
  challengeAfterExpiryMs: 7 * DAY_MS,
  issuerRecordAfterExpiryMs: 90 * DAY_MS,
});
export const PURGE_INTERVAL_MS = 60 * 60 * 1000;

// Delete statements per service, each paired with the table name its audit event reports.
function purgeStatements(db, service) {
  const shared = [
    ['audit_events', db.prepare('DELETE FROM audit_events WHERE occurred_at_ms < ?'), (now) => now - RETENTION.auditMs],
    ['sessions', db.prepare('DELETE FROM sessions WHERE last_activity_ms <= ? OR created_at_ms <= ?'),
      (now) => [now - SESSION_IDLE_MS, now - SESSION_ABSOLUTE_MS]],
  ];
  if (service === 'app') {
    return [
      ['verification_results', db.prepare('DELETE FROM verification_results WHERE verified_at_ms < ?'),
        (now) => now - RETENTION.resultsMs],
      ['challenges', db.prepare('DELETE FROM challenges WHERE expires_at_ms < ?'),
        (now) => now - RETENTION.challengeAfterExpiryMs],
      ...shared,
    ];
  }
  return [
    ['credentials', db.prepare('DELETE FROM credentials WHERE expires_at_unix < ?'),
      (now) => Math.floor((now - RETENTION.issuerRecordAfterExpiryMs) / 1000)],
    ...shared,
  ];
}

// Run one purge in a single transaction and return the deleted row count per table.
export function purgeExpiredRecords({ db, service, audit, now = Date.now }) {
  const time = now();
  const statements = purgeStatements(db, service);
  const counts = {};
  db.exec('BEGIN IMMEDIATE');
  try {
    db.prepare('INSERT INTO retention_guard (audit_cutoff_ms) VALUES (?)').run(time - RETENTION.auditMs);
    for (const [table, statement, cutoff] of statements) {
      const bound = cutoff(time);
      counts[table] = Number(statement.run(...(Array.isArray(bound) ? bound : [bound])).changes);
    }
    db.exec('DELETE FROM retention_guard');
    for (const [table, rowCount] of Object.entries(counts)) {
      audit(createAuditEvent({
        service, type: 'retention.purged', actor: { kind: 'system' }, outcome: 'success',
        context: { table, rowCount }, occurredAt: time,
      }));
    }
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
  return counts;
}

// Purge now and then every interval; the timer does not keep the process alive.
export function startRetentionSchedule({ db, service, audit, now = Date.now, intervalMs = PURGE_INTERVAL_MS }) {
  const run = () => {
    try {
      purgeExpiredRecords({ db, service, audit, now });
    } catch (error) {
      process.stderr.write(`Retention purge failed: ${error.message}\n`);
    }
  };
  run();
  const timer = setInterval(run, intervalMs);
  timer.unref();
  return () => clearInterval(timer);
}
