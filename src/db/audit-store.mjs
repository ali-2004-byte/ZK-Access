// Append-only SQLite audit table shared in shape by the app and issuer databases.
const COLUMNS = 'event_id, service, type, occurred_at_ms, actor_kind, actor_account_id, actor_role, outcome, code, context_json';

// Create the audit table and block in-place edits; only the retention purge may delete rows.
export function initializeAuditSchema(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS audit_events (
    event_id TEXT PRIMARY KEY,
    service TEXT NOT NULL CHECK (service IN ('app', 'issuer')),
    type TEXT NOT NULL,
    occurred_at_ms INTEGER NOT NULL,
    actor_kind TEXT NOT NULL CHECK (actor_kind IN ('account', 'anonymous', 'system', 'service')),
    actor_account_id TEXT,
    actor_role TEXT,
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'denied', 'failure')),
    code TEXT,
    context_json TEXT NOT NULL
  ) STRICT`);
  db.exec('CREATE INDEX IF NOT EXISTS audit_events_time ON audit_events (occurred_at_ms)');
  db.exec(`CREATE TRIGGER IF NOT EXISTS audit_events_append_only BEFORE UPDATE ON audit_events
    BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END`);
  // The purge inserts a guard row holding its cutoff; deletes outside that window are refused.
  db.exec('CREATE TABLE IF NOT EXISTS retention_guard (audit_cutoff_ms INTEGER NOT NULL) STRICT');
  db.exec(`CREATE TRIGGER IF NOT EXISTS audit_events_retention_only BEFORE DELETE ON audit_events
    WHEN NOT EXISTS (SELECT 1 FROM retention_guard WHERE OLD.occurred_at_ms < audit_cutoff_ms)
    BEGIN SELECT RAISE(ABORT, 'audit events are deleted only by the retention purge'); END`);
}

// Convert a stored row back into the audit event shape.
function rowToEvent(row) {
  const actor = row.actor_kind === 'account' ?
    { kind: 'account', accountId: row.actor_account_id, role: row.actor_role } : { kind: row.actor_kind };
  return {
    eventId: row.event_id,
    service: row.service,
    type: row.type,
    occurredAt: row.occurred_at_ms,
    actor,
    outcome: row.outcome,
    code: row.code,
    context: JSON.parse(row.context_json),
  };
}

// Store events built by createAuditEvent and read them newest first.
export function createAuditStore(db) {
  const insert = db.prepare(`INSERT INTO audit_events (${COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  const recent = db.prepare(`SELECT ${COLUMNS} FROM audit_events ORDER BY occurred_at_ms DESC, rowid DESC LIMIT ?`);
  return {
    append(event) {
      insert.run(event.eventId, event.service, event.type, event.occurredAt, event.actor.kind,
        event.actor.accountId ?? null, event.actor.role ?? null, event.outcome, event.code,
        JSON.stringify(event.context));
    },
    list({ limit = 100 } = {}) {
      return recent.all(limit).map(rowToEvent);
    },
  };
}
