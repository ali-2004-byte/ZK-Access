// Retention purge tests: D9 windows, audit-logged runs, and audit rows deletable only by the purge.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createAuditEvent } from '../src/contracts/audit-event.mjs';
import { createAuditStore } from '../src/db/audit-store.mjs';
import { purgeExpiredRecords, RETENTION, startRetentionSchedule } from '../src/db/retention.mjs';
import { openServiceDatabase } from '../src/db/service-database.mjs';

const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.UTC(2027, 2, 1);

// Insert one account so session and credential foreign keys resolve.
function addAccount(db, id, role) {
  db.prepare("INSERT INTO accounts (id, username_normalized, password_record, role, created_at_unix) VALUES (?, ?, 'x', ?, 1)")
    .run(id, id, role);
}

// Append an audit event at a given time through the normal store.
function auditAt(store, service, occurredAt) {
  store.append(createAuditEvent({ service, type: 'auth.logout', actor: { kind: 'system' }, outcome: 'success', occurredAt }));
}

// Insert a minimal result row verified at the given time.
function resultAt(db, id, verifiedAt) {
  db.prepare(`INSERT INTO verification_results VALUES (?, 'c', 'deny', 'PROOF_INVALID', 'age-at-least-18', 1, 'fresh',
    ?, 'cred', 'ZK Access Demo Issuer', 'valid', 1, NULL, 1, 1, 'operator-1', 'age18-groth16-v1')`).run(id, verifiedAt);
}

// Insert a challenge row expiring at the given time.
function challengeAt(db, id, expiresAt) {
  db.prepare(`INSERT INTO challenges VALUES (?, 'h', 'operator-1', 'cred', '7', 20081109, 'age-at-least-18', 1, ?, ?, 'used')`)
    .run(id, expiresAt - 300_000, expiresAt);
}

test('app purge applies each retention window and audits every table', () => {
  const db = openServiceDatabase('app', { file: ':memory:' });
  const store = createAuditStore(db);
  addAccount(db, 'operator-1', 'operator');
  resultAt(db, 'old-result', NOW - RETENTION.resultsMs - 1);
  resultAt(db, 'kept-result', NOW - RETENTION.resultsMs + 1);
  challengeAt(db, 'old-challenge', NOW - RETENTION.challengeAfterExpiryMs - 1);
  challengeAt(db, 'kept-challenge', NOW - RETENTION.challengeAfterExpiryMs + 1);
  auditAt(store, 'app', NOW - RETENTION.auditMs - 1);
  auditAt(store, 'app', NOW - RETENTION.auditMs + 1);
  db.prepare("INSERT INTO sessions VALUES ('stale', 'operator-1', 't', ?, ?)").run(NOW - DAY, NOW - DAY);
  db.prepare("INSERT INTO sessions VALUES ('live', 'operator-1', 't', ?, ?)").run(NOW - 60_000, NOW - 60_000);

  const counts = purgeExpiredRecords({ db, service: 'app', audit: store.append, now: () => NOW });
  assert.deepEqual(counts, { verification_results: 1, challenges: 1, audit_events: 1, sessions: 1 });
  assert.deepEqual(db.prepare('SELECT result_id FROM verification_results').all().map((row) => row.result_id), ['kept-result']);
  assert.deepEqual(db.prepare('SELECT challenge_id FROM challenges').all().map((row) => row.challenge_id), ['kept-challenge']);
  assert.deepEqual(db.prepare('SELECT id_hash FROM sessions').all().map((row) => row.id_hash), ['live']);

  const purged = db.prepare("SELECT actor_kind, context_json FROM audit_events WHERE type = 'retention.purged'").all();
  assert.equal(purged.length, 4);
  assert.ok(purged.every((row) => row.actor_kind === 'system'));
  assert.deepEqual(JSON.parse(purged[0].context_json), { table: 'verification_results', rowCount: 1 });
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM retention_guard').get().n, 0);
});

test('audit rows cannot be deleted outside the purge, even when old', () => {
  const db = openServiceDatabase('app', { file: ':memory:' });
  const store = createAuditStore(db);
  auditAt(store, 'app', NOW - RETENTION.auditMs - DAY);
  assert.throws(() => db.exec('DELETE FROM audit_events'), /retention purge/);
  db.prepare('INSERT INTO retention_guard VALUES (?)').run(NOW - RETENTION.auditMs - 2 * DAY);
  assert.throws(() => db.exec('DELETE FROM audit_events'), /retention purge/);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM audit_events').get().n, 1);
});

test('issuer purge removes records 90 days after credential expiry', () => {
  const db = openServiceDatabase('issuer', { file: ':memory:' });
  addAccount(db, 'issuer-admin-1', 'issuer_admin');
  const insert = db.prepare("INSERT INTO credentials VALUES (?, '1', 's', ?, ?, 'issuer-admin-1', 'active')");
  const cutoffUnix = Math.floor((NOW - RETENTION.issuerRecordAfterExpiryMs) / 1000);
  insert.run('old', cutoffUnix - 100, cutoffUnix - 1);
  insert.run('kept', cutoffUnix - 100, cutoffUnix + 1);
  const store = createAuditStore(db);
  const counts = purgeExpiredRecords({ db, service: 'issuer', audit: store.append, now: () => NOW });
  assert.equal(counts.credentials, 1);
  assert.deepEqual(db.prepare('SELECT credential_id FROM credentials').all().map((row) => row.credential_id), ['kept']);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM audit_events WHERE type = 'retention.purged'").get().n, 3);
});

test('the schedule purges at start and keeps running until stopped', () => {
  const db = openServiceDatabase('app', { file: ':memory:' });
  const store = createAuditStore(db);
  const stop = startRetentionSchedule({ db, service: 'app', audit: store.append, now: () => NOW, intervalMs: 60_000 });
  stop();
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM audit_events WHERE type = 'retention.purged'").get().n, 4);
});
