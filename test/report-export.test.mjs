// Result filter, sanitized export, and audit-log filter tests over real HTTP.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import { EXPORT_COLUMNS } from '../src/app/result-handlers.mjs';
import { createApp } from '../src/app/server.mjs';
import { createVerificationResult } from '../src/contracts/verification-result.mjs';
import { createAppRecords } from '../src/db/app-records.mjs';
import { openServiceDatabase } from '../src/db/service-database.mjs';
import { addAccount, browser, withServer } from './http-helpers.mjs';

const identifierKey = randomBytes(32);
const PASSWORD = 'synthetic-demo-password';
const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.UTC(2026, 10, 20);

// A stored result with the given reason, time, and credential ID.
function result(resultId, reasonCode, verifiedAt, credentialId = 'synthetic-1') {
  const allowed = reasonCode === 'PROOF_VALID';
  return createVerificationResult({
    resultId, decision: allowed ? 'allow' : 'deny', reasonCode, ruleName: 'age-at-least-18', ruleVersion: 1,
    nonceStatus: reasonCode === 'CHALLENGE_REPLAYED' ? 'replayed' : 'fresh', verifiedAt, credentialId,
    issuerName: 'ZK Access Demo Issuer',
    credentialExpiryStatus: reasonCode === 'CHALLENGE_REPLAYED' ? 'not_checked' : 'valid',
    measurements: { proofSizeBytes: 805, proofGenerationMs: 900, verificationMs: allowed ? 12 : null, decisionLatencyMs: 30 },
    actorAccountId: 'operator-1', engineVersion: 'age18-groth16-v1',
  });
}

// Seeded app with three results, three roles, and signed-in browsers for each.
async function withSeededApp(run) {
  const db = openServiceDatabase('app', { file: ':memory:' });
  await addAccount(db, 'admin-1', 'admin1', PASSWORD, 'admin');
  await addAccount(db, 'operator-1', 'operator1', PASSWORD, 'operator');
  await addAccount(db, 'viewer-1', 'viewer1', PASSWORD, 'viewer');
  const records = createAppRecords(db);
  records.insertResult('c1', result('r-old', 'PROOF_VALID', NOW - 3 * DAY));
  records.insertResult('c2', result('r-deny', 'PROOF_INVALID', NOW - DAY, '-formula'));
  records.insertResult('c3', result('r-replay', 'CHALLENGE_REPLAYED', NOW));
  await withServer(createApp({ db, identifierKey, now: () => NOW }), async (origin) => {
    const users = {};
    for (const name of ['admin1', 'operator1', 'viewer1']) {
      users[name] = browser(origin);
      await users[name].login(name, PASSWORD);
    }
    await run({ db, origin, ...users });
  });
}

// Fetch a route with a browser's cookie and return status, headers, and raw text.
async function raw(client, route) {
  const response = await fetch(`${client.origin}${route}`, { headers: { cookie: client.cookie } });
  return { status: response.status, headers: response.headers, text: await response.text() };
}

test('result history filters by decision, reason, and time, and rejects bad filters', async () => {
  await withSeededApp(async ({ viewer1 }) => {
    const ids = async (query) => (await viewer1.request('GET', `/api/results${query}`)).json.results.map((row) => row.resultId);
    assert.deepEqual(await ids(''), ['r-replay', 'r-deny', 'r-old']);
    assert.deepEqual(await ids('?decision=allow'), ['r-old']);
    assert.deepEqual(await ids('?reasonCode=PROOF_INVALID'), ['r-deny']);
    assert.deepEqual(await ids(`?from=${NOW - 2 * DAY}&to=${NOW - 1}`), ['r-deny']);
    for (const query of ['?decision=maybe', '?reasonCode=DROP', '?from=-1', `?from=${NOW}&to=1`, '?decision=allow&decision=deny', '?sort=x']) {
      assert.deepEqual((await viewer1.request('GET', `/api/results${query}`)).json, { code: 'MALFORMED_INPUT' }, query);
    }
  });
});

test('operator CSV export is sanitized, neutralizes formulas, and is audited', async () => {
  await withSeededApp(async ({ db, origin, operator1 }) => {
    const response = await raw({ ...operator1, origin }, '/api/reports/export?format=csv&decision=deny');
    assert.equal(response.status, 200);
    assert.match(response.headers.get('content-type'), /^text\/csv/);
    assert.equal(response.headers.get('content-disposition'), 'attachment; filename=zk-access-report-2026-11-20.csv');
    assert.equal(response.headers.get('cache-control'), 'no-store');
    const lines = response.text.trimEnd().split('\r\n');
    assert.equal(lines[0], EXPORT_COLUMNS.join(','));
    assert.equal(lines.length, 3);
    assert.ok(lines.some((line) => line.includes(",'-formula,")));
    assert.equal(/actorAccountId|operator-1|age18-groth16|commitment|signature/.test(response.text), false);

    const event = db.prepare("SELECT actor_account_id, context_json FROM audit_events WHERE type = 'report.exported'").get();
    assert.equal(event.actor_account_id, 'operator-1');
    assert.deepEqual(JSON.parse(event.context_json), { format: 'csv', rowCount: 2 });
  });
});

test('admin JSON export carries measurements; viewer export is denied and audited', async () => {
  await withSeededApp(async ({ db, admin1, viewer1 }) => {
    const report = await admin1.request('GET', '/api/reports/export?format=json');
    assert.deepEqual(report.json.columns, EXPORT_COLUMNS);
    assert.equal(report.json.results.length, 3);
    assert.equal(report.json.results.find((row) => row.resultId === 'r-old').verificationMs, 12);
    assert.deepEqual((await admin1.request('GET', '/api/reports/export?format=xml')).json, { code: 'MALFORMED_INPUT' });

    assert.deepEqual((await viewer1.request('GET', '/api/reports/export?format=csv')).json, { code: 'AUTH_DENIED' });
    const denied = db.prepare("SELECT actor_role, code FROM audit_events WHERE type = 'authz.denied'").get();
    assert.deepEqual({ ...denied }, { actor_role: 'viewer', code: 'AUTH_DENIED' });
  });
});

test('admin filters the audit log by type and time', async () => {
  await withSeededApp(async ({ admin1, operator1 }) => {
    await operator1.request('GET', '/api/reports/export');
    const exports = await admin1.request('GET', '/api/audit-events?type=report.exported');
    assert.deepEqual(exports.json.events.map((event) => event.type), ['report.exported']);
    const limited = await admin1.request('GET', '/api/audit-events?limit=2');
    assert.equal(limited.json.events.length, 2);
    for (const query of ['?type=nope', '?limit=0', '?limit=501', '?user=x']) {
      assert.deepEqual((await admin1.request('GET', `/api/audit-events${query}`)).json, { code: 'MALFORMED_INPUT' }, query);
    }
  });
});
