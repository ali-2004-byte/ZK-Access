// Admin rule configuration tests: confirmation, versioning, audit trace, and effect on new challenges only.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { ageCutoffForUtcDate } from '../src/age-policy.mjs';
import { createApp } from '../src/app/server.mjs';
import { createAppRecords } from '../src/db/app-records.mjs';
import { openServiceDatabase } from '../src/db/service-database.mjs';
import { addAccount, browser, withServer } from './http-helpers.mjs';

const identifierKey = randomBytes(32);
const PASSWORD = 'synthetic-demo-password';
const NOW = Date.UTC(2026, 10, 9, 12);

// App with an admin and an operator signed in.
async function withAdminAndOperator(run) {
  const db = openServiceDatabase('app', { file: ':memory:' });
  await addAccount(db, 'admin-1', 'admin1', PASSWORD, 'admin');
  await addAccount(db, 'operator-1', 'operator1', PASSWORD, 'operator');
  await withServer(createApp({ db, identifierKey, now: () => NOW }), async (origin) => {
    const admin = browser(origin);
    await admin.login('admin1', PASSWORD);
    const operator = browser(origin);
    await operator.login('operator1', PASSWORD);
    await run({ db, admin, operator });
  });
}

// Rules-change audit rows as parsed objects, oldest first.
function ruleEvents(db) {
  return db.prepare("SELECT outcome, code, context_json FROM audit_events WHERE type = 'rules.changed' ORDER BY rowid").all()
    .map((row) => ({ outcome: row.outcome, code: row.code, ...JSON.parse(row.context_json) }));
}

test('the cutoff follows the configured minimum age with the same leap-day rule', () => {
  assert.equal(ageCutoffForUtcDate('2026-11-09', 21), '2005-11-09');
  assert.equal(ageCutoffForUtcDate('2024-02-29', 21), '2003-02-28');
  assert.throws(() => ageCutoffForUtcDate('2026-11-09', 0));
});

test('admin reads and raises the rule; operators cannot configure it', async () => {
  await withAdminAndOperator(async ({ db, admin, operator }) => {
    assert.deepEqual((await admin.request('GET', '/api/rules')).json,
      { ruleName: 'age-at-least-18', ruleVersion: 1, minimumAge: 18, challengeLifetimeSeconds: 300, updatedAt: 0 });
    assert.deepEqual((await operator.request('GET', '/api/rules')).json, { code: 'AUTH_DENIED' });
    assert.deepEqual((await operator.request('PUT', '/api/rules', { minimumAge: 21, challengeLifetimeSeconds: 300, confirm: true })).json,
      { code: 'AUTH_DENIED' });

    const raised = await admin.request('PUT', '/api/rules', { minimumAge: 21, challengeLifetimeSeconds: 120, confirm: false });
    assert.deepEqual(raised.json,
      { ruleName: 'age-at-least-21', ruleVersion: 2, minimumAge: 21, challengeLifetimeSeconds: 120, updatedAt: NOW });
    assert.deepEqual(ruleEvents(db), [{
      outcome: 'success', code: null, ruleName: 'age-at-least-21', ruleVersion: 2, previousRuleVersion: 1,
      confirmed: false, note: 'minimumAge=21 challengeLifetimeSeconds=120',
    }]);
  });
});

test('lowering the age or lengthening challenges requires confirmation', async () => {
  await withAdminAndOperator(async ({ db, admin }) => {
    for (const change of [{ minimumAge: 16, challengeLifetimeSeconds: 300 }, { minimumAge: 18, challengeLifetimeSeconds: 600 }]) {
      const refused = await admin.request('PUT', '/api/rules', { ...change, confirm: false });
      assert.equal(refused.status, 409);
      assert.deepEqual(refused.json, { code: 'CONFIRMATION_REQUIRED' });
    }
    assert.equal((await admin.request('GET', '/api/rules')).json.ruleVersion, 1);
    const confirmed = await admin.request('PUT', '/api/rules', { minimumAge: 16, challengeLifetimeSeconds: 300, confirm: true });
    assert.equal(confirmed.json.ruleName, 'age-at-least-16');
    assert.deepEqual(ruleEvents(db).map((event) => [event.outcome, event.code, event.confirmed]),
      [['denied', 'CONFIRMATION_REQUIRED', false], ['denied', 'CONFIRMATION_REQUIRED', false], ['success', null, true]]);

    for (const bad of [{ minimumAge: 12 }, { challengeLifetimeSeconds: 901 }, { confirm: 'yes' }, { extra: 1 }]) {
      const response = await admin.request('PUT', '/api/rules', { minimumAge: 18, challengeLifetimeSeconds: 300, confirm: true, ...bad });
      assert.deepEqual(response.json, { code: 'MALFORMED_INPUT' }, JSON.stringify(bad));
    }
    const unchanged = await admin.request('PUT', '/api/rules', { minimumAge: 16, challengeLifetimeSeconds: 300, confirm: false });
    assert.equal(unchanged.json.ruleVersion, 2);
  });
});

test('a rule change applies to new challenges and leaves issued ones untouched', async () => {
  await withAdminAndOperator(async ({ db, admin, operator }) => {
    const before = await operator.request('POST', '/api/challenges', { credentialId: 'synthetic-1' });
    assert.equal(before.json.cutoff, '20081109');
    await admin.request('PUT', '/api/rules', { minimumAge: 21, challengeLifetimeSeconds: 120, confirm: false });
    const after = await operator.request('POST', '/api/challenges', { credentialId: 'synthetic-1' });
    assert.equal(after.json.cutoff, '20051109');
    assert.equal(after.json.expiresAt, NOW + 120_000);
    const rows = db.prepare('SELECT cutoff, rule_name, rule_version FROM challenges ORDER BY rowid').all().map((row) => ({ ...row }));
    assert.deepEqual(rows, [
      { cutoff: 20081109, rule_name: 'age-at-least-18', rule_version: 1 },
      { cutoff: 20051109, rule_name: 'age-at-least-21', rule_version: 2 },
    ]);
  });
});

test('an older rules table gains the minimum-age column on open', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'zk-access-rules-'));
  const file = path.join(dir, 'app.sqlite');
  try {
    const old = new DatabaseSync(file);
    old.exec(`CREATE TABLE rules (name TEXT PRIMARY KEY, version INTEGER NOT NULL CHECK (version >= 1),
      challenge_lifetime_seconds INTEGER NOT NULL CHECK (challenge_lifetime_seconds BETWEEN 30 AND 1800),
      updated_at_ms INTEGER NOT NULL) STRICT`);
    old.exec("INSERT INTO rules VALUES ('age-at-least-18', 3, 300, 5)");
    old.close();
    const db = openServiceDatabase('app', { file });
    const rule = createAppRecords(db).activeRule();
    assert.equal(rule.minimumAge, 18);
    assert.equal(rule.version, 3);
    db.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
