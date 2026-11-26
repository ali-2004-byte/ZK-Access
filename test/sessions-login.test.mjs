// Login, cookie session, CSRF, lockout, user management, and audit-log tests over real HTTP.
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createApp } from '../src/app/server.mjs';
import { SESSION_ABSOLUTE_MS, SESSION_IDLE_MS } from '../src/app/session-policy.mjs';
import { openServiceDatabase } from '../src/db/service-database.mjs';
import { createIssuer } from '../src/issuer/server.mjs';
import { addAccount, browser, withServer } from './http-helpers.mjs';

const identifierKey = randomBytes(32);
const ADMIN_PASSWORD = 'synthetic-admin-password';
const OPERATOR_PASSWORD = 'synthetic-operator-password';

// Fresh in-memory app database with one admin and one operator.
async function seededAppDb(file = ':memory:') {
  const db = openServiceDatabase('app', { file });
  await addAccount(db, 'admin-1', 'admin1', ADMIN_PASSWORD, 'admin');
  await addAccount(db, 'operator-1', 'operator1', OPERATOR_PASSWORD, 'operator');
  return db;
}

test('login sets a hardened cookie, stores only its hash, and returns a CSRF token', async () => {
  const db = await seededAppDb();
  await withServer(createApp({ db, identifierKey }), async (origin) => {
    const operator = browser(origin);
    const login = await operator.login('  Operator1 ', OPERATOR_PASSWORD);
    assert.equal(login.status, 200);
    assert.equal(login.json.role, 'operator');
    assert.match(operator.setCookie, /^zk_app_session=[A-Za-z0-9_-]{43}; Path=\/; HttpOnly; SameSite=Strict$/);
    const cookieValue = operator.cookie.split('=')[1];
    const row = db.prepare('SELECT id_hash FROM sessions').get();
    assert.equal(row.id_hash, createHash('sha256').update(cookieValue).digest('hex'));

    const session = await operator.request('GET', '/api/session');
    assert.deepEqual(session.json, { accountId: 'operator-1', role: 'operator', csrfToken: login.json.csrfToken });
  });
});

test('wrong password and unknown username fail identically and audit only keyed hashes', async () => {
  const db = await seededAppDb();
  await withServer(createApp({ db, identifierKey }), async (origin) => {
    const wrong = await browser(origin).login('operator1', 'not-the-password');
    const unknown = await browser(origin).login('nobody', 'not-the-password');
    assert.equal(wrong.status, 401);
    assert.deepEqual(wrong.json, unknown.json);
    assert.deepEqual(wrong.json, { code: 'LOGIN_FAILED' });
    const bad = await browser(origin).login('a b', 'x');
    assert.deepEqual(bad.json, { code: 'MALFORMED_INPUT' });
  });
  const contexts = db.prepare("SELECT context_json FROM audit_events WHERE type = 'auth.login_failed'").all();
  assert.equal(contexts.length, 2);
  for (const { context_json: context } of contexts) {
    assert.equal(/operator1|nobody|password|127\.0\.0\.1/.test(context), false);
    assert.match(JSON.parse(context).usernameHash, /^[0-9a-f]{64}$/);
  }
});

test('login rotates the session and rejects non-JSON bodies', async () => {
  const db = await seededAppDb();
  await withServer(createApp({ db, identifierKey }), async (origin) => {
    const operator = browser(origin);
    await operator.login('operator1', OPERATOR_PASSWORD);
    const firstCookie = operator.cookie;
    await operator.login('operator1', OPERATOR_PASSWORD);
    assert.notEqual(operator.cookie, firstCookie);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM sessions').get().n, 1);
    const stale = await fetch(`${origin}/api/session`, { headers: { cookie: firstCookie } });
    assert.equal(stale.status, 401);

    const form = await browser(origin).request('POST', '/api/session/login', 'username=operator1',
      { contentType: 'application/x-www-form-urlencoded' });
    assert.deepEqual(form.json, { code: 'UNSUPPORTED_MEDIA_TYPE' });
  });
});

test('logout needs the CSRF token and deletes the session row', async () => {
  const db = await seededAppDb();
  await withServer(createApp({ db, identifierKey }), async (origin) => {
    const operator = browser(origin);
    await operator.login('operator1', OPERATOR_PASSWORD);
    const forged = await operator.request('POST', '/api/session/logout', undefined, { csrf: false });
    assert.equal(forged.status, 403);
    assert.deepEqual(forged.json, { code: 'CSRF_INVALID' });
    const rejected = db.prepare("SELECT actor_account_id, code FROM audit_events WHERE type = 'csrf.rejected'").get();
    assert.deepEqual({ ...rejected }, { actor_account_id: 'operator-1', code: 'CSRF_INVALID' });

    const sessionCookie = operator.cookie;
    assert.equal((await operator.request('POST', '/api/session/logout')).status, 204);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM sessions').get().n, 0);
    const after = await fetch(`${origin}/api/session`, { headers: { cookie: sessionCookie } });
    assert.equal(after.status, 401);
  });
});

test('sessions expire after 30 idle minutes or eight hours in total', async () => {
  let clock = 1_800_000_000_000;
  const db = await seededAppDb();
  await withServer(createApp({ db, identifierKey, now: () => clock }), async (origin) => {
    const idle = browser(origin);
    await idle.login('operator1', OPERATOR_PASSWORD);
    clock += SESSION_IDLE_MS - 1;
    assert.equal((await idle.request('GET', '/api/session')).status, 200);
    clock += SESSION_IDLE_MS;
    assert.equal((await idle.request('GET', '/api/session')).status, 401);
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM audit_events WHERE type = 'auth.session_expired'").get().n, 1);

    const busy = browser(origin);
    await busy.login('operator1', OPERATOR_PASSWORD);
    const started = clock;
    while (clock + 20 * 60_000 < started + SESSION_ABSOLUTE_MS) {
      clock += 20 * 60_000;
      assert.equal((await busy.request('GET', '/api/session')).status, 200);
    }
    clock = started + SESSION_ABSOLUTE_MS;
    assert.equal((await busy.request('GET', '/api/session')).status, 401);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM sessions').get().n, 0);
  });
});

test('sessions survive a service restart on the same database file', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'zk-access-session-'));
  const file = path.join(dir, 'app.sqlite');
  try {
    const first = await seededAppDb(file);
    let cookie;
    await withServer(createApp({ db: first, identifierKey }), async (origin) => {
      const operator = browser(origin);
      await operator.login('operator1', OPERATOR_PASSWORD);
      cookie = operator.cookie;
    });
    first.close();
    const second = openServiceDatabase('app', { file });
    await withServer(createApp({ db: second, identifierKey }), async (origin) => {
      const response = await fetch(`${origin}/api/session`, { headers: { cookie } });
      assert.equal(response.status, 200);
      assert.equal((await response.json()).accountId, 'operator-1');
    });
    second.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('five failures lock login for a minute without extending it, and success clears the count', async () => {
  let clock = 1_800_000_000_000;
  const db = await seededAppDb();
  await withServer(createApp({ db, identifierKey, now: () => clock }), async (origin) => {
    for (let attempt = 0; attempt < 5; attempt++) {
      assert.equal((await browser(origin).login('operator1', 'wrong-password-x')).status, 401);
    }
    const locked = await browser(origin).login('operator1', OPERATOR_PASSWORD);
    assert.equal(locked.status, 429);
    assert.deepEqual(locked.json, { code: 'LOGIN_LOCKED' });
    assert.equal(locked.headers.get('retry-after'), '60');
    clock += 30_000;
    assert.equal((await browser(origin).login('operator1', OPERATOR_PASSWORD)).headers.get('retry-after'), '30');
    clock += 31_000;
    assert.equal((await browser(origin).login('operator1', OPERATOR_PASSWORD)).status, 200);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM login_limits').get().n, 0);
  });
  const locks = db.prepare("SELECT COUNT(*) AS n FROM audit_events WHERE type = 'auth.login_locked'").get().n;
  assert.equal(locks, 3);
});

test('app admin manages operator and viewer accounts; changes end the target sessions', async () => {
  const db = await seededAppDb();
  await withServer(createApp({ db, identifierKey }), async (origin) => {
    const admin = browser(origin);
    await admin.login('admin1', ADMIN_PASSWORD);
    const created = await admin.request('POST', '/api/users',
      { username: 'Viewer1', password: 'synthetic-viewer-password', role: 'viewer' });
    assert.equal(created.status, 201);
    assert.equal(created.json.username, 'viewer1');
    assert.equal(Object.hasOwn(created.json, 'password_record'), false);
    const duplicate = await admin.request('POST', '/api/users',
      { username: 'viewer1', password: 'synthetic-viewer-password', role: 'viewer' });
    assert.deepEqual(duplicate.json, { code: 'CONFLICT' });
    const adminRole = await admin.request('POST', '/api/users',
      { username: 'admin2', password: 'synthetic-admin-password', role: 'admin' });
    assert.deepEqual(adminRole.json, { code: 'MALFORMED_INPUT' });

    const viewer = browser(origin);
    assert.equal((await viewer.login('viewer1', 'synthetic-viewer-password')).status, 200);
    assert.deepEqual((await viewer.request('GET', '/api/users')).json, { code: 'AUTH_DENIED' });

    const disabled = await admin.request('PATCH', `/api/users/${created.json.accountId}`, { disabled: true });
    assert.equal(disabled.json.disabled, true);
    assert.equal((await viewer.request('GET', '/api/session')).status, 401);
    assert.deepEqual((await viewer.login('viewer1', 'synthetic-viewer-password')).json, { code: 'LOGIN_FAILED' });

    const self = await admin.request('PATCH', '/api/users/admin-1', { disabled: true });
    assert.equal(self.status, 404);
    const listed = await admin.request('GET', '/api/users');
    assert.deepEqual(listed.json.users.map((user) => user.username), ['admin1', 'operator1', 'viewer1']);
  });
});

test('admin reads the audit log, the read is audited, and audit rows cannot be edited', async () => {
  const db = await seededAppDb();
  await withServer(createApp({ db, identifierKey }), async (origin) => {
    const admin = browser(origin);
    await admin.login('admin1', ADMIN_PASSWORD);
    const operator = browser(origin);
    await operator.login('operator1', OPERATOR_PASSWORD);
    assert.deepEqual((await operator.request('GET', '/api/audit-events')).json, { code: 'AUTH_DENIED' });
    const log = await admin.request('GET', '/api/audit-events');
    assert.deepEqual(log.json.events.map((event) => event.type).slice(0, 3),
      ['authz.denied', 'auth.login_succeeded', 'auth.login_succeeded']);
    assert.equal(log.json.events[0].actor.accountId, 'operator-1');
  });
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM audit_events WHERE type = 'audit.viewed'").get().n, 1);
  assert.throws(() => db.exec("UPDATE audit_events SET outcome = 'success'"), /append-only/);
});

test('issuer login is separate: app accounts cannot sign in and cookie names differ', async () => {
  const appDb = await seededAppDb();
  const issuerDb = openServiceDatabase('issuer', { file: ':memory:' });
  await addAccount(issuerDb, 'issuer-admin-1', 'issuer1', ADMIN_PASSWORD, 'issuer_admin');
  await withServer(createIssuer({ db: issuerDb, identifierKey }), async (origin) => {
    assert.deepEqual((await browser(origin).login('admin1', ADMIN_PASSWORD)).json, { code: 'LOGIN_FAILED' });
    const issuerAdmin = browser(origin);
    const login = await issuerAdmin.login('issuer1', ADMIN_PASSWORD);
    assert.equal(login.json.role, 'issuer_admin');
    assert.match(issuerAdmin.setCookie, /^zk_issuer_session=/);
    const created = await issuerAdmin.request('POST', '/api/users',
      { username: 'issuer2', password: 'synthetic-issuer-password', role: 'issuer_admin' });
    assert.equal(created.status, 201);
    const appRole = await issuerAdmin.request('POST', '/api/users',
      { username: 'operator9', password: 'synthetic-issuer-password', role: 'operator' });
    assert.deepEqual(appRole.json, { code: 'MALFORMED_INPUT' });
  });
  assert.equal(appDb.prepare("SELECT COUNT(*) AS n FROM accounts WHERE username_normalized = 'issuer2'").get().n, 0);
});
