// HTTP authorization tests: every endpoint against every role, with audited generic denials.
import assert from 'node:assert/strict';
import { once } from 'node:events';
import test from 'node:test';
import { APP_ENDPOINTS } from '../src/app/endpoints.mjs';
import { createApp } from '../src/app/server.mjs';
import { createVerificationResult, MEASUREMENT_FIELDS } from '../src/contracts/verification-result.mjs';
import { ISSUER_ENDPOINTS } from '../src/issuer/endpoints.mjs';
import { createIssuer } from '../src/issuer/server.mjs';

const ALLOWED_APP_ROLES = {
  logout: ['admin', 'operator', 'viewer'],
  currentSession: ['admin', 'operator', 'viewer'],
  issueChallenge: ['operator'],
  submitVerification: ['operator'],
  listResults: ['admin', 'operator', 'viewer'],
  getResult: ['admin', 'operator', 'viewer'],
  exportReport: ['admin', 'operator'],
  getRules: ['admin'],
  updateRules: ['admin'],
  listAuditEvents: ['admin'],
  listUsers: ['admin'],
  createUser: ['admin'],
  updateUser: ['admin'],
};
const ALLOWED_ISSUER_ROLES = {
  logout: ['issuer_admin'],
  currentSession: ['issuer_admin'],
  issueCredential: ['issuer_admin'],
  revokeCredential: ['issuer_admin'],
  listUsers: ['issuer_admin'],
  createUser: ['issuer_admin'],
  updateUser: ['issuer_admin'],
};
const ALL_ROLES = ['admin', 'operator', 'viewer', 'issuer_admin'];

const storedResult = createVerificationResult({
  resultId: 'result-1',
  decision: 'allow',
  reasonCode: 'PROOF_VALID',
  ruleName: 'age-at-least',
  ruleVersion: 1,
  nonceStatus: 'fresh',
  verifiedAt: 1794268800000,
  credentialId: 'synthetic-1',
  issuerName: 'ZK Access Demo Issuer',
  credentialExpiryStatus: 'valid',
  measurements: { proofSizeBytes: 805, proofGenerationMs: 1200, verificationMs: 14, decisionLatencyMs: 40 },
  actorAccountId: 'operator-1',
  engineVersion: 'age18-groth16-v1',
});
const resultStore = {
  list: async () => [storedResult],
  get: async (id) => (id === storedResult.resultId ? storedResult : null),
};

// Test-only resolver: the role comes from a header standing in for a server-side session row.
function headerSession(request) {
  const role = request.get('x-test-role');
  return role ? { accountId: `${role}-1`.replace('_', '-'), role, csrfToken: 'test-csrf' } : null;
}

// Start a service on an ephemeral loopback port, run the callback, then close it.
async function withServer(app, run) {
  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    await run(`http://127.0.0.1:${server.address().port}`);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  }
}

// Send one request to a declared endpoint, filling path parameters with fixed IDs.
function call(origin, endpoint, role) {
  const path = endpoint.path.replace(':resultId', 'result-1').replace(':accountId', 'viewer-1')
    .replace(':credentialId', 'synthetic-1');
  const headers = role ? { 'x-test-role': role, 'x-csrf-token': 'test-csrf' } : {};
  return fetch(`${origin}${path}`, { method: endpoint.method, headers });
}

test('app endpoints follow the role matrix and audit every denial', async () => {
  const events = [];
  const app = createApp({ resolveSession: headerSession, audit: (event) => events.push(event), resultStore });
  await withServer(app, async (origin) => {
    for (const endpoint of APP_ENDPOINTS.filter((item) => !item.public)) {
      for (const role of ALL_ROLES) {
        const response = await call(origin, endpoint, role);
        const label = `${role} ${endpoint.method} ${endpoint.path}`;
        if (ALLOWED_APP_ROLES[endpoint.name].includes(role)) {
          assert.notEqual(response.status, 403, label);
          assert.notEqual(response.status, 401, label);
          await response.arrayBuffer();
          continue;
        }
        assert.equal(response.status, 403, label);
        assert.deepEqual(await response.json(), { code: 'AUTH_DENIED' }, label);
        const event = events.at(-1);
        assert.equal(event.type, 'authz.denied', label);
        assert.equal(event.code, 'AUTH_DENIED', label);
        assert.equal(event.outcome, 'denied', label);
        assert.equal(event.context.route, endpoint.path, label);
        assert.equal(event.context.action, endpoint.action ?? undefined, label);
      }
    }
  });
});

test('issuer endpoints admit only issuer admins', async () => {
  const events = [];
  const issuer = createIssuer({ resolveSession: headerSession, audit: (event) => events.push(event) });
  await withServer(issuer, async (origin) => {
    for (const endpoint of ISSUER_ENDPOINTS.filter((item) => !item.public)) {
      for (const role of ALL_ROLES) {
        const response = await call(origin, endpoint, role);
        const label = `${role} ${endpoint.method} ${endpoint.path}`;
        if (ALLOWED_ISSUER_ROLES[endpoint.name].includes(role)) {
          assert.equal(response.status, 501, label);
          await response.arrayBuffer();
          continue;
        }
        assert.equal(response.status, 403, label);
        assert.deepEqual(await response.json(), { code: 'AUTH_DENIED' }, label);
        assert.deepEqual(events.at(-1).actor, { kind: 'anonymous' }, label);
        assert.equal(events.at(-1).service, 'issuer', label);
      }
    }
  });
});

test('requests without a session get AUTH_REQUIRED and an anonymous audit', async () => {
  const events = [];
  const app = createApp({ resolveSession: headerSession, audit: (event) => events.push(event), resultStore });
  await withServer(app, async (origin) => {
    const response = await fetch(`${origin}/api/results`);
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { code: 'AUTH_REQUIRED' });
    assert.equal(events.length, 1);
    assert.deepEqual(events[0].actor, { kind: 'anonymous' });
    assert.equal(events[0].code, 'AUTH_REQUIRED');
  });
});

test('default services fail closed until sessions exist', async () => {
  const events = [];
  await withServer(createApp({ audit: (event) => events.push(event) }), async (origin) => {
    const response = await fetch(`${origin}/api/results`, { headers: { 'x-test-role': 'admin' } });
    assert.equal(response.status, 401);
    await response.arrayBuffer();
    const login = await fetch(`${origin}/api/session/login`, { method: 'POST' });
    assert.equal(login.status, 501);
    await login.arrayBuffer();
  });
  assert.equal(events.length, 1);
});

test('viewer reads sanitized results without timings; admin and operator see measurements', async () => {
  const app = createApp({ resolveSession: headerSession, audit: () => {}, resultStore });
  await withServer(app, async (origin) => {
    const viewer = await (await fetch(`${origin}/api/results`, { headers: { 'x-test-role': 'viewer' } })).json();
    assert.equal(viewer.results.length, 1);
    for (const field of [...MEASUREMENT_FIELDS, 'actorAccountId', 'engineVersion', 'measurements']) {
      assert.equal(Object.hasOwn(viewer.results[0], field), false, field);
    }
    for (const role of ['admin', 'operator']) {
      const view = await (await fetch(`${origin}/api/results/result-1`, { headers: { 'x-test-role': role } })).json();
      assert.equal(view.verificationMs, 14, role);
      assert.equal(Object.hasOwn(view, 'actorAccountId'), false, role);
    }
    const missing = await fetch(`${origin}/api/results/none`, { headers: { 'x-test-role': 'viewer' } });
    assert.equal(missing.status, 404);
    assert.deepEqual(await missing.json(), { code: 'NOT_FOUND' });
  });
});

test('denied requests never reach the handler, and audit failure still denies', async () => {
  let reached = false;
  const handlers = { exportReport: () => { reached = true; } };
  const failingAudit = () => { throw new Error('audit store offline'); };
  const app = createApp({ resolveSession: headerSession, audit: failingAudit, handlers });
  await withServer(app, async (origin) => {
    const response = await fetch(`${origin}/api/reports/export`, { headers: { 'x-test-role': 'viewer' } });
    assert.equal(response.status, 500);
    assert.deepEqual(await response.json(), { code: 'INTERNAL_ERROR' });
  });
  assert.equal(reached, false);
});

test('a session role from the other service is denied', async () => {
  const events = [];
  const app = createApp({ resolveSession: () => ({ accountId: 'issuer-1', role: 'issuer_admin' }), audit: (event) => events.push(event) });
  await withServer(app, async (origin) => {
    const response = await fetch(`${origin}/api/session`);
    assert.equal(response.status, 403);
    assert.deepEqual(await response.json(), { code: 'AUTH_DENIED' });
  });
  assert.deepEqual(events[0].actor, { kind: 'anonymous' });
});
