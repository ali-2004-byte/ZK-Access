import assert from 'node:assert/strict';
import { once } from 'node:events';
import test from 'node:test';
import express from 'express';
import { checkIssuerStatus } from '../src/app/issuer-status-client.mjs';
import { createIssuerStatusRouter } from '../src/issuer/status-router.mjs';

const serviceToken = 'A'.repeat(43);

async function withStatusServer(lookupStatus, run) {
  const app = express();
  app.use(createIssuerStatusRouter({ serviceToken, lookupStatus }));
  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    await run(`http://127.0.0.1:${server.address().port}`);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

test('authenticated loopback status checks match both credential fields', async () => {
  const seen = [];
  await withStatusServer(async (id, commitment) => {
    seen.push([id, commitment]);
    return id === 'active-1' && commitment === '123' ? 'active' :
      id === 'revoked-1' ? 'revoked' : 'unknown';
  }, async (issuerOrigin) => {
    const options = { issuerOrigin, serviceToken };
    assert.equal(await checkIssuerStatus({ credentialId: 'active-1', commitment: '123' }, options), 'active');
    assert.equal(await checkIssuerStatus({ credentialId: 'revoked-1', commitment: '123' }, options), 'revoked');
    assert.equal(await checkIssuerStatus({ credentialId: 'active-1', commitment: '124' }, options), 'unknown');
    assert.equal(await checkIssuerStatus({ credentialId: 'active-1', commitment: '123' }, { ...options, serviceToken: 'B'.repeat(43) }), 'unavailable');
  });
  assert.deepEqual(seen, [
    ['active-1', '123'], ['revoked-1', '123'], ['active-1', '124'],
  ]);
});

test('issuer rejects missing token and malformed or duplicate status JSON', async () => {
  await withStatusServer(async () => 'active', async (issuerOrigin) => {
    const url = `${issuerOrigin}/internal/credential-status`;
    const noToken = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    assert.equal(noToken.status, 403);
    assert.deepEqual(await noToken.json(), { code: 'AUTH_DENIED' });
    const duplicate = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-zk-access-service-token': serviceToken },
      body: '{"credentialId":"one","credentialId":"two","commitment":"123"}',
    });
    assert.equal(duplicate.status, 400);
    assert.deepEqual(await duplicate.json(), { code: 'MALFORMED_INPUT' });
  });
});

test('issuer errors and unexpected responses fail closed', async () => {
  await withStatusServer(async () => { throw new Error('database offline'); }, async (issuerOrigin) => {
    assert.equal(await checkIssuerStatus({ credentialId: 'one', commitment: '123' }, { issuerOrigin, serviceToken }), 'unavailable');
  });
  let attempts = 0;
  const unexpected = async () => {
    attempts++;
    return new Response('{"status":"active","extra":"x"}', { status: 200, headers: { 'content-type': 'application/json' } });
  };
  assert.equal(await checkIssuerStatus({ credentialId: 'one', commitment: '123' }, { serviceToken, fetchImpl: unexpected }), 'unavailable');
  assert.equal(attempts, 1);
  const timeout = async (_url, options) => new Promise((_resolve, reject) => {
    options.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
  });
  assert.equal(await checkIssuerStatus({ credentialId: 'one', commitment: '123' }, { serviceToken, fetchImpl: timeout, timeoutMs: 5 }), 'unavailable');
});
