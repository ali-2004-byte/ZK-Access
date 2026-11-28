import assert from 'node:assert/strict';
import test from 'node:test';
import { createApp } from '../src/app/server.mjs';
import { createIssuer } from '../src/issuer/server.mjs';
import { withServer } from './http-helpers.mjs';

test('separate app role pages and issuer page serve only allowlisted browser assets', async () => {
  await withServer(createApp(), async (appOrigin) => {
    for (const route of ['/', '/operator', '/admin', '/viewer', '/styles.css', '/app.js', '/ui-common.mjs']) {
      const response = await fetch(`${appOrigin}${route}`);
      assert.equal(response.status, 200, route);
      assert.equal(response.headers.get('cache-control'), 'no-store', route);
      assert.equal(response.headers.get('x-content-type-options'), 'nosniff', route);
    }
    const viewer = await (await fetch(`${appOrigin}/viewer`)).text();
    assert.match(viewer, /data-page="viewer"/);
    assert.doesNotMatch(viewer, /export-json|prove-submit|rule-form/);
    const operator = await (await fetch(`${appOrigin}/operator`)).text();
    assert.match(operator, /data-page="operator"/);
    assert.match(operator, /credential-file/);
    assert.equal((await fetch(`${appOrigin}/issuer.js`)).status, 404);
  });
  await withServer(createIssuer(), async (issuerOrigin) => {
    for (const route of ['/', '/issuer.js', '/styles.css']) {
      const response = await fetch(`${issuerOrigin}${route}`);
      assert.equal(response.status, 200, route);
      assert.equal(response.headers.get('cache-control'), 'no-store', route);
    }
    const issuer = await (await fetch(`${issuerOrigin}/`)).text();
    assert.match(issuer, /issue-form/);
    assert.equal((await fetch(`${issuerOrigin}/app.js`)).status, 404);
  });
});
