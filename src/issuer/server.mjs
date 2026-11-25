// ZK Access mock issuer service: health check plus issuer-admin-only endpoints.
import express from 'express';
import { pathToFileURL } from 'node:url';
import { mayUseIssuerAction } from '../app/access-policy.mjs';
import { createAuthorizer, noSession, writeAuditToStdout } from '../http/authorization.mjs';
import { mountEndpoints, mountFallbacks } from '../http/endpoints.mjs';
import { listenLocal } from '../listen-local.mjs';
import { ISSUER_ENDPOINTS } from './endpoints.mjs';

// Build the issuer; its sessions resolve only issuer accounts, never app accounts.
export function createIssuer({
  resolveSession = noSession,
  audit = writeAuditToStdout,
  handlers = {},
  now = Date.now,
} = {}) {
  const app = express();
  app.disable('x-powered-by');
  app.get('/health', (_request, response) => {
    response.json({ service: 'zk-access-issuer', status: 'ok' });
  });
  const requireAction = createAuthorizer({ service: 'issuer', mayUse: mayUseIssuerAction, resolveSession, audit, now });
  mountEndpoints(app, ISSUER_ENDPOINTS, { requireAction, handlers });
  mountFallbacks(app);
  return app;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  listenLocal(createIssuer(), {
    portVariable: 'ISSUER_PORT',
    defaultPort: 3001,
    serviceName: 'ZK Access issuer',
  });
}
