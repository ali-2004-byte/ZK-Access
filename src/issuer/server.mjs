// ZK Access mock issuer service: health check plus issuer-admin-only endpoints.
import express from 'express';
import { pathToFileURL } from 'node:url';
import { mayUseIssuerAction } from '../app/access-policy.mjs';
import { loadServiceConfig } from '../config/local-config.mjs';
import { openServiceDatabase } from '../db/service-database.mjs';
import { createAccountServices } from '../http/account-services.mjs';
import { createAuthorizer, noSession, writeAuditToStdout } from '../http/authorization.mjs';
import { mountEndpoints, mountFallbacks } from '../http/endpoints.mjs';
import { listenLocal } from '../listen-local.mjs';
import { createIssuerRecords } from '../db/issuer-records.mjs';
import { ISSUER_ENDPOINTS } from './endpoints.mjs';
import { createIssuanceHandlers } from './issuance-handlers.mjs';
import { createIssuerStatusRouter } from './status-router.mjs';

// Build the issuer; its sessions resolve only issuer accounts, and the status route needs the service token.
export function createIssuer({
  db = null,
  identifierKey = null,
  signingKey = null,
  serviceToken = null,
  resolveSession,
  audit,
  handlers = {},
  now = Date.now,
} = {}) {
  let defaults = {};
  const records = db ? createIssuerRecords(db) : null;
  if (db) {
    const accounts = createAccountServices({ service: 'issuer', db, identifierKey, audit, now });
    audit = accounts.audit;
    resolveSession ??= accounts.resolveSession;
    defaults = {
      ...accounts.handlers,
      ...(signingKey ? createIssuanceHandlers({ records, signingKey, audit, now }) : {}),
    };
  }
  resolveSession ??= noSession;
  audit ??= writeAuditToStdout;

  const app = express();
  app.disable('x-powered-by');
  app.get('/health', (_request, response) => {
    response.json({ service: 'zk-access-issuer', status: 'ok' });
  });
  if (records && serviceToken) {
    app.use(createIssuerStatusRouter({
      serviceToken,
      lookupStatus: (credentialId, commitment) => records.lookupStatus(credentialId, commitment),
    }));
  }
  const requireAction = createAuthorizer({ service: 'issuer', mayUse: mayUseIssuerAction, resolveSession, audit, now });
  mountEndpoints(app, ISSUER_ENDPOINTS, { requireAction, handlers: { ...defaults, ...handlers } });
  mountFallbacks(app);
  return app;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const config = loadServiceConfig('issuer');
  listenLocal(createIssuer({ db: openServiceDatabase('issuer'), ...config }), {
    portVariable: 'ISSUER_PORT',
    defaultPort: 3001,
    serviceName: 'ZK Access issuer',
  });
}
