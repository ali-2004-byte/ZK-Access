// ZK Access app service: health check plus role-guarded API endpoints.
import express from 'express';
import { pathToFileURL } from 'node:url';
import { loadServiceConfig } from '../config/local-config.mjs';
import { createAuditStore } from '../db/audit-store.mjs';
import { startRetentionSchedule } from '../db/retention.mjs';
import { openServiceDatabase } from '../db/service-database.mjs';
import { createAccountServices } from '../http/account-services.mjs';
import { createAuthorizer, noSession, writeAuditToStdout } from '../http/authorization.mjs';
import { mountEndpoints, mountFallbacks } from '../http/endpoints.mjs';
import { listenLocal } from '../listen-local.mjs';
import { mayUseAppAction } from './access-policy.mjs';
import { createAppRecords } from '../db/app-records.mjs';
import { createAuditHandlers } from './audit-handlers.mjs';
import { createBrowserAssetRouter } from './browser-assets.mjs';
import { createChallengeHandlers } from './challenge-handlers.mjs';
import { APP_ENDPOINTS } from './endpoints.mjs';
import { checkIssuerStatus } from './issuer-status-client.mjs';
import { ENGINE_VERSION, verifyAgeProof } from './proof-engine.mjs';
import { createResultHandlers } from './result-handlers.mjs';
import { createRuleHandlers } from './rule-handlers.mjs';
import { createVerificationHandlers } from './verification-handlers.mjs';

// Build the app; with a database it gets sessions, challenges, and verification, and every seam stays injectable.
export function createApp({
  db = null,
  identifierKey = null,
  trustedIssuerKey = null,
  serviceToken = null,
  issuerOrigin = 'http://127.0.0.1:3001',
  checkStatus,
  verifyProof = verifyAgeProof,
  resolveSession,
  audit,
  resultStore = null,
  handlers = {},
  now = Date.now,
} = {}) {
  let defaults = {};
  if (db) {
    const accounts = createAccountServices({ service: 'app', db, identifierKey, audit, now });
    audit = accounts.audit;
    resolveSession ??= accounts.resolveSession;
    const records = createAppRecords(db);
    records.recoverClaims();
    resultStore ??= records.resultStore;
    const shared = { db, records, sessions: accounts.sessions, audit, now };
    checkStatus ??= (credential) => checkIssuerStatus(credential, { serviceToken, issuerOrigin });
    defaults = {
      ...accounts.handlers,
      ...createAuditHandlers({ auditStore: accounts.auditStore, audit, now }),
      ...createChallengeHandlers(shared),
      ...createRuleHandlers(shared),
      ...(trustedIssuerKey ? createVerificationHandlers({
        ...shared, trustedIssuerKey, checkStatus, verifyProof, engineVersion: ENGINE_VERSION,
      }) : {}),
    };
  }
  resolveSession ??= noSession;
  audit ??= writeAuditToStdout;

  const app = express();
  app.disable('x-powered-by');
  app.get('/health', (_request, response) => {
    response.json({ service: 'zk-access-app', status: 'ok' });
  });
  app.use(createBrowserAssetRouter());
  const requireAction = createAuthorizer({ service: 'app', mayUse: mayUseAppAction, resolveSession, audit, now });
  const resultHandlers = resultStore ? createResultHandlers({ resultStore, audit, now }) : {};
  mountEndpoints(app, APP_ENDPOINTS, { requireAction, handlers: { ...defaults, ...resultHandlers, ...handlers } });
  mountFallbacks(app);
  return app;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const config = loadServiceConfig('app');
  const issuerOrigin = `http://127.0.0.1:${process.env.ISSUER_PORT ?? 3001}`;
  const db = openServiceDatabase('app');
  startRetentionSchedule({ db, service: 'app', audit: createAuditStore(db).append });
  listenLocal(createApp({ db, ...config, issuerOrigin }), {
    portVariable: 'APP_PORT',
    defaultPort: 3000,
    serviceName: 'ZK Access app',
  });
}
