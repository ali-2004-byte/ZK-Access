// ZK Access app service: health check plus role-guarded API endpoints.
import express from 'express';
import { pathToFileURL } from 'node:url';
import { loadServiceConfig } from '../config/local-config.mjs';
import { openServiceDatabase } from '../db/service-database.mjs';
import { createAccountServices } from '../http/account-services.mjs';
import { createAuthorizer, noSession, writeAuditToStdout } from '../http/authorization.mjs';
import { mountEndpoints, mountFallbacks } from '../http/endpoints.mjs';
import { listenLocal } from '../listen-local.mjs';
import { mayUseAppAction } from './access-policy.mjs';
import { createAuditHandlers } from './audit-handlers.mjs';
import { APP_ENDPOINTS } from './endpoints.mjs';
import { createResultHandlers } from './result-handlers.mjs';

// Build the app; with a database it gets sessions, login, users, and audit, and every seam stays injectable.
export function createApp({
  db = null,
  identifierKey = null,
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
    defaults = { ...accounts.handlers, ...createAuditHandlers({ auditStore: accounts.auditStore, audit, now }) };
  }
  resolveSession ??= noSession;
  audit ??= writeAuditToStdout;

  const app = express();
  app.disable('x-powered-by');
  app.get('/health', (_request, response) => {
    response.json({ service: 'zk-access-app', status: 'ok' });
  });
  const requireAction = createAuthorizer({ service: 'app', mayUse: mayUseAppAction, resolveSession, audit, now });
  const resultHandlers = resultStore ? createResultHandlers(resultStore) : {};
  mountEndpoints(app, APP_ENDPOINTS, { requireAction, handlers: { ...defaults, ...resultHandlers, ...handlers } });
  mountFallbacks(app);
  return app;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { identifierKey } = loadServiceConfig('app');
  listenLocal(createApp({ db: openServiceDatabase('app'), identifierKey }), {
    portVariable: 'APP_PORT',
    defaultPort: 3000,
    serviceName: 'ZK Access app',
  });
}
