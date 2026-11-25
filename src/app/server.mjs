// ZK Access app service: health check plus role-guarded API endpoints.
import express from 'express';
import { pathToFileURL } from 'node:url';
import { createAuthorizer, noSession, writeAuditToStdout } from '../http/authorization.mjs';
import { mountEndpoints, mountFallbacks } from '../http/endpoints.mjs';
import { listenLocal } from '../listen-local.mjs';
import { mayUseAppAction } from './access-policy.mjs';
import { APP_ENDPOINTS } from './endpoints.mjs';
import { createResultHandlers } from './result-handlers.mjs';

// Build the app; session, audit, and storage seams are injected so later work can replace them.
export function createApp({
  resolveSession = noSession,
  audit = writeAuditToStdout,
  resultStore = null,
  handlers = {},
  now = Date.now,
} = {}) {
  const app = express();
  app.disable('x-powered-by');
  app.get('/health', (_request, response) => {
    response.json({ service: 'zk-access-app', status: 'ok' });
  });
  const requireAction = createAuthorizer({ service: 'app', mayUse: mayUseAppAction, resolveSession, audit, now });
  const resultHandlers = resultStore ? createResultHandlers(resultStore) : {};
  mountEndpoints(app, APP_ENDPOINTS, { requireAction, handlers: { ...resultHandlers, ...handlers } });
  mountFallbacks(app);
  return app;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  listenLocal(createApp(), {
    portVariable: 'APP_PORT',
    defaultPort: 3000,
    serviceName: 'ZK Access app',
  });
}
