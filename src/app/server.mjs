import express from 'express';
import { pathToFileURL } from 'node:url';
import { listenLocal } from '../listen-local.mjs';

export function createApp() {
  const app = express();
  app.disable('x-powered-by');
  app.get('/health', (_request, response) => {
    response.json({ service: 'zk-access-app', status: 'ok' });
  });
  app.use((_request, response) => {
    response.status(404).json({ code: 'NOT_FOUND' });
  });
  return app;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  listenLocal(createApp(), {
    portVariable: 'APP_PORT',
    defaultPort: 3000,
    serviceName: 'ZK Access app',
  });
}
