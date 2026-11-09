import express from 'express';
import { pathToFileURL } from 'node:url';
import { listenLocal } from '../listen-local.mjs';

export function createIssuer() {
  const app = express();
  app.disable('x-powered-by');
  app.get('/health', (_request, response) => {
    response.json({ service: 'zk-access-issuer', status: 'ok' });
  });
  app.use((_request, response) => {
    response.status(404).json({ code: 'NOT_FOUND' });
  });
  return app;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  listenLocal(createIssuer(), {
    portVariable: 'ISSUER_PORT',
    defaultPort: 3001,
    serviceName: 'ZK Access issuer',
  });
}
