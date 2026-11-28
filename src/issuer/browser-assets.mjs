import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const ROUTES = Object.freeze([
  ['/', path.join(ROOT, 'src', 'issuer', 'public', 'index.html'), 'text/html; charset=utf-8'],
  ['/issuer.js', path.join(ROOT, 'src', 'issuer', 'public', 'issuer.js'), 'text/javascript; charset=utf-8'],
  ['/styles.css', path.join(ROOT, 'src', 'app', 'public', 'styles.css'), 'text/css; charset=utf-8'],
]);

export function createIssuerBrowserAssetRouter() {
  const router = express.Router();
  for (const [route, file, type] of ROUTES) {
    router.get(route, (_request, response) => {
      response.setHeader('Cache-Control', 'no-store');
      response.setHeader('X-Content-Type-Options', 'nosniff');
      response.type(type).send(readFileSync(file));
    });
  }
  return router;
}
