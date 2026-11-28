// Allowlisted static routes for browser proof assets and committed Groth16 artifacts.
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { ARTIFACTS_DIR, MANIFEST_PATH, verifyCommittedArtifacts } from '../zk/artifacts.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const PUBLIC_DIR = path.join(ROOT, 'src', 'app', 'public');
const SHARED_DIR = path.join(ROOT, 'src');
const SNARKJS_MIN = path.join(path.dirname(fileURLToPath(import.meta.resolve('snarkjs'))), 'build', 'snarkjs.min.js');

const STATIC_ROUTES = Object.freeze([
  ['/', path.join(PUBLIC_DIR, 'index.html'), 'text/html; charset=utf-8'],
  ['/operator', path.join(PUBLIC_DIR, 'operator.html'), 'text/html; charset=utf-8'],
  ['/admin', path.join(PUBLIC_DIR, 'admin.html'), 'text/html; charset=utf-8'],
  ['/viewer', path.join(PUBLIC_DIR, 'viewer.html'), 'text/html; charset=utf-8'],
  ['/styles.css', path.join(PUBLIC_DIR, 'styles.css'), 'text/css; charset=utf-8'],
  ['/app.js', path.join(PUBLIC_DIR, 'app.js'), 'text/javascript; charset=utf-8'],
  ['/ui-common.mjs', path.join(PUBLIC_DIR, 'ui-common.mjs'), 'text/javascript; charset=utf-8'],
  ['/prover-client.mjs', path.join(PUBLIC_DIR, 'prover-client.mjs'), 'text/javascript; charset=utf-8'],
  ['/vendor/snarkjs.min.js', SNARKJS_MIN, 'text/javascript; charset=utf-8'],
  ['/shared/credential-json.mjs', path.join(SHARED_DIR, 'credential-json.mjs'), 'text/javascript; charset=utf-8'],
  ['/shared/strict-json.mjs', path.join(SHARED_DIR, 'strict-json.mjs'), 'text/javascript; charset=utf-8'],
  ['/shared/calendar-date.mjs', path.join(SHARED_DIR, 'calendar-date.mjs'), 'text/javascript; charset=utf-8'],
  ['/shared/issuer/birth-date.mjs', path.join(SHARED_DIR, 'issuer', 'birth-date.mjs'), 'text/javascript; charset=utf-8'],
  ['/shared/zk/field.mjs', path.join(SHARED_DIR, 'zk', 'field.mjs'), 'text/javascript; charset=utf-8'],
  ['/zk/manifest.json', MANIFEST_PATH, 'application/json; charset=utf-8'],
  ['/zk/age18.wasm', path.join(ARTIFACTS_DIR, 'age18.wasm'), 'application/wasm'],
  ['/zk/age18_final.zkey', path.join(ARTIFACTS_DIR, 'age18_final.zkey'), 'application/octet-stream'],
]);

export function createBrowserAssetRouter({ verifyArtifacts = true } = {}) {
  if (verifyArtifacts) verifyCommittedArtifacts();
  const router = express.Router();
  for (const [routePath, filePath, contentType] of STATIC_ROUTES) {
    router.get(routePath, (_request, response) => {
      response.setHeader('Cache-Control', 'no-store');
      response.setHeader('X-Content-Type-Options', 'nosniff');
      response.type(contentType);
      response.send(readFileSync(filePath));
    });
  }
  return router;
}
