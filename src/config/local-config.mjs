// Loads each service's ignored .local/ secrets written by `npm run local:setup`.
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const KEY_TEXT = /^[A-Za-z0-9_-]{43}$/;

// Read one setup file, pointing at the setup command when it is missing.
function readSetupFile(file) {
  try {
    return readFileSync(file, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') throw new Error(`Missing ${file}; run npm run local:setup first`);
    throw error;
  }
}

// Decode a 32-byte base64url key file.
function readKey(file) {
  const text = readSetupFile(file);
  if (!KEY_TEXT.test(text)) throw new Error(`${file} is malformed; rerun npm run local:setup`);
  return Buffer.from(text, 'base64url');
}

// Secrets the given service needs at startup.
export function loadServiceConfig(service, root = projectRoot) {
  if (service !== 'app' && service !== 'issuer') throw new TypeError('Unknown service');
  const dir = path.join(root, '.local', service);
  return { identifierKey: readKey(path.join(dir, 'audit-identifier-key')) };
}
