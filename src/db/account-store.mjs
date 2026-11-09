import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const SERVICE_FILES = Object.freeze({
  app: ['app', 'app.sqlite'],
  issuer: ['issuer', 'issuer.sqlite'],
});
const ROLE_CHECKS = Object.freeze({
  app: "role IN ('admin', 'operator', 'viewer')",
  issuer: "role = 'issuer_admin'",
});

export function accountDatabasePath(service, root = projectRoot) {
  if (!Object.hasOwn(SERVICE_FILES, service)) throw new TypeError('Unknown account service');
  return path.join(root, '.local', ...SERVICE_FILES[service]);
}

export function initializeAccountSchema(db, service) {
  if (!Object.hasOwn(ROLE_CHECKS, service)) throw new TypeError('Unknown account service');
  db.exec('PRAGMA foreign_keys = ON');
  db.exec(`CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    username_normalized TEXT NOT NULL UNIQUE,
    password_record TEXT NOT NULL,
    role TEXT NOT NULL CHECK (${ROLE_CHECKS[service]}),
    created_at_unix INTEGER NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1))
  ) STRICT`);
}

export function openAccountDatabase(service, root = projectRoot) {
  const file = accountDatabasePath(service, root);
  mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(file);
  try {
    initializeAccountSchema(db, service);
    return db;
  } catch (error) {
    db.close();
    throw error;
  }
}
