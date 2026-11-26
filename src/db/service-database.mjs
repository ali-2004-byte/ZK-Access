// Opens one service's SQLite file with every table that service needs.
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { accountDatabasePath, initializeAccountSchema } from './account-store.mjs';
import { initializeAppRecordSchema } from './app-records.mjs';
import { initializeAuditSchema } from './audit-store.mjs';
import { initializeIssuerRecordSchema } from './issuer-records.mjs';
import { initializeSessionSchema } from './session-store.mjs';

// Create all tables for the service on an open database handle.
export function initializeServiceSchema(db, service) {
  initializeAccountSchema(db, service);
  initializeSessionSchema(db);
  initializeAuditSchema(db);
  if (service === 'app') initializeAppRecordSchema(db);
  else initializeIssuerRecordSchema(db);
}

// Open the service's file under .local/, or an in-memory database when file is ':memory:'.
export function openServiceDatabase(service, { root, file } = {}) {
  const target = file ?? accountDatabasePath(service, root);
  if (target !== ':memory:') mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(target);
  try {
    db.exec('PRAGMA busy_timeout = 5000');
    if (target !== ':memory:') db.exec('PRAGMA journal_mode = WAL');
    initializeServiceSchema(db, service);
    return db;
  } catch (error) {
    db.close();
    throw error;
  }
}
