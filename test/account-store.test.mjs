import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { accountDatabasePath, initializeAccountSchema } from '../src/db/account-store.mjs';

test('app and issuer account paths are separate and restricted to known services', () => {
  const root = 'C:\\synthetic-project';
  assert.notEqual(accountDatabasePath('app', root), accountDatabasePath('issuer', root));
  assert.throws(() => accountDatabasePath('../issuer', root));
});

test('SQLite enforces normalized username uniqueness and service roles', () => {
  const app = new DatabaseSync(':memory:');
  const issuer = new DatabaseSync(':memory:');
  try {
    initializeAccountSchema(app, 'app');
    initializeAccountSchema(issuer, 'issuer');
    const addApp = app.prepare('INSERT INTO accounts (id, username_normalized, password_record, role, created_at_unix) VALUES (?, ?, ?, ?, ?)');
    addApp.run('app-1', 'admin', 'synthetic-record', 'admin', 1);
    assert.throws(() => addApp.run('app-2', 'admin', 'synthetic-record', 'viewer', 1));
    assert.throws(() => addApp.run('app-3', 'issuer-admin', 'synthetic-record', 'issuer_admin', 1));

    const addIssuer = issuer.prepare('INSERT INTO accounts (id, username_normalized, password_record, role, created_at_unix) VALUES (?, ?, ?, ?, ?)');
    addIssuer.run('issuer-1', 'issuer-admin', 'synthetic-record', 'issuer_admin', 1);
    assert.throws(() => addIssuer.run('issuer-2', 'operator', 'synthetic-record', 'operator', 1));
  } finally {
    app.close();
    issuer.close();
  }
});
