import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { bootstrapAdmins, existingAdmin } from '../src/auth/bootstrap.mjs';
import { hashPassword, parsePasswordRecord, verifyPassword } from '../src/auth/password.mjs';
import { normalizeUsername } from '../src/auth/username.mjs';
import { initializeAccountSchema } from '../src/db/account-store.mjs';

test('username normalization uses trim, NFKC, lowercase, and ASCII rules', () => {
  assert.equal(normalizeUsername('  ＡＬＩ_04  '), 'ali_04');
  assert.equal(normalizeUsername('Ab.C-d'), 'ab.c-d');
  for (const value of ['ab', 'a'.repeat(33), 'with space', 'école', 'a/b', '']) {
    assert.throws(() => normalizeUsername(value));
  }
});

test('async scrypt records use approved parameters and verify with exact bytes', async () => {
  const password = 'synthetic-demo-password';
  const record = await hashPassword(password);
  const parsed = parsePasswordRecord(record);
  assert.equal(parsed.N, 131072);
  assert.equal(parsed.r, 8);
  assert.equal(parsed.p, 1);
  assert.equal(parsed.salt.length, 16);
  assert.equal(parsed.hash.length, 64);
  assert.equal(record.split('$').length, 6);
  assert.equal(record.includes(password), false);
  assert.equal(await verifyPassword(password, record), true);
  assert.equal(await verifyPassword('different-password', record), false);
  const second = await hashPassword(password);
  assert.notEqual(parsePasswordRecord(second).salt.toString('hex'), parsed.salt.toString('hex'));
});

test('tampered scrypt records are rejected before password derivation', async () => {
  const salt = Buffer.alloc(16).toString('base64url');
  const hash = Buffer.alloc(64).toString('base64url');
  for (const params of ['1073741824$8$1', '12345$8$1', '16384$16$1', '16384$8$2']) {
    await assert.rejects(() => verifyPassword('synthetic-demo-password', `scrypt$${params}$${salt}$${hash}`));
  }
  await assert.rejects(() => hashPassword('too-short'));
  await assert.rejects(() => verifyPassword('synthetic-demo-password', `scrypt$16384$8$1$${salt}=$${hash}`));
});

test('bootstrap normalizes distinct admin names and preserves rows on rerun', async () => {
  const appDb = new DatabaseSync(':memory:');
  const issuerDb = new DatabaseSync(':memory:');
  initializeAccountSchema(appDb, 'app');
  initializeAccountSchema(issuerDb, 'issuer');
  const hash = async () => 'synthetic-record';
  try {
    await assert.rejects(() => bootstrapAdmins({
      appDb, issuerDb, appAdmin: { username: ' Admin ', password: 'synthetic-password' },
      issuerAdmin: { username: 'ＡＤＭＩＮ', password: 'synthetic-password' }, hash,
    }));
    const first = await bootstrapAdmins({
      appDb, issuerDb, appAdmin: { username: ' App.Admin ', password: 'synthetic-password' },
      issuerAdmin: { username: 'Issuer.Admin', password: 'synthetic-password' }, hash, now: () => 1000,
    });
    assert.deepEqual(first, { appCreated: true, issuerCreated: true });
    assert.equal(existingAdmin(appDb, 'admin').username_normalized, 'app.admin');
    assert.equal(existingAdmin(issuerDb, 'issuer_admin').username_normalized, 'issuer.admin');
    assert.deepEqual(await bootstrapAdmins({ appDb, issuerDb, hash }), { appCreated: false, issuerCreated: false });
    assert.equal(appDb.prepare('SELECT COUNT(*) AS count FROM accounts').get().count, 1);
    assert.equal(issuerDb.prepare('SELECT COUNT(*) AS count FROM accounts').get().count, 1);
  } finally {
    appDb.close();
    issuerDb.close();
  }
});

test('bootstrap completes an interrupted two-database setup without replacing the first admin', async () => {
  const appDb = new DatabaseSync(':memory:');
  const issuerDb = new DatabaseSync(':memory:');
  initializeAccountSchema(appDb, 'app');
  initializeAccountSchema(issuerDb, 'issuer');
  try {
    appDb.prepare('INSERT INTO accounts (id, username_normalized, password_record, role, created_at_unix) VALUES (?, ?, ?, ?, ?)')
      .run('existing-id', 'app.admin', 'existing-record', 'admin', 1);
    const result = await bootstrapAdmins({
      appDb, issuerDb, issuerAdmin: { username: 'ISSUER.ADMIN', password: 'synthetic-password' },
      hash: async () => 'new-record', now: () => 2000,
    });
    assert.deepEqual(result, { appCreated: false, issuerCreated: true });
    assert.equal(appDb.prepare('SELECT password_record FROM accounts WHERE id = ?').get('existing-id').password_record, 'existing-record');
    assert.equal(issuerDb.prepare('SELECT username_normalized FROM accounts').get().username_normalized, 'issuer.admin');
  } finally {
    appDb.close();
    issuerDb.close();
  }
});
