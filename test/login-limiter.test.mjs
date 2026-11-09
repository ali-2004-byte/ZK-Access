import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { activeLoginLockout, clearLoginFailures, recordLoginFailure } from '../src/auth/login-limiter.mjs';
import { openAccountDatabase } from '../src/db/account-store.mjs';

test('five failures in 15 minutes lock for one minute, then double only after expiry', () => {
  const tempRoot = mkdtempSync(path.join(tmpdir(), 'zk-access-limiter-'));
  let db;
  try {
    db = openAccountDatabase('app', tempRoot);
    for (let index = 0; index < 4; index++) {
      assert.equal(recordLoginFailure(db, '127.0.0.1', 'Admin', 1000 + index).locked, false);
    }
    assert.deepEqual(recordLoginFailure(db, '127.0.0.1', 'Admin', 1004), {
      locked: true, untilUnix: 1064, extended: true,
    });
    assert.equal(activeLoginLockout(db, '127.0.0.1', 'admin', 1050), 1064);
    assert.deepEqual(recordLoginFailure(db, '127.0.0.1', 'Admin', 1050), {
      locked: true, untilUnix: 1064, extended: false,
    });
    db.close();
    db = openAccountDatabase('app', tempRoot);
    assert.equal(activeLoginLockout(db, '127.0.0.1', 'Admin', 1050), 1064);
    assert.deepEqual(recordLoginFailure(db, '127.0.0.1', 'Admin', 1064), {
      locked: true, untilUnix: 1184, extended: true,
    });
    assert.equal(recordLoginFailure(db, '127.0.0.1', 'Admin', 1184).untilUnix, 1424);
    assert.equal(recordLoginFailure(db, '127.0.0.1', 'Admin', 1424).untilUnix, 1904);
    assert.equal(recordLoginFailure(db, '127.0.0.1', 'Admin', 1904).untilUnix, 2804);
    assert.equal(recordLoginFailure(db, '127.0.0.1', 'Admin', 2804).untilUnix, 3704);
    clearLoginFailures(db, '127.0.0.1', 'Admin');
    assert.equal(activeLoginLockout(db, '127.0.0.1', 'Admin', 2805), null);
  } finally {
    db?.close();
    if (!tempRoot.startsWith(path.join(tmpdir(), 'zk-access-limiter-'))) throw new Error('Unexpected test directory');
    rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('failure counters apply independently per IP and normalized username', () => {
  const tempRoot = mkdtempSync(path.join(tmpdir(), 'zk-access-limiter-'));
  const db = openAccountDatabase('issuer', tempRoot);
  try {
    for (let index = 0; index < 4; index++) {
      recordLoginFailure(db, '127.0.0.1', 'first', 1000 + index);
    }
    assert.equal(recordLoginFailure(db, '127.0.0.1', 'second', 1004).locked, true);
    assert.equal(activeLoginLockout(db, '127.0.0.1', 'third', 1005), 1064);
    assert.equal(activeLoginLockout(db, '127.0.0.2', 'second', 1005), null);
  } finally {
    db.close();
    if (!tempRoot.startsWith(path.join(tmpdir(), 'zk-access-limiter-'))) throw new Error('Unexpected test directory');
    rmSync(tempRoot, { recursive: true, force: true });
  }
});

test('fewer than five failures age out after the 15-minute window', () => {
  const tempRoot = mkdtempSync(path.join(tmpdir(), 'zk-access-limiter-'));
  const db = openAccountDatabase('app', tempRoot);
  try {
    for (let index = 0; index < 4; index++) {
      recordLoginFailure(db, '127.0.0.1', 'admin', 1000 + index);
    }
    assert.equal(recordLoginFailure(db, '127.0.0.1', 'admin', 1900).locked, false);
    assert.equal(activeLoginLockout(db, '127.0.0.1', 'admin', 1900), null);
  } finally {
    db.close();
    if (!tempRoot.startsWith(path.join(tmpdir(), 'zk-access-limiter-'))) throw new Error('Unexpected test directory');
    rmSync(tempRoot, { recursive: true, force: true });
  }
});
