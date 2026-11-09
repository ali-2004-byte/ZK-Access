import { createHash } from 'node:crypto';
import { normalizeUsername } from './username.mjs';

const WINDOW_SECONDS = 15 * 60;
const THRESHOLD = 5;

function keys(ip, username) {
  if (typeof ip !== 'string' || ip.length === 0 || ip.length > 128) throw new TypeError('Invalid client IP');
  const normalized = normalizeUsername(username);
  const digest = (scope, value) => createHash('sha256').update(scope).update('\0').update(value).digest('hex');
  return [
    ['ip', digest('ip', ip)],
    ['username', digest('username', normalized)],
  ];
}

function requireTime(nowUnix) {
  if (!Number.isSafeInteger(nowUnix) || nowUnix < 0) throw new RangeError('Invalid login time');
}

function rowsFor(db, limitKeys) {
  const select = db.prepare('SELECT * FROM login_limits WHERE scope = ? AND key_hash = ?');
  return limitKeys.map(([scope, keyHash]) => select.get(scope, keyHash) ?? null);
}

/** Read-only check before password work; an active lockout is never extended. */
export function activeLoginLockout(db, ip, username, nowUnix) {
  requireTime(nowUnix);
  const rows = rowsFor(db, keys(ip, username));
  const until = Math.max(0, ...rows.map((row) => row?.lockout_until_unix ?? 0));
  return until > nowUnix ? until : null;
}

/** Atomically record both per-IP and per-username failures in one SQLite file. */
export function recordLoginFailure(db, ip, username, nowUnix) {
  requireTime(nowUnix);
  const limitKeys = keys(ip, username);
  db.exec('BEGIN IMMEDIATE');
  try {
    const rows = rowsFor(db, limitKeys);
    const activeUntil = Math.max(0, ...rows.map((row) => row?.lockout_until_unix ?? 0));
    if (activeUntil > nowUnix) {
      db.exec('COMMIT');
      return { locked: true, untilUnix: activeUntil, extended: false };
    }

    const upsert = db.prepare(`INSERT INTO login_limits
      (scope, key_hash, window_started_unix, failure_count, lockout_stage, lockout_until_unix)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(scope, key_hash) DO UPDATE SET
      window_started_unix = excluded.window_started_unix,
      failure_count = excluded.failure_count,
      lockout_stage = excluded.lockout_stage,
      lockout_until_unix = excluded.lockout_until_unix`);
    let lockedUntil = 0;
    for (const [index, [scope, keyHash]] of limitKeys.entries()) {
      const old = rows[index];
      let windowStart = old?.window_started_unix ?? nowUnix;
      let count = old?.failure_count ?? 0;
      let stage = old?.lockout_stage ?? 0;
      if (stage > 0) {
        stage = Math.min(stage + 1, 5);
        count++;
      } else if (!old || nowUnix - windowStart >= WINDOW_SECONDS) {
        windowStart = nowUnix;
        count = 1;
      } else {
        count++;
      }
      if (stage === 0 && count >= THRESHOLD) stage = 1;
      const until = stage > 0 ? nowUnix + Math.min(60 * 2 ** (stage - 1), 900) : 0;
      lockedUntil = Math.max(lockedUntil, until);
      upsert.run(scope, keyHash, windowStart, count, stage, until);
    }
    db.exec('COMMIT');
    return { locked: lockedUntil > nowUnix, untilUnix: lockedUntil || null, extended: lockedUntil > nowUnix };
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

/** A successful login clears both this username and this IP's failure state. */
export function clearLoginFailures(db, ip, username) {
  const limitKeys = keys(ip, username);
  db.exec('BEGIN IMMEDIATE');
  try {
    const remove = db.prepare('DELETE FROM login_limits WHERE scope = ? AND key_hash = ?');
    for (const [scope, keyHash] of limitKeys) remove.run(scope, keyHash);
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}
