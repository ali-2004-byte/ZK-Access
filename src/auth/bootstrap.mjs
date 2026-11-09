import { randomUUID } from 'node:crypto';
import { hashPassword } from './password.mjs';
import { normalizeUsername } from './username.mjs';

export function existingAdmin(db, role) {
  if (role !== 'admin' && role !== 'issuer_admin') throw new TypeError('Invalid bootstrap role');
  return db.prepare('SELECT id, username_normalized FROM accounts WHERE role = ? ORDER BY created_at_unix, id LIMIT 1').get(role) ?? null;
}

/** Existing admin accounts are preserved; a partly completed bootstrap may be rerun. */
export async function bootstrapAdmins({ appDb, issuerDb, appAdmin, issuerAdmin, hash = hashPassword, now = () => Date.now() }) {
  const currentApp = existingAdmin(appDb, 'admin');
  const currentIssuer = existingAdmin(issuerDb, 'issuer_admin');
  if (!currentApp && !appAdmin) throw new TypeError('App admin credentials are required');
  if (!currentIssuer && !issuerAdmin) throw new TypeError('Issuer admin credentials are required');

  const appName = currentApp?.username_normalized ?? normalizeUsername(appAdmin.username);
  const issuerName = currentIssuer?.username_normalized ?? normalizeUsername(issuerAdmin.username);
  if (appName === issuerName) throw new TypeError('App and issuer admin usernames must differ');

  const appRecord = currentApp ? null : await hash(appAdmin.password);
  const issuerRecord = currentIssuer ? null : await hash(issuerAdmin.password);
  if ((appRecord !== null && (typeof appRecord !== 'string' || appRecord.length === 0)) ||
      (issuerRecord !== null && (typeof issuerRecord !== 'string' || issuerRecord.length === 0))) {
    throw new TypeError('Password hasher did not produce a record');
  }
  const createdAt = Math.floor(now() / 1000);
  const insert = (db, username, record, role) => {
    db.prepare('INSERT INTO accounts (id, username_normalized, password_record, role, created_at_unix) VALUES (?, ?, ?, ?, ?)')
      .run(randomUUID(), username, record, role, createdAt);
  };
  if (appRecord !== null) insert(appDb, appName, appRecord, 'admin');
  if (issuerRecord !== null) insert(issuerDb, issuerName, issuerRecord, 'issuer_admin');
  return { appCreated: appRecord !== null, issuerCreated: issuerRecord !== null };
}
