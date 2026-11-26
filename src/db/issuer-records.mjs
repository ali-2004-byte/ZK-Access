// Issuer issuance records: only ID, commitment, signature, times, issuing admin, and status.
export function initializeIssuerRecordSchema(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS credentials (
    credential_id TEXT PRIMARY KEY,
    commitment TEXT NOT NULL,
    signature TEXT NOT NULL,
    issued_at_unix INTEGER NOT NULL,
    expires_at_unix INTEGER NOT NULL CHECK (expires_at_unix > issued_at_unix),
    issued_by TEXT NOT NULL REFERENCES accounts(id),
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked'))
  ) STRICT`);
}

// Prepared statements for issuing, revoking, listing, and status lookup.
export function createIssuerRecords(db) {
  const insert = db.prepare(`INSERT INTO credentials
    (credential_id, commitment, signature, issued_at_unix, expires_at_unix, issued_by, status)
    VALUES (?, ?, ?, ?, ?, ?, 'active')`);
  const revoke = db.prepare("UPDATE credentials SET status = 'revoked' WHERE credential_id = ?");
  const find = db.prepare('SELECT commitment, status FROM credentials WHERE credential_id = ?');
  const list = db.prepare(`SELECT credential_id, issued_at_unix, expires_at_unix, issued_by, status
    FROM credentials ORDER BY issued_at_unix DESC, credential_id`);
  return {
    insert(record) {
      insert.run(record.credentialId, record.commitment, record.signature, record.issuedAt, record.expiresAt,
        record.issuedBy);
    },
    revoke(credentialId) {
      return revoke.run(credentialId).changes === 1;
    },
    // Status only when both ID and commitment match; anything else is unknown.
    lookupStatus(credentialId, commitment) {
      const row = find.get(credentialId);
      return row && row.commitment === commitment ? row.status : 'unknown';
    },
    list() {
      return list.all().map((row) => ({
        credentialId: row.credential_id,
        issuedAt: row.issued_at_unix,
        expiresAt: row.expires_at_unix,
        issuedBy: row.issued_by,
        status: row.status,
      }));
    },
  };
}
