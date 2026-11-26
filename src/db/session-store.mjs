// SQLite session table; rows hold a hash of the cookie value, never the value itself.
export function initializeSessionSchema(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS sessions (
    id_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    last_activity_ms INTEGER NOT NULL CHECK (last_activity_ms >= created_at_ms)
  ) STRICT`);
  db.exec('CREATE INDEX IF NOT EXISTS sessions_account ON sessions (account_id)');
}
