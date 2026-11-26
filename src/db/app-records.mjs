// App rules, single-use challenges, and verification results.
const RESULT_COLUMNS = `result_id, challenge_id, decision, reason_code, rule_name, rule_version, nonce_status,
  verified_at_ms, credential_id, issuer_name, credential_expiry_status, proof_size_bytes, proof_generation_ms,
  verification_ms, decision_latency_ms, actor_account_id, engine_version`;

// Create the app tables and seed the default rule; 'verifying' marks a claimed, unfinished check.
export function initializeAppRecordSchema(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS rules (
    name TEXT PRIMARY KEY,
    version INTEGER NOT NULL CHECK (version >= 1),
    challenge_lifetime_seconds INTEGER NOT NULL CHECK (challenge_lifetime_seconds BETWEEN 30 AND 1800),
    updated_at_ms INTEGER NOT NULL
  ) STRICT`);
  db.exec("INSERT OR IGNORE INTO rules VALUES ('age-at-least-18', 1, 300, 0)");
  db.exec(`CREATE TABLE IF NOT EXISTS challenges (
    challenge_id TEXT PRIMARY KEY,
    session_id_hash TEXT NOT NULL,
    account_id TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    challenge_hash TEXT NOT NULL,
    cutoff INTEGER NOT NULL,
    rule_name TEXT NOT NULL,
    rule_version INTEGER NOT NULL,
    issued_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('issued', 'verifying', 'used', 'expired'))
  ) STRICT`);
  db.exec('CREATE INDEX IF NOT EXISTS challenges_account_time ON challenges (account_id, issued_at_ms)');
  db.exec(`CREATE TABLE IF NOT EXISTS verification_results (
    result_id TEXT PRIMARY KEY,
    challenge_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('allow', 'deny')),
    reason_code TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    rule_version INTEGER NOT NULL,
    nonce_status TEXT NOT NULL CHECK (nonce_status IN ('fresh', 'replayed', 'expired')),
    verified_at_ms INTEGER NOT NULL,
    credential_id TEXT NOT NULL,
    issuer_name TEXT NOT NULL,
    credential_expiry_status TEXT NOT NULL,
    proof_size_bytes INTEGER,
    proof_generation_ms INTEGER,
    verification_ms INTEGER,
    decision_latency_ms INTEGER NOT NULL,
    actor_account_id TEXT NOT NULL,
    engine_version TEXT NOT NULL
  ) STRICT`);
}

// Rebuild the stored result shape from a row.
function rowToResult(row) {
  return {
    resultId: row.result_id,
    decision: row.decision,
    reasonCode: row.reason_code,
    ruleName: row.rule_name,
    ruleVersion: row.rule_version,
    nonceStatus: row.nonce_status,
    verifiedAt: row.verified_at_ms,
    credentialId: row.credential_id,
    issuerName: row.issuer_name,
    credentialExpiryStatus: row.credential_expiry_status,
    measurements: {
      proofSizeBytes: row.proof_size_bytes,
      proofGenerationMs: row.proof_generation_ms,
      verificationMs: row.verification_ms,
      decisionLatencyMs: row.decision_latency_ms,
    },
    actorAccountId: row.actor_account_id,
    engineVersion: row.engine_version,
  };
}

// Prepared statements for the challenge lifecycle and result history.
export function createAppRecords(db) {
  const rule = db.prepare('SELECT name, version, challenge_lifetime_seconds FROM rules ORDER BY name LIMIT 1');
  const insertChallenge = db.prepare(`INSERT INTO challenges (challenge_id, session_id_hash, account_id, credential_id,
    challenge_hash, cutoff, rule_name, rule_version, issued_at_ms, expires_at_ms, state)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'issued')`);
  const recentChallenges = db.prepare(
    'SELECT COUNT(*) AS n FROM challenges WHERE account_id = ? AND issued_at_ms > ?');
  const findChallenge = db.prepare('SELECT * FROM challenges WHERE challenge_id = ?');
  const setState = db.prepare('UPDATE challenges SET state = ? WHERE challenge_id = ? AND state = ?');
  const recover = db.prepare("UPDATE challenges SET state = 'issued' WHERE state = 'verifying'");
  const insertResult = db.prepare(`INSERT INTO verification_results (${RESULT_COLUMNS})
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  const listResults = db.prepare(`SELECT ${RESULT_COLUMNS} FROM verification_results
    ORDER BY verified_at_ms DESC, rowid DESC LIMIT 500`);
  const getResult = db.prepare(`SELECT ${RESULT_COLUMNS} FROM verification_results WHERE result_id = ?`);

  return {
    activeRule() {
      const row = rule.get();
      return { name: row.name, version: row.version, challengeLifetimeMs: row.challenge_lifetime_seconds * 1000 };
    },
    countRecentChallenges(accountId, sinceMs) {
      return recentChallenges.get(accountId, sinceMs).n;
    },
    insertChallenge(challenge) {
      insertChallenge.run(challenge.challengeId, challenge.sessionIdHash, challenge.accountId, challenge.credentialId,
        challenge.challengeHash, challenge.cutoff, challenge.ruleName, challenge.ruleVersion, challenge.issuedAt,
        challenge.expiresAt);
    },
    findChallenge(challengeId) {
      return findChallenge.get(challengeId) ?? null;
    },
    // Atomic compare-and-set; true only for the caller that made the change.
    transition(challengeId, from, to) {
      return setState.run(to, challengeId, from).changes === 1;
    },
    // After a crash, a claimed but undecided challenge becomes usable again until its expiry.
    recoverClaims() {
      return recover.run().changes;
    },
    insertResult(challengeId, result) {
      const m = result.measurements;
      insertResult.run(result.resultId, challengeId, result.decision, result.reasonCode, result.ruleName,
        result.ruleVersion, result.nonceStatus, result.verifiedAt, result.credentialId, result.issuerName,
        result.credentialExpiryStatus, m.proofSizeBytes, m.proofGenerationMs, m.verificationMs, m.decisionLatencyMs,
        result.actorAccountId, result.engineVersion);
    },
    resultStore: {
      list: () => listResults.all().map(rowToResult),
      get: (resultId) => {
        const row = getResult.get(resultId);
        return row ? rowToResult(row) : null;
      },
    },
  };
}
