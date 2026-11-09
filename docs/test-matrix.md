# Evaluation cases and safe fixtures

Use synthetic dates and mock credentials only. This matrix records expected behavior already determined by the project owner. Each implemented test should capture its input description, expected result, actual result, evidence location, and pass/fail status, as required by the proposal. Do not put raw birth dates, salt, commitment values, or signatures in user-facing verifier output or exported reports; synthetic witness values may appear in restricted test fixtures.

## Age boundary cases (T1)

The server computes the age-18 cutoff from the current UTC date when it issues the challenge and stores the cutoff in that challenge row. The circuit must prove that the issuer-attested private birth date meets the stored cutoff. The expected results below assume a valid issuer credential and an unused, unexpired challenge. The server clock must be injectable for fixed-date tests.

| Case | Synthetic birth date | Challenge issue date (UTC) | Expected decision | Reason |
| --- | --- | --- | --- | --- |
| AGE-01 | 2008-11-09 | 2026-11-09 | Allow | Exactly 18th birthday. |
| AGE-02 | 2008-11-10 | 2026-11-09 | Deny | One day before 18th birthday. |
| AGE-03 | 2008-11-08 | 2026-11-09 | Allow | One day after 18th birthday. |
| AGE-04 | 2008-02-29 | 2026-02-28 | Deny | Feb 29 birthday is observed Mar 1 in a non-leap year. |
| AGE-05 | 2008-02-29 | 2026-03-01 | Allow | Observed 18th birthday. |
| AGE-06 | 2006-02-28 | 2024-02-29 | Allow | On a leap-day challenge issue date, the cutoff is Feb 28 in the year 18 years earlier. |
| AGE-07 | 2006-03-01 | 2024-02-29 | Deny | One day after that cutoff. |

Tests should also reject impossible dates, malformed encodings, out-of-range field values, and a witness that opens a different commitment. Exact API error codes remain an interface decision; a failed signature/proof verification consumes its challenge under the agreed rule below.

## Issuer and credential misuse (T1 and T-final)

| Case | Expected behavior |
| --- | --- |
| CRED-01 valid issuer signature, valid credential | Continue to proof verification. |
| CRED-02 changed credential ID, commitment, issue time, expiry time, or issuer name after signing | Deny: signature must no longer verify. |
| CRED-03 forged signature or unknown issuer key | Deny without leaking signature or commitment in output/export/logs. |
| CRED-04 credential older than its 90-day validity period | Deny and report expiry status as `expired`, without exposing the expiry value. |
| CRED-05 user-supplied birth date inconsistent with the issuer-signed commitment | Proof generation or verification must fail. |
| CRED-06 issuer marks credential revoked | Verifier denies it with a safe reason code and no private fields in output/export. |
| CRED-07 issuer issuance record redaction | Stored record contains only credential ID, commitment, signature, issue/expiry times, issuing admin ID, and active/revoked status. It contains no birth date, salt, or request body. |
| CRED-08 valid synthetic witness at cutoff | Groth16 proof verifies against the committed verification key; public signals match requestTag, commitment, cutoff, and challengeHash. |
| CRED-09 birth date after cutoff or wrong salt | Witness/proof generation fails. |
| CRED-10 mutate public cutoff or challengeHash after proving | Groth16 verification fails. |
| CRED-11 signed-byte vector | The shared encoder emits the fixed `ZKACCESS-CRED-V1` binary vector with five four-byte big-endian byte lengths; the fixed Ed25519 signature verifies. Changing any signed field fails verification. |
| CRED-12 credential JSON shape | Import rejects duplicate, missing, extra, or wrongly typed fields, unknown versions, files over 4 KB, invalid calendar dates, out-of-field salt, and malformed base64url signatures before proof generation. The public verifier request also needs a strict schema. |
| CRED-13 private credential handoff | Issuer-admin browser downloads the private JSON; operator browser imports it; birth date and salt are absent from issuer storage, app verifier requests, ordinary logs, results, and reports. |
| CRED-14 public request schema and signal binding | Raw JSON is at most 16 KB and rejects duplicate/missing/extra/wrongly typed keys and unknown versions. Signals are exactly requestTag, commitment, cutoff, challengeHash as decimal strings; each matches credential or stored challenge, and the tag is recomputed. Any `birthDate` or `salt` key is rejected and audited with values redacted. |
| CRED-15 local key setup | Repeated setup preserves the issuer private key and service token, app public key matches that key, and none of these `.local/` files enter Git. |
| CRED-16 issuer status wire | One authenticated loopback POST sends only ID and commitment. Valid 200 responses contain exactly active/revoked/unknown; malformed, non-200, connection, and timeout cases fail closed as `ISSUER_UNAVAILABLE` after two seconds at most, without automatic retry or response-body logging. |

## Challenge and replay (T2 and T-final)

| Case | Expected behavior |
| --- | --- |
| REPLAY-01 first valid use of a bound, unexpired challenge | One decision is recorded and the challenge is consumed atomically with that verification record. |
| REPLAY-02 repeat of a used challenge | Deny; report nonce status as `replayed`. |
| REPLAY-03 expired challenge | Deny; report nonce status as `expired`. |
| REPLAY-04 challenge from another session or credential ID | Deny. |
| REPLAY-05 concurrent submissions with the same challenge | At most one may succeed; database state and decision history remain consistent. |
| REPLAY-06 restart with unused, unexpired challenge | It remains valid until expiry. |
| REPLAY-07 restart with used challenge | It remains rejected. |
| REPLAY-08 bad issuer signature or invalid proof after early checks | Deny, consume challenge atomically with the verification record, and record a safe failure reason code in the internal audit log. |
| REPLAY-09 unauthenticated, bad CSRF, malformed/oversized, or wrong-session-binding request | Reject before signature/proof verification; challenge remains unused. |
| REPLAY-10 challenge database and audit inspection | Store only a nonce hash in the challenge row; never persist raw nonce in the challenge table, audit log, or user-facing output. |
| REPLAY-11 challenge crosses UTC midnight | A valid proof uses the cutoff stored at challenge issuance, even if verification occurs on the next UTC day; the challenge still expires after five minutes. |
| REPLAY-12 issuer status unavailable after valid signature | Return sanitized deny with `ISSUER_UNAVAILABLE` and HTTP 503, audit the reason code without the response body, and leave the challenge unused for a retry before expiry. |
| REPLAY-13 issuer definitive revoked/unknown status | Return `CREDENTIAL_REVOKED` or `CREDENTIAL_UNKNOWN`, audit the reason, and consume the challenge with the decision transaction. |

The challenge lifetime defaults to five minutes from the rules table. Signature failures, definitive issuer revoked/unknown statuses, and proof verification consume the challenge with the decision transaction. An issuer timeout, connection error, or unexpected response is the agreed exception: it fails closed but leaves the challenge retryable until expiry. Authentication, CSRF, malformed/oversized input, and wrong-session-binding rejections happen earlier and do not consume it. Challenge issuance is rate limited.

## Performance and security evidence (T3, T4, T-final)

- Record proof size, proof generation time, verifier time, and end-to-end decision latency with the exact laptop environment, number of runs, and measurement method.
- Map at least eight concrete threats to mitigations and test or review evidence. Include forged issuer data, arbitrary witness values, proof substitution, replay/race, unauthorized access, secret exposure, malformed/oversized input, and audit tampering as candidate threats.
- Exercise safe errors, unauthorized access, restart recovery, sanitized export, and administrator rule changes.
- Check every verifier response and admin/operator export against the agreed allowed-field list in the implementation plan. Exports include a fixed-enum reason code and proof size/timing measurements. Viewer results omit timings, and viewer export is denied with generic `AUTH_DENIED` and a redacted audit event.
- Verify that admin cannot generate proofs, operator cannot configure rules, review audit logs, or manage users, and only a separately authenticated issuer admin can issue or revoke credentials.
- Verify 90-day result retention from verification time, 90-day audit retention from event time, challenge purge seven days after expiry, and issuer-record purge 90 days after credential expiry. A scheduled purge must log its own audit event; audit rows are never edited during ordinary operation.
- Verify that SQLite-backed sessions survive restart, rotate on login, expire after 30 minutes inactive or eight hours total, and are deleted on logout/expiry. Cookies are `httpOnly` and `sameSite=strict`.
- Verify app and issuer account tables live in separate SQLite files, enforce unique normalized usernames and service-specific roles, and never hold plaintext passwords. Bootstrap is idempotent; wrong username and wrong password produce the same generic response and both perform scrypt work. Per-IP and per-username login limits and redacted failure audits survive the agreed lockout window.
- Verify five failures in 15 minutes trigger a persisted one-minute lockout; active-lockout attempts do not extend it; each failed attempt after expiry doubles delay up to 15 minutes; success clears that IP and username's state. Test counters across multiple usernames/IPs and a database reopen.
