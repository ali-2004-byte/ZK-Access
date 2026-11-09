# Contributor work packages

This is an issue-ready breakdown of the [implementation plan](implementation-plan.md). Member labels follow the proposal; assign names when the team confirms them. The **State** column is a progress snapshot as of 2026-11-10: **complete** means the completion check is met, **partial** identifies work already in the repository, and **not started** identifies remaining work. A dependency listed in a state still needs resolution before that part is implemented.

The repository has 39 passing automated tests and a synthetic Groth16 proof check. The app and issuer entry points still expose health checks only; there is no end-to-end credential issuance or verification workflow yet.

## Shared contract review

Before implementation pull requests, all four members review one agreed statement:

> The browser proves that the mock issuer-attested birth date makes the holder at least 18 on the server's UTC challenge-issue day, without disclosing the birth date to the verifier.

The proof must be connected to an issuer attestation and a one-time request. A comparison against a birth date typed freely by the user is not sufficient. Review the precise public inputs, private witness, issuer-binding method, and replay rule in the implementation plan before coding the interface.

## Member A: API, identity, persistence

| Task | State | Completion check |
| --- | --- | --- |
| A1. Turn the agreed role matrix into endpoint authorization checks. | **Partial:** pure role-policy functions exist; HTTP authorization and denial audits remain. | Admin configures/audits/exports/manages users but cannot prove; operator proves/views/exports but cannot configure/audit/manage users; viewer only reads sanitized results without timings; issuer admin only issues/revokes through the separate service. Denials return `AUTH_DENIED` and are audit-logged. |
| A2. Draft request, result, and audit-event schemas with stable error codes. | **Partial:** private credential and public proof-request schemas exist; result/audit schemas and full error-code enum remain. | Schemas identify private/public/sanitized fields; B and C review them. |
| A3. Implement cookie-session accounts and SQLite persistence. | **Partial:** separate account tables, password/username helpers, interactive bootstrap, and persisted login limiter exist; login, dummy verification, cookie-session, and audit routes remain. | `npm run local:accounts` prompts for missing app/issuer admin usernames and passwords of at least 12 characters; each admin creates users only in their own service. Use bounded async scrypt records, normalized unique usernames, dummy verification for unknown users, and persisted per-IP/per-username lockouts. App sessions persist across restarts, rotate on login, expire after 30 minutes inactive or eight hours absolute, and delete on logout/expiry. Cookies are `httpOnly` and `sameSite=strict`; active sessions last longer than challenges. |
| A4. Implement the separate issuer service and verification endpoints. | **Partial:** key setup, strict parsers, issuer-status client, and injectable status router exist; issuer records, persistent lookup, issuance, and verification routes remain. | Issuer login is separate and admin-only. Its browser downloads the agreed nine-field private JSON for operator import. Both services use the shared domain-separated, length-prefixed Ed25519 encoding and vectors. The private importer and public verifier parser reject duplicate/missing/extra fields. The app makes one authenticated loopback status call with a two-second timeout and fails closed on issuer outage without consuming the challenge. Issuance records contain only ID, commitment, signature, issue/expiry times, issuing admin ID, and active/revoked status; no birth date, salt, or request body is retained. Forged, malformed, expired, revoked, and unauthorized credentials fail safely. |
| A5. Add append-only audit events, scheduled retention purge, and sanitized report export. | **Not started:** retention rules are agreed, but audit/result storage, purge, and export are not implemented. | Login, configuration, submission, decision, export, failure, and administration events are traceable and redacted. Results retain 90 days from verification; audit events retain 90 days from event time; challenges purge seven days after expiry; issuer records purge 90 days after credential expiry. Purges are audit-logged. Admin/operator exports include safe reason code and proof measurements; viewer cannot export. |

## Member B: circuit, proof, fixtures

| Task | State | Completion check |
| --- | --- | --- |
| B1. Write an age-18 truth table and edge fixtures. | **Complete:** the test matrix and synthetic tests cover date boundaries, leap days, malformed dates, and invalid witnesses. | Includes day before 18th birthday, exact birthday, day after, malformed dates, leap-day cases, and invalid witnesses without real personal data. |
| B2. Review the implemented public/private circuit contract and issuer/challenge binding. | **Partial:** circuit and binding helpers are implemented; API-owner and team review remain. | A validates the contract against the API; the team can explain why the prover cannot choose an arbitrary birth date, challenge hash, or cutoff. |
| B3. Integrate browser proof generation and verifier checks around the compiled circuit. | **Partial:** circuit, committed artifacts, and synthetic proof check work; browser and HTTP verifier integration remain. | `npm run zk:setup` verifies the final proving key and `npm run zk:check` proves valid/invalid synthetic cases. Browser and API must use the identical committed WASM/key and check all public signals. Limitations explain the local single-party ceremony. |
| B4. Measure proof size, witness/proof generation time, and verification time. | **Not started:** depends on integrated browser and verifier workflow in B3. | Measurement method, environment, sample count, and raw results are recorded. |

## Member C: browser workflow and reporting

| Task | State | Completion check |
| --- | --- | --- |
| C1. Wireframe credential setup, proof request, result, history, and dashboard. | **Not started.** | Normal, adverse, denied, and failure states have clear explanations without displaying the birth date to the verifier. |
| C2. Build validated browser input and proof-generation flow in plain JavaScript. | **Partial:** private JSON validation exists as a reusable module; browser screens, import flow, and proof generation remain. | Issuer-admin browser downloads private credential JSON; operator imports it in the app browser, which handles the private birth date and salt and sends only agreed public proof material to verification. |
| C3. Build dashboard, filters, evidence view, and sanitized export UI. | **Not started:** depends on A2 result/audit schemas and A5 export data. | Status, safe reason code, evidence, recommended action, history, proof size, and timing are legible for admin/operator; viewer sees sanitized results without timings and cannot export. |
| C4. Integrate the 10-15 minute demo journey. | **Not started:** depends on A4, B3, and C3. | Valid, invalid, replay, unauthorized, rule-change, and export examples are reproducible. |

## Member D: security, automation, QA, packaging

| Task | State | Completion check |
| --- | --- | --- |
| D1. Review and complete the draft data-flow diagram and threat-model worksheet. | **Partial:** diagram and eleven-threat draft exist; instructor-scope approval and team review remain. | [Threat model](threat-model.md) lists eleven concrete threats with boundary, mitigation, and implementation/evidence status; team validates against final design and instructor scope. |
| D2. Create the test matrix for T1-T4 and T-final. | **Partial:** expected cases are documented; actual results, evidence locations, and pass/fail entries remain. | Every case records input description, expected result, actual result, evidence, and pass/fail. |
| D3. Add repeatable automated security and misuse tests. | **Partial:** 39 tests cover policies, schemas, signatures, proof fixtures, account rules, and issuer-status behavior; full HTTP authorization, replay, persistence, and recovery cases remain. | Covers role-denial audit with generic `AUTH_DENIED`, unauthorized access, malformed/oversized input, repeated submission/replay, concurrent challenge use, early rejection without consumption, invalid signature/proof and definitive issuer denial with consumption, issuer outage without consumption, revocation, and recovery after restart. |
| D4. Package local setup, sanitized fixtures, and clean-install rehearsal. | **Partial:** setup guide, scripts, and synthetic fixtures exist; teammate clean-install and restart rehearsal remain. | A teammate can follow the guide from a clean checkout on an ordinary laptop. |
| D5. Check final evidence gate. | **Not started:** requires integrated workflow and final test evidence. | At least 80% of automated tests pass and no critical authorization, injection, secret-exposure, or unsafe-file-handling defect remains unresolved. |

## Current dependency order

1. Finish A2's result and audit schemas and the remaining login, lockout-response, and CSRF contracts.
2. Wire A1/A3 authorization, login, sessions, and audit events into the two services; build A4's issuer records, challenge persistence, issuance, and verifier routes.
3. Connect B3 and C2 to the browser using the committed proof artifacts and public request contract.
4. Build A5/C3 reporting and export, then complete D3/D4 integration tests and clean-install rehearsal before D5.

## Pull request handoff checklist

Each contribution should state which task and proposal requirement it addresses, the decision IDs it depends on, how it was tested, any change to public/private data handling, and the evidence that should appear in the final report. Ask the affected owner to review a changed interface before building on it.
