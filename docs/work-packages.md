# Contributor work packages

This is an issue-ready breakdown of the [implementation plan](implementation-plan.md). Member labels follow the proposal; assign names when the team confirms them. Work marked **ready** can start with the decisions already made. Work marked **waiting** needs the listed decision, so its owner should not silently choose a value.

## Shared contract review

Before implementation pull requests, all four members review one agreed statement:

> The browser proves that the mock issuer-attested birth date makes the holder at least 18 on the server's UTC challenge-issue day, without disclosing the birth date to the verifier.

The proof must be connected to an issuer attestation and a one-time request. A comparison against a birth date typed freely by the user is not sufficient. Review the precise public inputs, private witness, issuer-binding method, and replay rule in the implementation plan before coding the interface.

## Member A: API, identity, persistence

| Task | State | Completion check |
| --- | --- | --- |
| A1. Turn the agreed role matrix into endpoint authorization checks. | Ready | Admin configures/audits/exports/manages users but cannot prove; operator proves/views/exports but cannot configure/audit/manage users; viewer only reads sanitized results without timings; issuer admin only issues/revokes through the separate service. Denials return `AUTH_DENIED` and are audit-logged. |
| A2. Draft request, result, and audit-event schemas with stable error codes. | Ready | Schemas identify private/public/sanitized fields; B and C review them. |
| A3. Implement cookie-session accounts and SQLite persistence. | Ready | App sessions persist across restarts, rotate on login, expire after 30 minutes inactive or eight hours absolute, and delete on logout/expiry. Cookies are `httpOnly` and `sameSite=strict`; active sessions last longer than challenges. Server rejects unauthorized operations and protects secrets. |
| A4. Implement the separate issuer service and verification endpoints. | Key setup and strict public request parser ready; HTTP routes, status wire format, and remaining interface details pending | Issuer login is separate and admin-only. Its browser downloads the agreed nine-field private JSON for operator import. Both services use the shared domain-separated, length-prefixed Ed25519 encoding and vectors. The private importer and public verifier parser reject duplicate/missing/extra fields. The app authenticates loopback status checks with the setup-generated token and fails closed on issuer outage without consuming the challenge. Issuance records contain only ID, commitment, signature, issue/expiry times, issuing admin ID, and active/revoked status; no birth date, salt, or request body is retained. Forged, malformed, expired, revoked, and unauthorized credentials fail safely. |
| A5. Add append-only audit events, scheduled retention purge, and sanitized report export. | Retention clocks agreed; remaining data model details pending | Login, configuration, submission, decision, export, failure, and administration events are traceable and redacted. Results retain 90 days from verification; audit events retain 90 days from event time; challenges purge seven days after expiry; issuer records purge 90 days after credential expiry. Purges are audit-logged. Admin/operator exports include safe reason code and proof measurements; viewer cannot export. |

## Member B: circuit, proof, fixtures

| Task | State | Completion check |
| --- | --- | --- |
| B1. Write an age-18 truth table and edge fixtures. | Ready | Includes day before 18th birthday, exact birthday, day after, malformed dates, leap-day cases, and invalid witnesses without real personal data. |
| B2. Review the implemented public/private circuit contract and issuer/challenge binding. | Ready for review | A validates the contract against the API; the team can explain why the prover cannot choose an arbitrary birth date, challenge hash, or cutoff. |
| B3. Integrate browser proof generation and verifier checks around the compiled circuit. | Circuit and artifacts built; browser/API integration waiting | `npm run zk:setup` verifies the final proving key and `npm run zk:check` proves valid/invalid synthetic cases. Browser and API must use the identical committed WASM/key and check all public signals. Limitations explain the local single-party ceremony. |
| B4. Measure proof size, witness/proof generation time, and verification time. | Waiting on B3 | Measurement method, environment, sample count, and raw results are recorded. |

## Member C: browser workflow and reporting

| Task | State | Completion check |
| --- | --- | --- |
| C1. Wireframe credential setup, proof request, result, history, and dashboard. | Ready | Normal, adverse, denied, and failure states have clear explanations without displaying the birth date to the verifier. |
| C2. Build validated browser input and proof-generation flow in plain JavaScript. | Private JSON parser ready; waiting on A2 and browser integration | Issuer-admin browser downloads private credential JSON; operator imports it in the app browser, which handles the private birth date and salt and sends only agreed public proof material to verification. |
| C3. Build dashboard, filters, evidence view, and sanitized export UI. | Waiting on A2 | Status, safe reason code, evidence, recommended action, history, proof size, and timing are legible for admin/operator; viewer sees sanitized results without timings and cannot export. |
| C4. Integrate the 10-15 minute demo journey. | Waiting on A4/B3/C3 | Valid, invalid, replay, unauthorized, rule-change, and export examples are reproducible. |

## Member D: security, automation, QA, packaging

| Task | State | Completion check |
| --- | --- | --- |
| D1. Draft data-flow diagram and threat-model worksheet. | Ready | At least eight concrete threats identify trust boundary, mitigation, and verification evidence; team validates against final design. |
| D2. Create the test matrix for T1-T4 and T-final. | Ready | Every case records input description, expected result, actual result, evidence, and pass/fail. |
| D3. Add repeatable automated security and misuse tests. | Waiting on HTTP and database interfaces | Covers role-denial audit with generic `AUTH_DENIED`, unauthorized access, malformed/oversized input, repeated submission/replay, concurrent challenge use, early rejection without consumption, invalid signature/proof and definitive issuer denial with consumption, issuer outage without consumption, revocation, and recovery after restart. |
| D4. Package local setup, sanitized fixtures, and clean-install rehearsal. | Waiting on stack details | A teammate can follow the guide from a clean checkout on an ordinary laptop. |
| D5. Check final evidence gate. | Waiting on integration | At least 80% of automated tests pass and no critical authorization, injection, secret-exposure, or unsafe-file-handling defect remains unresolved. |

## Pull request handoff checklist

Each contribution should state which task and proposal requirement it addresses, the decision IDs it depends on, how it was tested, any change to public/private data handling, and the evidence that should appear in the final report. Ask the affected owner to review a changed interface before building on it.
