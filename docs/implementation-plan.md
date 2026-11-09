# ZK Access implementation plan (draft)

Status: requirements extracted from the supplied three-page proposal; some implementation decisions remain pending. This document is a planning aid, not an instruction from the proposal to use a particular design.

Confirmed by the project owner: the demo proves age at least 18 from a mock issuer-attested birth date. The browser generates proofs with Circom, snarkjs, and Groth16. The app uses Node.js, Express, SQLite, cookie sessions, and plain JavaScript with four team members. The mock issuer runs as a separate local service, validates the calendar date, signs a Poseidon commitment and credential metadata with Ed25519, and issues credentials valid for 90 days. The server computes the age-18 cutoff from its UTC date when it issues a challenge, stores that cutoff with the challenge, and uses the stored cutoff at verification even across midnight. Feb 29 birthdays reach age 18 on Mar 1 in a non-leap year. Challenges are database-backed, session- and credential-bound, single-use, and default to five minutes. Remaining interface choices are listed below.

## Required outcome

Build a functioning, locally demonstrable web system in which a user proves an eligibility attribute without disclosing the underlying private value. A reviewer must be able to reproduce an explainable verification decision and inspect sanitized evidence. The system needs a responsive browser interface, local API, persistent store, dedicated security/proof engine, evidence view, and exportable result. It must run on ordinary laptops from VS Code; Docker is optional.

The proposal lists six functional modules, in this order: credential setup; circuit or educational proof workflow; proof generation; verifier; replay protection; and performance dashboard. Each must validate input, return a clear result, and record security-relevant actions without retaining unnecessary sensitive data. A mock-up alone will not meet the proposal.

## Decision register and remaining questions

Confirmed values below came from the project owner. Questions in the same rows remain open; a proposed value should not be treated as agreed until the team records an answer.

| ID | Decision | Why it blocks work |
| --- | --- | --- |
| D1 | Age at least 18; server UTC challenge-issue date determines the cutoff, which is stored with the five-minute challenge and remains authoritative at verification. Feb 29 birthdays reach 18 on Mar 1 in non-leap years. If challenge issuance is Feb 29 and the cutoff year lacks that date, use Feb 28. The server clock must be injectable for tests. | Defines date edge-case fixtures. |
| D2 | A separate local mock issuer service named `ZK Access Demo Issuer` validates the birth date as a calendar date, encodes it as a YYYYMMDD integer, and signs `credential ID, Poseidon(encoded birth date, browser-generated random salt), issue time, expiry time, issuer name` with Ed25519. Its issuance API requires a separate issuer-admin login. The issuer-admin browser downloads a private credential JSON file, which the operator later imports in the app browser for proof generation. The issuer retains only credential ID, commitment, signature, issue time, expiry time, issuing admin ID, and active/revoked status in an issuance record. It never retains birth date, salt, or request body. The nine-field private JSON format is fixed in [the credential file contract](credential-format.md). This replaces the earlier no-records answer. | Defines credential setup and issuer trust. |
| D3 | Circom, snarkjs, and Groth16 selected. `npm run zk:setup` compiles the circuit, creates a small local Powers of Tau file, contributes to phases 1 and 2, verifies the final key, and exports `verification_key.json`. Circom 2.2.3, snarkjs 0.7.6, and circomlib 2.0.5 are pinned. The circuit, final proving key, witness WASM, verification key, and hash manifest belong in Git so teammates use identical artifacts. The single-party local ceremony is documented as non-production. | Defines setup and reproducibility. |
| D4 | Verifier output/export field policy is agreed below. A safe fixed-enum reason code is allowed in verifier output and admin/operator exports. Proof size and timing measurements appear on the admin/operator dashboard and in their exports; viewer results exclude timings. API may process commitment and issuer signature transiently; they must not enter ordinary logs, output, or exports. | Defines the internal verification boundary. |
| D5 | Challenges are bound to issuing session and credential ID, persist in the database in issued/used/expired states, and expire after a rules-table value defaulting to five minutes. The challenge row stores issue timestamp, age cutoff, and `challengeHash`, derived from the first 31 bytes of SHA-256 of a transient random nonce. Raw nonce is never persisted. Circuit public inputs are the signed commitment, stored cutoff, and 248-bit challengeHash; its public output `requestTag` is constrained to Poseidon(challengeHash, commitment). The API recomputes that tag, compares public cutoff/hash with its challenge row, and verifies Ed25519 outside the circuit. Signature failures, definitive issuer revoked/unknown statuses, and any proof verification consume the challenge with an atomic decision/audit transaction. An issuer timeout, connection failure, or unexpected response produces a sanitized deny but leaves the challenge retryable until expiry. Earlier authentication, CSRF, malformed/oversized input, or wrong-session-binding rejection does not consume. Unexpired unused challenges survive restart; used and expired remain rejected. Challenge issuance is rate limited. | Defines challenge and audit behavior. |
| D6 | SQLite-backed app sessions persist across restarts. They expire after 30 minutes of inactivity or eight hours total, whichever comes first; cookies are `httpOnly` and `sameSite=strict`, session IDs are generated server-side and rotated on login, and logout/expiry delete the session row. Session lifetime must exceed the five-minute challenge lifetime. The role matrix below is selected. Admin configures rules/thresholds with confirmation for high-impact changes, reviews audit logs, views all sanitized results, exports sanitized reports, and manages users; admin does not generate proofs. Operator logs in, requests challenges, runs proof/verification, views results/history, and exports sanitized reports; operator cannot change rules, view audit logs, or manage users. Viewer reads sanitized results only and cannot export. Issuance uses the separate issuer-admin login. Every endpoint enforces its permission server-side; denied requests return generic `AUTH_DENIED` and are audit-logged. | Determines session and authorization behavior. |
| D7 | Node.js/Express/SQLite/plain JavaScript selected for the app. Are there instructor constraints on proof tools or dependencies? | Determines proof tooling and run commands. |
| D8 | Four-person team confirmed. Who are Members A-D? | Determines named task ownership. |
| D9 | Credential expiry is 90 days after issuance. Each verification result is retained for 90 days from its creation/verification timestamp; each audit event is retained for 90 days from its event timestamp. Issued/used/expired challenges are purged seven days after their expiry; issuer credential metadata is retained until 90 days after credential expiry. Audit events are append-only and are deleted only by the scheduled retention purge, which is audit-logged. The challenge database stores a nonce hash, and raw nonces are never persisted, including in the audit log. | Determines storage and purge behavior. |
| D10 | What sample input and threat-model scope has the instructor approved? | Determines safe fixtures and adverse cases. |
| D11 | Ed25519 signs a domain-separated, length-prefixed binary payload. The exact bytes are the ASCII tag `ZKACCESS-CRED-V1`, followed by credential ID (UTF-8), commitment (ASCII decimal without leading zeros), issue time (ASCII decimal Unix seconds, UTC), expiry time (same encoding), and issuer name (UTF-8). Each of the five fields has a four-byte unsigned big-endian byte-length prefix. The issuer and verifier use the same encoder and fixed vectors. The private-file importer and public-request parser reject duplicate, missing, or extra fields; the verifier rejects any signature over different bytes. | Defines issuer/verifier interoperability. |
| D12 | Local setup generates one persistent Ed25519 issuer key. Its private key stays in an ignored issuer-only file; its public key is copied into ignored app configuration. Setup also generates a random service token in ignored app/issuer config files. The app makes one authenticated `POST /internal/credential-status` call over loopback with ID and commitment, a two-second timeout, and no automatic retry. The issuer returns only active/revoked/unknown and matches both fields. The exact wire and failure behavior are in [the verification contract](verification-contract.md). | Defines key trust, revocation, and public input handling. |
| D13 | A local setup command prompts for separate app-admin and issuer-admin passwords. Thereafter each admin creates users only within their own service. Password hashing, username policy, and database isolation remain open. | Defines initial identity bootstrap. |

Decision record format: `ID | chosen answer | reason | approved by/date | affected interfaces/tests`. If an answer changes, keep the prior entry and add a new dated entry so evidence remains traceable.

### Proof-route assessment for D3

| Route | Fit for an age-threshold claim | Work and limitation |
| --- | --- | --- |
| Circom + snarkjs | A circuit can constrain a private birth date or age calculation against a public threshold and output only the allowed public result. | Requires circuit constraints, proving artifacts, a verification key, and setup. The proof must be bound to an issuer-attested value and a one-time request; otherwise it only proves a user-chosen value passed the comparison. |
| Educational Sigma protocol | A purpose-built range proof can prove a committed number is in a range. | A basic proof of secret knowledge does not by itself prove an age inequality. Implementing and reviewing a suitable range proof and issuer binding is additional cryptographic work. An interactive challenge can support one-time use, but the server still needs replay state. |

Circom, snarkjs, and Groth16 are selected. The comparison is retained to explain the decision. The signed credential fields and challenge lifecycle are recorded above. Sources: [Circom public/private signals](https://docs.circom.io/circom-language/signals/), [circomlib comparison components](https://github.com/iden3/circomlib/blob/master/circuits/comparators.circom), [snarkjs setup and verification](https://github.com/iden3/snarkjs/blob/master/README.md), [Stanford Sigma protocol notes](https://crypto.stanford.edu/cs355/19sp/lec6.pdf), and [Stanford applied cryptography text on range proofs](https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_4.pdf).

### Circuit contract now implemented

`circuits/age18.circom` takes private `birthDate` (a YYYYMMDD integer) and `salt`; public `commitment`, `cutoff` (YYYYMMDD integer), and `challengeHash` (248 bits); and emits public `requestTag`. It constrains Poseidon(birthDate, salt) to the commitment, independently range-checks birth date and cutoff to 32 bits, proves birthDate <= cutoff, range-checks challengeHash to 248 bits, and constrains requestTag = Poseidon(challengeHash, commitment). The issuer validates the Gregorian calendar date before signing; the circuit does not perform calendar validation. The server must compare every public input/output to its stored challenge and signed credential before accepting a proof.

### Issuer handoff and signed bytes

The separately authenticated issuer-admin browser handles the synthetic birth date and browser-generated salt, requests issuance, and downloads a private credential JSON file. The operator imports that file in the app browser and generates the proof there. The issuer must not retain the birth date, salt, or request body. The downloaded file contains private witness material, so the browser must not send those fields to the app verifier, write them to ordinary logs, or include them in reports. The exact nine-field schema and signature encoding are recorded in [the credential file contract](credential-format.md).

`src/credential-signing.mjs` is the shared binary encoder and Ed25519 sign/verify helper. It takes exactly five ordered string fields, prepends the ASCII domain tag, and prefixes each UTF-8/ASCII byte sequence with its four-byte big-endian length. Fixed byte and signature vectors are in `test/credential-signing.test.mjs`. The private JSON importer already rejects duplicate, missing, and extra fields. The public verifier request schema must be finalized and must enforce the same strict-shape principle before calling the signature helper.

### Agreed verifier output and export policy

The verifier output may contain: allow/deny decision; rule name and version; nonce status (`fresh`, `replayed`, or `expired`), without the raw nonce; verification timestamp; an opaque server-generated credential ID; the fixed name `ZK Access Demo Issuer`; credential expiry status (`valid` or `expired`), without the expiry value; and a safe fixed-enum reason code. The admin/operator performance dashboard and exported report additionally include proof size and timing measurements. The viewer receives a read-only projection of sanitized results without timing fields and cannot export. Birth date, salt, commitment value, issuer signature, and raw nonce must never appear in verifier output or exported reports. The API may process the commitment and issuer signature transiently to check the issuer attestation; the issuer's own restricted issuance record retains the D2 metadata. Commitment, signature, and raw nonce must not enter ordinary logs; raw nonce is also excluded from the internal audit log under the latest decision.

### Server-enforced role matrix

| Action | App admin | Operator | Viewer | Issuer admin |
| --- | --- | --- | --- | --- |
| Configure rules/thresholds, manage app users | Allow, with confirmation for high-impact changes | Deny | Deny | Deny |
| Review app audit log | Allow | Deny | Deny | Deny |
| Request challenge and generate/submit proof | Deny | Allow | Deny | Deny |
| View sanitized results/history | Allow | Allow | Allow, without timings | Deny |
| Export sanitized report with reason code and measurements | Allow | Allow | Deny | Deny |
| Issue or revoke credentials in separate issuer service | Deny | Deny | Deny | Allow |

Denied requests return generic `AUTH_DENIED` and create a redacted audit event. The issuer-admin login is separate from app accounts.

## Architecture required by the proposal

```text
Browser interface
  -> API/service (authentication, authorization, validation, safe errors)
  -> dedicated security/proof engine (independently testable)
  -> repository (application records and append-only audit events)

Safe test fixtures exercise each layer and the complete workflow.
```

Trust boundaries to show in the data-flow diagram: browser to app server, browser to separate issuer service at issuance, app server to proof verifier, app server to SQLite, and issuer service to its restricted issuance records and signing key. Show where private values, public proof inputs, proofs, results, session material, and audit events flow. The issuer sees birth date and salt during issuance but retains neither; the verifier never receives the birth date or salt.

Define and review these contracts before screens are built:

- Roles and permissions for each operation, enforced by the API.
- Input and normalization schema for credential setup and proof requests, including server-side limits.
- Public statement and witness schema, with private/public separation explicit.
- Verification result schema: status, decision, reason, supporting evidence, proof/engine version, configured rule or threshold, and measurement references. Include only fields the chosen approach can justify.
- Append-only audit-event schema: event type, actor or safe identifier, timestamp, outcome, and redacted context. Do not store a raw private witness merely to explain a result.
- Persistent records needed for accounts, configuration, replay protection, result history, and export, subject to D5 and D9.
- Scheduled retention purge for application results, app audit events, challenges, and issuer metadata, with an audit event for each purge run and no ordinary edits to audit events.
- Stable API error codes and safe error responses; no stack traces to clients.
- Audit coverage for login, configuration change, submission, decision, export, failure, and administrative activity, with secrets and unnecessary personal information redacted.

The API must cover authentication, submission/import, proof or policy execution, result retrieval, administration, and report export. Endpoint paths and payload shapes remain open until the contracts are agreed.

## Workstreams and handoffs

| Workstream | Proposal owner | First deliverable | Handoff needed |
| --- | --- | --- | --- |
| Backend, data, authentication | Member A | Role matrix, schemas, API contract, repository and audit design | Agreed claim and engine inputs from B; result needs from C |
| Proof engine and evaluation fixtures | Member B | Statement/witness contract, independent engine tests, safe fixtures | Credential trust decision; API contract from A |
| Frontend, reporting, integration | Member C | Workflow wireframes and evidence/report field list | Schemas and permissions from A; explainable output from B |
| Automation, security testing, packaging, QA | Member D if four people | Repeatable test plan, threat-model draft, local run checklist | Interfaces and fixtures from A-C |

The four-person team has a D workstream. Assign names to A-D when available. Everyone should rehearse the complete system and be able to explain the security boundary and limitations.

## Five-week sequence from the proposal

### Week 1: agree the design

- Answer D1-D13, with instructor approval where required.
- Draw architecture and data-flow diagrams with trust boundaries.
- Write a threat model with at least eight concrete threats, each mapped to a mitigation and verification method. Candidate topics are authorization, credential forgery, proof misuse, replay, secret exposure, injection/unsafe input, audit tampering, and availability; refine these against the chosen design.
- Define roles, schemas, audit format, error codes, fixtures, wireframes, and module acceptance examples.

### Week 2: runnable vertical slice

- Create the app and setup guide using the agreed Node.js/Express/SQLite/plain JavaScript stack.
- Implement authentication and server-side role checks, then API and storage skeleton.
- Connect one safe credential input through validation to a result and audit event. Mark any temporary result as a development placeholder and keep it out of final evidence.
- Check that invalid and unauthorized inputs are rejected before processing.

### Week 3: complete security workflow

- Implement credential setup, selected proof workflow, proof generation, independent verification, and replay protection.
- Connect dashboard, result history, filters, evidence display, and sanitized export.
- Show status, supporting evidence, recommended action, and severity/confidence where relevant. Require server authorization and user confirmation for high-impact actions.
- Store rule/threshold and engine version with each decision for reproducibility.
- Show a permitted administrator configuration change and its audit trace.

### Week 4: evaluate and harden

- Run valid/invalid witness and replay tests, malformed/oversized input tests, unauthorized requests, repeated submissions, safe failure, and restart recovery.
- Measure proof generation time, verification time, proof size, and decision latency with a documented method and environment.
- Check password/identity controls, session expiry, rate limiting, protected secrets, safe errors, query parameterization, upload validation if uploads exist, and CSRF protection if cookie sessions are used.
- Review accessibility and the 10-15 minute demo path.

### Week 5: evidence and delivery

- Fix defects; rerun tests and collect results. The proposal's review threshold is at least 80% automated tests passing and zero unresolved critical authorization, injection, secret-exposure, or unsafe-file-handling defects.
- Finish setup, user/admin guides, sanitized sample data, diagrams, threat model, test plan/results, limitations and ethics statement, final report, and demo script.
- Verify every report claim has a linked test, screenshot, log excerpt, or measurement. Rehearse a clean install and restart on a teammate's laptop.

## Acceptance and evidence checklist

| Case | Required evidence to capture |
| --- | --- |
| T1 valid/invalid witnesses | Input description without unnecessary private data, expected result, actual result, explanation, pass/fail. |
| T2 replay attempts | Initial challenge/proof and repeat attempt, expected/actual result, evidence, pass/fail. |
| T3 proof size and timing | Measurement method, environment, sample count, recorded values, expected/actual result, pass/fail. |
| T4 threat-model analysis | At least eight threats with trust boundary, mitigation, verification evidence, and pass/fail. |
| T-final misuse and recovery | Malformed/oversized input, unauthorized request, repeated submission, safe failure, and recovery after restart. |
| Example demo | Normal sample, adverse sample with specific reason, viewer denied an export or audit request with redacted audit event, history comparison, sanitized admin/operator export, admin rule change followed by operator retest and trace. |

For quantitative behavior, report suitable accuracy/error and performance measures. For rule-based behavior, report coverage, false positives, false negatives, and decision latency. Only claim a measure when the selected design and fixtures make it meaningful; document its denominator and method.

## Repository setup after decisions

With the core choices recorded, build the source, fixture, test, documentation, and local configuration layout from the agreed contracts. The first pull requests should be (1) agreed contracts and threat model, (2) runnable vertical slice with safe fixtures, and (3) proof engine and adversarial cases. Each pull request should state which proposal requirement and acceptance case it advances, how it was tested, and whether it changes private/public data handling. Do not commit secrets, real credentials, or raw private witnesses.
