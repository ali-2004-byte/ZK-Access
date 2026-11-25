# API, result, and audit contract (draft for B and C review)

This contract covers work package A2. It fixes the endpoint table, request shapes, stable error codes, the verification result schema, and the audit event schema. Members B and C should review it before building on it. Code that enforces it lives in `src/contracts/`; tests are in `test/contracts.test.mjs`.

## Field classes

Every field in the system belongs to one class. A field may only move toward a less restricted class through the projections described below.

| Class | Fields | Where it may exist |
| --- | --- | --- |
| Private | `birthDate`, `salt` | Issuer-admin browser, the issuer process during one issuance request (never stored), the downloaded credential file, and the operator browser. Never sent to the app. |
| Transient public | `commitment`, `signature`, `issuedAt`, `expiresAt`, Groth16 `proof`, `publicSignals`, raw nonce, issuer status response body | App memory while one request is processed. Never in app results, exports, ordinary logs, or audit events. The issuer's restricted issuance record keeps commitment and signature (D2). |
| Internal | `actorAccountId`, `engineVersion`, challenge rows, session rows, password records, lockout counters | App or issuer database only. Never returned by result or export endpoints. |
| Sanitized | `resultId`, `decision`, `reasonCode`, `ruleName`, `ruleVersion`, `nonceStatus`, `verifiedAt`, `credentialId`, `issuerName`, `credentialExpiryStatus` | Result views for admin, operator, and viewer; admin/operator exports. |
| Measurement | `proofSizeBytes`, `proofGenerationMs`, `verificationMs`, `decisionLatencyMs` | Admin/operator result views, dashboard, and exports. Never shown to viewer. |

## Endpoints

All bodies are JSON. Every endpoint except login checks the server-side session first, then the role permission, then CSRF for state-changing methods, then the body. Permission names are the actions in `src/app/access-policy.mjs`. The tables below are declared in `src/app/endpoints.mjs` and `src/issuer/endpoints.mjs`; `src/http/authorization.mjs` enforces them. A role from the other service's session is denied. Declared routes without a handler yet return `NOT_IMPLEMENTED` after the permission check.

### App service (`127.0.0.1:3000`)

| Method and path | Permission | Request body |
| --- | --- | --- |
| `POST /api/session/login` | none | `{ "username": string, "password": string }` |
| `POST /api/session/logout` | any signed-in role | none |
| `GET /api/session` | any signed-in role | none; returns `{ accountId, role, csrfToken }` |
| `POST /api/challenges` | `request_challenge` | `{ "credentialId": string }` |
| `POST /api/verifications` | `submit_proof` | the public request in [the verification contract](verification-contract.md), plus measurements below |
| `GET /api/results` | `view_results` | none; query filters `decision`, `reasonCode`, `from`, `to` |
| `GET /api/results/:resultId` | `view_results` | none |
| `GET /api/reports/export` | `export_report` | none; query `format=csv` or `format=json`, plus the result filters |
| `GET /api/rules` | `configure_rules` | none |
| `PUT /api/rules` | `configure_rules` | `{ "minimumAge": integer, "challengeLifetimeSeconds": integer, "confirm": boolean }` |
| `GET /api/audit-events` | `review_audit` | none; query `type`, `from`, `to` |
| `GET /api/users` | `manage_users` | none |
| `POST /api/users` | `manage_users` | `{ "username": string, "password": string, "role": "operator" \| "viewer" }` |
| `PATCH /api/users/:accountId` | `manage_users` | `{ "role"?: string, "disabled"?: boolean }` |

High-impact rule changes (a lower minimum age or a longer challenge lifetime) without `"confirm": true` return `CONFIRMATION_REQUIRED` and change nothing.

The proof measurements are carried outside the signed and proven material because the browser reports them. `POST /api/verifications` therefore accepts one optional top-level field, `clientMeasurements: { "proofGenerationMs": integer }`. The parser in `src/app/verification-request.mjs` must be extended for it when the route is built (owner: A, reviewer: B). The server measures `proofSizeBytes`, `verificationMs`, and `decisionLatencyMs` itself.

### Issuer service (`127.0.0.1:3001`)

| Method and path | Permission | Request body |
| --- | --- | --- |
| `POST /api/session/login` | none | `{ "username": string, "password": string }` |
| `POST /api/session/logout` | any signed-in issuer account | none |
| `GET /api/session` | any signed-in issuer account | none |
| `POST /api/credentials` | `issue_credential` | `{ "version": "1", "birthDate": "YYYY-MM-DD", "salt": decimal string }`; returns the nine-field private credential JSON |
| `POST /api/credentials/:credentialId/revoke` | `revoke_credential` | none |
| `POST /internal/credential-status` | service token | as in [the verification contract](verification-contract.md) |

The issuance request is the only place where a private field crosses a network boundary. The issuer parses it strictly, computes the commitment, signs, stores only the D2 issuance record, and must not log or retain the body.

## Error responses

An error response is HTTP status plus exactly `{ "code": "<CODE>" }`. It has no message, stack trace, or echo of input. `src/contracts/error-codes.mjs` holds the enum.

| Code | HTTP | Meaning |
| --- | --- | --- |
| `AUTH_REQUIRED` | 401 | No valid session. The browser should show the login screen. |
| `AUTH_DENIED` | 403 | Signed in, but the role lacks permission. Always audited. |
| `CSRF_INVALID` | 403 | Missing or wrong CSRF token on a state-changing request. |
| `LOGIN_FAILED` | 401 | Wrong username or password; the two cases are indistinguishable. |
| `LOGIN_LOCKED` | 429 | Login lockout is active; `Retry-After` gives whole seconds. Unknown usernames lock the same way. |
| `RATE_LIMITED` | 429 | Challenge issuance or another limited action is over its limit. |
| `MALFORMED_INPUT` | 400 | Body or query failed the strict schema. |
| `PRIVATE_FIELD_SUBMITTED` | 400 | A `birthDate` or `salt` key reached the app. Audited without values. |
| `PAYLOAD_TOO_LARGE` | 413 | Body exceeds the endpoint limit. |
| `UNSUPPORTED_MEDIA_TYPE` | 415 | Body is not `application/json`. |
| `CONFIRMATION_REQUIRED` | 409 | A high-impact change was sent without confirmation. |
| `CONFLICT` | 409 | Normalized username already exists. |
| `CHALLENGE_NOT_FOUND` | 404 | Challenge ID is unknown or bound to another session or credential. The same code covers all three so one session cannot probe another's challenges. The challenge is not consumed. |
| `NOT_FOUND` | 404 | Unknown route or record. |
| `NOT_IMPLEMENTED` | 501 | Route is declared but its handler is not built yet. |
| `INTERNAL_ERROR` | 500 | Unexpected server error. |

## Verification result

A request that passes authentication, CSRF, shape, and challenge lookup always produces a recorded result. `src/contracts/verification-result.mjs` builds the stored record and rejects any field outside this schema, so a commitment or signature passed by mistake fails at once instead of being stored.

The verifier checks in this order: challenge state, public signals against the challenge and credential, Ed25519 signature, credential expiry, issuer status, Groth16 proof. The first failure decides the reason code.

| Reason code | Decision | Challenge | HTTP |
| --- | --- | --- | --- |
| `PROOF_VALID` | allow | consumed | 200 |
| `PROOF_INVALID` | deny | consumed | 200 |
| `SIGNALS_MISMATCH` | deny | consumed | 200 |
| `SIGNATURE_INVALID` | deny | consumed | 200 |
| `CREDENTIAL_EXPIRED` | deny | consumed | 200 |
| `CREDENTIAL_REVOKED` | deny | consumed | 200 |
| `CREDENTIAL_UNKNOWN` | deny | consumed | 200 |
| `ISSUER_UNAVAILABLE` | deny | left unused for retry | 503 |
| `CHALLENGE_REPLAYED` | deny | already used | 200 |
| `CHALLENGE_EXPIRED` | deny | already expired | 200 |

`SIGNALS_MISMATCH` and `CREDENTIAL_EXPIRED` are new in this draft. A mismatch means the submitted signals do not open this challenge; consuming it follows the same rule as an invalid proof. Expiry is checked after the signature so the expiry value is authenticated.

Stored record fields:

| Field | Type | Class |
| --- | --- | --- |
| `resultId` | opaque ID | sanitized |
| `decision` | `allow` or `deny`, fixed by the reason code | sanitized |
| `reasonCode` | one code from the table above | sanitized |
| `ruleName`, `ruleVersion` | rule in force when the challenge was issued | sanitized |
| `nonceStatus` | `fresh`, `replayed`, or `expired`, fixed by the reason code | sanitized |
| `verifiedAt` | Unix milliseconds | sanitized |
| `credentialId` | opaque issuer-generated ID | sanitized |
| `issuerName` | always `ZK Access Demo Issuer` | sanitized |
| `credentialExpiryStatus` | `valid`, `expired`, or `not_checked` when the decision came before the signature check | sanitized |
| `measurements.proofSizeBytes` | integer or null | measurement |
| `measurements.proofGenerationMs` | integer or null (browser-reported) | measurement |
| `measurements.verificationMs` | integer or null (null when no proof was verified) | measurement |
| `measurements.decisionLatencyMs` | integer | measurement |
| `actorAccountId` | operator account ID | internal |
| `engineVersion` | circuit and verifier version, e.g. `age18-groth16-v1` | internal |

`projectResult(result, role)` returns sanitized and measurement fields, flattened, for admin and operator; sanitized fields only for viewer; and throws for any other role. Exports use the admin/operator projection.

## Audit events

Each service writes to its own append-only audit table. Rows are never updated; only the scheduled retention purge deletes them, and the purge writes its own `retention.purged` event. `src/contracts/audit-event.mjs` builds events.

| Field | Content |
| --- | --- |
| `eventId` | random UUID |
| `service` | `app` or `issuer` |
| `type` | one of the types below |
| `occurredAt` | Unix milliseconds |
| `actor` | `{ kind: "account", accountId, role }`, `{ kind: "anonymous" }`, `{ kind: "system" }`, or `{ kind: "service" }` |
| `outcome` | `success`, `denied`, or `failure` |
| `code` | an API error code, a reason code, or null |
| `context` | flat object of allowlisted keys only |

Event types for both services: `auth.login_succeeded`, `auth.login_failed`, `auth.login_locked`, `auth.logout`, `auth.session_expired`, `authz.denied`, `csrf.rejected`, `users.created`, `users.updated`, `retention.purged`. App only: `rules.changed`, `audit.viewed`, `challenge.issued`, `verification.rejected`, `verification.decided`, `report.exported`. Issuer only: `credential.issued`, `credential.revoked`, `credential.issue_rejected`.

Allowed context keys: `action`, `method`, `route` (pattern such as `/api/results/:resultId`, never a raw URL), `role`, `targetAccountId`, `usernameHash`, `ipHash`, `lockoutSeconds`, `challengeId`, `resultId`, `credentialId`, `ruleName`, `ruleVersion`, `previousRuleVersion`, `confirmed`, `format`, `rowCount`, `table`, and `note` (128 printable ASCII characters). Any other key is refused, including username, password, birth date, salt, commitment, signature, proof, nonce, token, and body. `usernameHash` and `ipHash` are 64-character hex digests; A3 should compute them with HMAC-SHA256 under a local key in `.local/` so short usernames cannot be reversed by guessing.

## Open questions for review

1. B: is the check order above compatible with the verifier you are building, and is `engineVersion` the right place for the circuit version?
2. C: are the sanitized and measurement fields enough for the dashboard and evidence view? Does the UI need `AUTH_REQUIRED` separate from `AUTH_DENIED`?
3. All: should `SIGNALS_MISMATCH` consume the challenge, as drafted, or be an early rejection?
