# Public verification request and issuer status

The operator browser submits only public credential metadata, a Groth16 proof, and public signals. It never sends `birthDate` or `salt` to the app verifier. The raw JSON body is at most 16,384 bytes and has exactly these top-level keys: `version`, `challengeId`, `credential`, `proof`, and `publicSignals`. `version` is `"1"`; `challengeId` is an opaque server-generated ID unrelated to the nonce.

`credential` has exactly six keys: `credentialId`, `commitment`, `issuedAt`, `expiresAt`, `issuerName`, and `signature`. Their encodings match [the private credential file](credential-format.md); it has no birth date, salt, or version. `proof` has the fixed Groth16/bn128 shape emitted by the pinned snarkjs version. `publicSignals` is an array of exactly four decimal strings, in the observed order: `requestTag`, `commitment`, `cutoff`, `challengeHash`.

`src/app/verification-request.mjs` parses the raw body with duplicate-key detection, rejects missing/extra/wrongly typed fields and unknown versions, and enforces the size limit. The HTTP route must pass the raw text to this parser rather than using `express.json()` first. Any request containing a `birthDate` or `salt` key at any depth is rejected; its audit event must contain only a reason code, never field values or the request body.

After authentication, CSRF, size/shape validation, session binding, and challenge lookup, the server compares the proof's public commitment to the credential commitment, cutoff/hash to the challenge row, and request tag to Poseidon(challengeHash, commitment). It verifies the Ed25519 signature using the app's trusted issuer public key, then asks the issuer service for current credential status over loopback, then verifies the Groth16 proof against the committed verification key. The app fails closed if the issuer is unavailable or responds unexpectedly.

The status call is exactly one `POST http://127.0.0.1:<issuer-port>/internal/credential-status` with `Content-Type: application/json`, the setup-generated token in `X-ZK-Access-Service-Token`, and JSON containing exactly `credentialId` and `commitment`. The issuer matches both fields against its issuance record. A successful response is HTTP 200 with exactly `{"status":"active"}`, `{"status":"revoked"}`, or `{"status":"unknown"}`. The app waits at most two seconds and makes no automatic retry. Any connection error, timeout, non-200 status, malformed/extra response field, or oversized response becomes `ISSUER_UNAVAILABLE` in the verifier. The issuer response body never enters audit logs.

| Outcome | Sanitized reason code | Challenge handling |
| --- | --- | --- |
| Signature failure | Safe invalid-signature code, to be fixed in the result schema | Consume with decision/audit transaction |
| Issuer says revoked | `CREDENTIAL_REVOKED` | Consume with decision/audit transaction |
| Issuer says unknown | `CREDENTIAL_UNKNOWN` | Consume with decision/audit transaction |
| Issuer timeout, connection error, or unexpected response | `ISSUER_UNAVAILABLE`; HTTP 503 | Leave unused so the operator can retry until the original five-minute expiry; record sanitized deny and audit event |
| Proof verification reached, whether valid or invalid | Safe proof/decision code, to be fixed in the result schema | Consume with decision/audit transaction |

Malformed/oversized requests, unauthenticated requests, bad CSRF, and wrong-session binding are rejected before signature verification without consuming the challenge. The status service and app verifier must never log the issuer response body or private fields. `src/app/issuer-status-client.mjs` and `src/issuer/status-router.mjs` implement and test this wire contract with an injected issuer-record lookup. They are not yet connected to persistent records or the main HTTP services. The remaining verifier reason-code enum still needs approval before full route integration.

## Local service credentials

Run `npm run local:setup` once after `npm ci`. It generates an Ed25519 issuer key pair and a random 32-byte app-to-issuer service token. The issuer private key is in ignored `.local/issuer/signing-private.pem`; the trusted public key is copied to ignored `.local/app/trusted-issuer-public.pem`. The token is in ignored issuer and app config files. Re-running setup preserves existing values and rejects key/token mismatches. These paths are for the local demo; the private key and token are never committed.

Initial app-admin and separate issuer-admin accounts will be created by a local setup command. The selected driver, password parameters, normalized-username behavior, login throttling, and remaining decisions are recorded in [the account contract](account-contract.md). Account bootstrap is not implemented yet.
