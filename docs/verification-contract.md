# Public verification request and issuer status

The operator browser submits only public credential metadata, a Groth16 proof, and public signals. It never sends `birthDate` or `salt` to the app verifier. The raw JSON body is at most 16,384 bytes and has the required top-level keys `version`, `challengeId`, `credential`, `proof`, and `publicSignals`, plus the optional `clientMeasurements` field defined in the API contract. `version` is `"1"`; `challengeId` is an opaque server-generated ID unrelated to the nonce.

`credential` has exactly six keys: `credentialId`, `commitment`, `issuedAt`, `expiresAt`, `issuerName`, and `signature`. Their encodings match [the private credential file](credential-format.md); it has no birth date, salt, or version. `proof` has the fixed Groth16/bn128 shape emitted by the pinned snarkjs version. `publicSignals` is an array of exactly four decimal strings, in the observed order: `requestTag`, `commitment`, `cutoff`, `challengeHash`.

`src/app/verification-request.mjs` parses the raw body with duplicate-key detection, rejects missing/extra/wrongly typed fields and unknown versions, and enforces the size limit. The HTTP route must pass the raw text to this parser rather than using `express.json()` first. Any request containing a `birthDate` or `salt` key at any depth is rejected; its audit event must contain only a reason code, never field values or the request body.

After authentication, CSRF, size/shape validation, session binding, and challenge lookup, the server compares the proof's public commitment to the credential commitment, cutoff/hash to the challenge row, and request tag to Poseidon(challengeHash, commitment). It verifies the Ed25519 signature using the app's trusted issuer public key, then asks the issuer service for current credential status over loopback, then verifies the Groth16 proof against the committed verification key. The app fails closed if the issuer is unavailable or responds unexpectedly.

The status call is exactly one `POST http://127.0.0.1:<issuer-port>/internal/credential-status` with `Content-Type: application/json`, the setup-generated token in `X-ZK-Access-Service-Token`, and JSON containing exactly `credentialId` and `commitment`. The issuer matches both fields against its issuance record. A successful response is HTTP 200 with exactly `{"status":"active"}`, `{"status":"revoked"}`, or `{"status":"unknown"}`. The app waits at most two seconds and makes no automatic retry. Any connection error, timeout, non-200 status, malformed/extra response field, or oversized response becomes `ISSUER_UNAVAILABLE` in the verifier. The issuer response body never enters audit logs.

| Outcome | Sanitized reason code | Challenge handling |
| --- | --- | --- |
| Signature failure | `SIGNATURE_INVALID` | Consume with decision/audit transaction |
| Issuer says revoked | `CREDENTIAL_REVOKED` | Consume with decision/audit transaction |
| Issuer says unknown | `CREDENTIAL_UNKNOWN` | Consume with decision/audit transaction |
| Issuer timeout, connection error, or unexpected response | `ISSUER_UNAVAILABLE`; HTTP 503 | Leave unused so the operator can retry until the original five-minute expiry; record sanitized deny and audit event |
| Proof verification reached, whether valid or invalid | `PROOF_VALID` or `PROOF_INVALID` | Consume with decision/audit transaction |

Malformed/oversized requests, unauthenticated requests, bad CSRF, and wrong-session binding are rejected before signature verification without consuming the challenge. The status service and app verifier must never log the issuer response body or private fields. `src/app/issuer-status-client.mjs` and `src/issuer/status-router.mjs` implement and test this wire contract with an injected issuer-record lookup. The issuer mounts the status route against its issuance records when started with the service token, and `POST /api/verifications` in the app calls the client after the signature check. The full reason-code enum, including `SIGNALS_MISMATCH` and `CREDENTIAL_EXPIRED`, is drafted in [the API contract](api-contract.md) and reviewed by Member B.

## Circuit contract and binding guarantees

`circuits/age18.circom` defines the Groth16 relation `Age18`:

- **Private witness (never leaves the browser):** `birthDate` (8-digit `YYYYMMDD` integer, 32-bit range-checked) and `salt` (BN254 scalar field element).
- **Public signals, in exact snarkjs order:**
  1. `publicSignals[0]` — `requestTag` (circuit output)
  2. `publicSignals[1]` — `commitment` (circuit public input)
  3. `publicSignals[2]` — `cutoff` (circuit public input, 32-bit `YYYYMMDD` integer)
  4. `publicSignals[3]` — `challengeHash` (circuit public input, 248-bit integer)

Security and binding properties:

1. **Why the prover cannot choose an arbitrary `birthDate`:** Inside the circuit, `Poseidon(birthDate, salt) === commitment` constrains the private `birthDate` and `salt` to open the public `commitment`. Outside the circuit, the server verifies the issuer's Ed25519 signature over `[credentialId, commitment, issuedAt, expiresAt, issuerName]` using the trusted issuer public key, and checks `POST /internal/credential-status` with both `credentialId` and `commitment`. Because the commitment is issuer-attested and Poseidon is collision-resistant, a prover cannot substitute a different birth date without breaking the commitment opening or failing issuer signature/status verification.
2. **Why the prover cannot choose `cutoff` or `challengeHash`:** Although `cutoff` and `challengeHash` are inputs to the prover, the server generates both when issuing the one-time challenge (`POST /api/challenges`), stores them in the `challenges` table bound to the operator's session and `credentialId`, and compares `publicSignals[2]` and `publicSignals[3]` against the stored challenge row before verifying the Groth16 proof. Any mismatch returns `SIGNALS_MISMATCH` and consumes the challenge.
3. **How `requestTag` binds the proof to the one-time challenge:** The circuit constrains `requestTag <== Poseidon(challengeHash, commitment)` and exposes it as `publicSignals[0]`. This binds the specific credential commitment to the one-time `challengeHash` inside the zero-knowledge proof itself, and the server recomputes `Poseidon(challenge.challenge_hash, credential.commitment)` to verify `publicSignals[0]` matches.
4. **Mandatory server-side signal comparison:** Groth16 verification (`groth16.verify`) only proves that *some* witness satisfies the circuit for the submitted `publicSignals`; it does not know which challenge or credential the server expects. Therefore, `publicSignalsMatchChallenge` in `src/app/verification-request.mjs` must compare all four `publicSignals` against the stored challenge and submitted credential before signature/proof acceptance.
5. **Private-field exclusion:** `birthDate` and `salt` must never be submitted to the app verifier (`POST /api/verifications` rejects any `birthDate` or `salt` key at any depth with `PRIVATE_FIELD_SUBMITTED`) and must never appear in logs, verification results, report exports, or audit event context.

## Local service credentials

Run `npm run local:setup` once after `npm ci`. It generates an Ed25519 issuer key pair and a random 32-byte app-to-issuer service token. The issuer private key is in ignored `.local/issuer/signing-private.pem`; the trusted public key is copied to ignored `.local/app/trusted-issuer-public.pem`. The token is in ignored issuer and app config files. Re-running setup preserves existing values and rejects key/token mismatches. These paths are for the local demo; the private key and token are never committed.

Setup also generates a separate audit identifier key for each service. Initial app-admin and issuer-admin accounts are created by `npm run local:accounts`; the driver, password parameters, normalized-username behavior, and login throttling are recorded in [the account contract](account-contract.md).
