# Private credential file contract

The separately authenticated issuer-admin browser downloads this JSON file after issuance. The operator imports it in the app browser for proof generation. It contains private witness material and is for synthetic demo data only. The issuer must not retain the birth date, salt, or request body; the app verifier must never receive them.

The UTF-8 file is at most 4,096 bytes. It is one flat JSON object with exactly these nine case-sensitive keys and string values; key order in JSON is irrelevant:

| Key | Required value |
| --- | --- |
| `version` | `"1"` |
| `credentialId` | Nonempty opaque ID |
| `birthDate` | Valid Gregorian date in `YYYY-MM-DD` form |
| `salt` | Decimal integer below the BN254 scalar-field modulus |
| `commitment` | Decimal integer below the modulus, with no leading zeros |
| `issuedAt` | Decimal Unix seconds, UTC |
| `expiresAt` | Decimal Unix seconds, UTC |
| `issuerName` | `"ZK Access Demo Issuer"` |
| `signature` | Unpadded canonical base64url of exactly 64 Ed25519 signature bytes |

`src/credential-json.mjs` rejects duplicate keys, missing/extra keys, wrong types, unknown versions, invalid dates or encodings, and files over the limit. It does not establish authenticity. The browser converts the validated birth date to a `YYYYMMDD` integer only when assembling the private proof witness. The verifier checks the signature and the proof independently. The verifier's HTTP request schema must contain only public credential/proof material and still needs to be finalized.

## Signed bytes

`src/credential-signing.mjs` is the one shared encoder for issuer and verifier. The bytes are the ASCII domain tag `ZKACCESS-CRED-V1`, followed by these five fields in order: credential ID (UTF-8), commitment (ASCII decimal without leading zeros), issue time (ASCII decimal Unix seconds), expiry time (same encoding), and issuer name (UTF-8). Each field has a four-byte unsigned big-endian prefix containing its byte length. The birth date, salt, file version, and signature are not part of the signed payload. The signature covers the commitment that the age proof opens.

The fixed byte and Ed25519 signature vectors in `test/credential-signing.test.mjs` are the interoperability check. Both services must call the same encoder. The verifier must reject a malformed public credential structure before signature verification and reject a signature over any different bytes.
