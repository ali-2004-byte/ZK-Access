// Issuer-admin handlers: issue a signed credential file, revoke, and list issuance records.
import { randomBytes } from 'node:crypto';
import { currentUtcDate } from '../age-policy.mjs';
import { createAuditEvent } from '../contracts/audit-event.mjs';
import { sendApiError } from '../contracts/error-codes.mjs';
import { signCredentialFields } from '../credential-signing.mjs';
import { hasExactKeys, strictJsonBody } from '../http/json-body.mjs';
import { credentialCommitment } from '../zk/poseidon.mjs';
import { BN254_FIELD_MODULUS } from '../zk/field.mjs';
import { encodeBirthDate } from './birth-date.mjs';

export const ISSUER_NAME = 'ZK Access Demo Issuer';
export const CREDENTIAL_LIFETIME_SECONDS = 90 * 24 * 60 * 60;
const SALT = /^[0-9]{1,78}$/;
const CREDENTIAL_ID = /^[A-Za-z0-9_-]{1,64}$/;

// Build the handlers; the private key never leaves this process and the request body is never stored.
export function createIssuanceHandlers({ records, signingKey, audit, now = Date.now }) {
  if (signingKey?.type !== 'private' || signingKey.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('Issuer requires an Ed25519 private signing key');
  }

  // Append one credential.* audit event for the acting issuer admin.
  async function record(request, type, outcome, code, context = {}) {
    await audit(createAuditEvent({
      service: 'issuer', type, actor: { kind: 'account', ...request.auth }, outcome, code, context, occurredAt: now(),
    }));
  }

  // Validate the date and salt, sign the commitment metadata, and return the nine-field private file.
  async function issueHandler(request, response) {
    const body = request.jsonBody;
    const time = now();
    let birthDateNumber;
    try {
      if (!hasExactKeys(body, ['version', 'birthDate', 'salt']) || body.version !== '1' ||
          typeof body.salt !== 'string' || !SALT.test(body.salt) || BigInt(body.salt) >= BN254_FIELD_MODULUS ||
          typeof body.birthDate !== 'string' || body.birthDate > currentUtcDate(new Date(time))) {
        throw new TypeError('Invalid issuance request');
      }
      birthDateNumber = encodeBirthDate(body.birthDate);
    } catch {
      await record(request, 'credential.issue_rejected', 'failure', 'MALFORMED_INPUT');
      sendApiError(response, 'MALFORMED_INPUT');
      return;
    }

    const credentialId = randomBytes(16).toString('base64url');
    const commitment = credentialCommitment(birthDateNumber, body.salt);
    const issuedAt = Math.floor(time / 1000);
    const expiresAt = issuedAt + CREDENTIAL_LIFETIME_SECONDS;
    const fields = [credentialId, commitment, String(issuedAt), String(expiresAt), ISSUER_NAME];
    const signature = signCredentialFields(fields, signingKey).toString('base64url');
    records.insert({ credentialId, commitment, signature, issuedAt, expiresAt, issuedBy: request.auth.accountId });
    await record(request, 'credential.issued', 'success', null, { credentialId });

    response.set('Cache-Control', 'no-store');
    response.status(201).json({
      version: '1',
      credentialId,
      birthDate: body.birthDate,
      salt: body.salt,
      commitment,
      issuedAt: String(issuedAt),
      expiresAt: String(expiresAt),
      issuerName: ISSUER_NAME,
      signature,
    });
  }

  // Mark one credential revoked; repeating the call keeps it revoked.
  async function revokeCredential(request, response) {
    const { credentialId } = request.params;
    if (!CREDENTIAL_ID.test(credentialId) || !records.revoke(credentialId)) {
      sendApiError(response, 'NOT_FOUND');
      return;
    }
    await record(request, 'credential.revoked', 'success', null, { credentialId });
    response.json({ credentialId, status: 'revoked' });
  }

  // List issuance metadata so the admin can pick a credential to revoke.
  function listCredentials(_request, response) {
    response.json({ credentials: records.list() });
  }

  return { issueCredential: [...strictJsonBody(512), issueHandler], revokeCredential, listCredentials };
}
