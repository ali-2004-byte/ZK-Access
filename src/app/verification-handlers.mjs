// Verification route: early rejections leave the challenge alone; decisions are recorded atomically with their audit event.
import { randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import express from 'express';
import { createAuditEvent } from '../contracts/audit-event.mjs';
import { sendApiError } from '../contracts/error-codes.mjs';
import { createVerificationResult, projectResult, REASON_CODES } from '../contracts/verification-result.mjs';
import { decodeCredentialSignature } from '../credential-json.mjs';
import { verifyCredentialFields } from '../credential-signing.mjs';
import { parseVerificationRequest, publicSignalsMatchChallenge } from './verification-request.mjs';

const ISSUER_NAME = 'ZK Access Demo Issuer';
const NOT_CHECKED_EXPIRY = new Set(['CHALLENGE_REPLAYED', 'CHALLENGE_EXPIRED', 'SIGNALS_MISMATCH', 'SIGNATURE_INVALID']);

// True when the Ed25519 signature covers exactly the five signed public fields.
function signatureValid(credential, trustedIssuerKey) {
  try {
    const fields = [credential.credentialId, credential.commitment, credential.issuedAt, credential.expiresAt,
      credential.issuerName];
    return verifyCredentialFields(fields, Buffer.from(decodeCredentialSignature(credential.signature)), trustedIssuerKey);
  } catch {
    return false;
  }
}

// Map an early parse failure to its safe API error code.
function parseErrorCode(error) {
  if (error?.message === 'PRIVATE_FIELD_SUBMITTED') return 'PRIVATE_FIELD_SUBMITTED';
  if (error instanceof RangeError && /size limit/.test(error.message)) return 'PAYLOAD_TOO_LARGE';
  return 'MALFORMED_INPUT';
}

// Build the submit handler; `audit` must be synchronous so it joins the decision transaction.
export function createVerificationHandlers({
  db, records, sessions, audit, trustedIssuerKey, checkStatus, verifyProof, engineVersion, now = Date.now,
}) {
  if (trustedIssuerKey?.type !== 'public' || trustedIssuerKey.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('Verifier requires the trusted Ed25519 issuer public key');
  }

  // Audit a rejection that happens before any decision; the challenge is not touched.
  function reject(request, response, code, context = {}) {
    audit(createAuditEvent({
      service: 'app', type: 'verification.rejected', actor: { kind: 'account', ...request.auth }, outcome: 'denied',
      code, context, occurredAt: now(),
    }));
    sendApiError(response, code);
  }

  // Run the checks in contract order on a claimed challenge and return the first failing reason.
  async function evaluate(submission, challenge, measured) {
    if (!publicSignalsMatchChallenge(submission, {
      credentialId: challenge.credential_id, cutoff: challenge.cutoff, challengeHash: challenge.challenge_hash,
    })) return 'SIGNALS_MISMATCH';
    if (!signatureValid(submission.credential, trustedIssuerKey)) return 'SIGNATURE_INVALID';
    if (Number(submission.credential.expiresAt) * 1000 <= now()) return 'CREDENTIAL_EXPIRED';
    const status = await checkStatus(submission.credential);
    if (status === 'revoked') return 'CREDENTIAL_REVOKED';
    if (status === 'unknown') return 'CREDENTIAL_UNKNOWN';
    if (status !== 'active') return 'ISSUER_UNAVAILABLE';
    const started = performance.now();
    const valid = await verifyProof(submission.publicSignals, submission.proof);
    measured.verificationMs = Math.round(performance.now() - started);
    return valid ? 'PROOF_VALID' : 'PROOF_INVALID';
  }

  // Store the result, settle the challenge, and write the audit event in one transaction.
  function decide(request, submission, challenge, reasonCode, measured, claimed) {
    const reason = REASON_CODES[reasonCode];
    const result = createVerificationResult({
      resultId: randomBytes(16).toString('base64url'),
      decision: reason.decision,
      reasonCode,
      ruleName: challenge.rule_name,
      ruleVersion: challenge.rule_version,
      nonceStatus: reasonCode === 'CHALLENGE_REPLAYED' ? 'replayed' : reasonCode === 'CHALLENGE_EXPIRED' ? 'expired' : 'fresh',
      verifiedAt: now(),
      credentialId: challenge.credential_id,
      issuerName: ISSUER_NAME,
      credentialExpiryStatus: NOT_CHECKED_EXPIRY.has(reasonCode) ? 'not_checked' :
        reasonCode === 'CREDENTIAL_EXPIRED' ? 'expired' : 'valid',
      measurements: {
        proofSizeBytes: Buffer.byteLength(JSON.stringify(submission.proof)),
        proofGenerationMs: submission.clientMeasurements?.proofGenerationMs ?? null,
        verificationMs: measured.verificationMs,
        decisionLatencyMs: Math.round(performance.now() - measured.started),
      },
      actorAccountId: request.auth.accountId,
      engineVersion,
    });
    db.exec('BEGIN IMMEDIATE');
    try {
      if (claimed) records.transition(challenge.challenge_id, 'verifying', reason.consumesChallenge ? 'used' : 'issued');
      records.insertResult(challenge.challenge_id, result);
      audit(createAuditEvent({
        service: 'app', type: 'verification.decided', actor: { kind: 'account', ...request.auth },
        outcome: reason.decision === 'allow' ? 'success' : reasonCode === 'ISSUER_UNAVAILABLE' ? 'failure' : 'denied',
        code: reasonCode,
        context: { resultId: result.resultId, challengeId: challenge.challenge_id, credentialId: challenge.credential_id },
        occurredAt: result.verifiedAt,
      }));
      db.exec('COMMIT');
    } catch (error) {
      db.exec('ROLLBACK');
      throw error;
    }
    return { result, httpStatus: reason.httpStatus };
  }

  // Parse, bind to the session's challenge, claim it, evaluate, and record the decision.
  async function submitHandler(request, response) {
    const measured = { started: performance.now(), verificationMs: null };
    let submission;
    try {
      submission = parseVerificationRequest(typeof request.body === 'string' ? request.body : '');
    } catch (error) {
      reject(request, response, parseErrorCode(error));
      return;
    }
    const session = await sessions.resolve(request);
    const challenge = records.findChallenge(submission.challengeId);
    if (!challenge || challenge.session_id_hash !== session.idHash ||
        challenge.credential_id !== submission.credential.credentialId) {
      reject(request, response, 'CHALLENGE_NOT_FOUND');
      return;
    }

    let reasonCode = null;
    let claimed = false;
    if (challenge.state === 'expired' || (challenge.state === 'issued' && challenge.expires_at_ms <= now())) {
      records.transition(challenge.challenge_id, 'issued', 'expired');
      reasonCode = 'CHALLENGE_EXPIRED';
    } else {
      claimed = records.transition(challenge.challenge_id, 'issued', 'verifying');
      if (!claimed) reasonCode = 'CHALLENGE_REPLAYED';
    }
    try {
      reasonCode ??= await evaluate(submission, challenge, measured);
    } catch (error) {
      if (claimed) records.transition(challenge.challenge_id, 'verifying', 'issued');
      throw error;
    }
    const { result, httpStatus } = decide(request, submission, challenge, reasonCode, measured, claimed);
    response.status(httpStatus).json(projectResult(result, request.auth.role));
  }

  const rawJson = [
    (request, response, next) => {
      if (!request.is('application/json')) {
        sendApiError(response, 'UNSUPPORTED_MEDIA_TYPE');
        return;
      }
      next();
    },
    express.text({ type: 'application/json', limit: '64kb' }),
  ];
  return { submitVerification: [...rawJson, submitHandler] };
}
