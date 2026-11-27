// Operator challenge issuance: session- and credential-bound, rate limited, with the cutoff fixed at issue time.
import { randomBytes } from 'node:crypto';
import { ageCutoffForUtcDate, currentUtcDate } from '../age-policy.mjs';
import { createAuditEvent } from '../contracts/audit-event.mjs';
import { sendApiError } from '../contracts/error-codes.mjs';
import { hasExactKeys, strictJsonBody } from '../http/json-body.mjs';
import { createChallengeHash } from '../zk/challenge-hash.mjs';
import { sessionCanIssueChallenge } from './session-policy.mjs';

export const CHALLENGES_PER_MINUTE = 10;
const CREDENTIAL_ID = /^[A-Za-z0-9_-]{1,64}$/;

// Build the challenge handler over the app records and session manager.
export function createChallengeHandlers({ records, sessions, audit, now = Date.now }) {
  // Store a new challenge row; the raw nonce exists only inside createChallengeHash.
  async function issueHandler(request, response) {
    const body = request.jsonBody;
    if (!hasExactKeys(body, ['credentialId']) || typeof body.credentialId !== 'string' ||
        !CREDENTIAL_ID.test(body.credentialId)) {
      sendApiError(response, 'MALFORMED_INPUT');
      return;
    }
    const time = now();
    const session = await sessions.resolve(request);
    const rule = records.activeRule();
    if (!sessionCanIssueChallenge(session, time, rule.challengeLifetimeMs)) {
      sendApiError(response, 'AUTH_REQUIRED');
      return;
    }
    if (records.countRecentChallenges(session.accountId, time - 60_000) >= CHALLENGES_PER_MINUTE) {
      sendApiError(response, 'RATE_LIMITED');
      return;
    }

    const challenge = {
      challengeId: randomBytes(16).toString('base64url'),
      sessionIdHash: session.idHash,
      accountId: session.accountId,
      credentialId: body.credentialId,
      challengeHash: createChallengeHash(),
      cutoff: Number(ageCutoffForUtcDate(currentUtcDate(new Date(time)), rule.minimumAge).replaceAll('-', '')),
      ruleName: rule.name,
      ruleVersion: rule.version,
      issuedAt: time,
      expiresAt: time + rule.challengeLifetimeMs,
    };
    records.insertChallenge(challenge);
    await audit(createAuditEvent({
      service: 'app', type: 'challenge.issued', actor: { kind: 'account', ...request.auth }, outcome: 'success',
      context: { challengeId: challenge.challengeId, credentialId: challenge.credentialId }, occurredAt: time,
    }));
    response.status(201).json({
      challengeId: challenge.challengeId,
      challengeHash: challenge.challengeHash,
      cutoff: String(challenge.cutoff),
      expiresAt: challenge.expiresAt,
    });
  }

  return { issueChallenge: [...strictJsonBody(256), issueHandler] };
}
