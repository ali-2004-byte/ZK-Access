export const SESSION_IDLE_MS = 30 * 60 * 1000;
export const SESSION_ABSOLUTE_MS = 8 * 60 * 60 * 1000;
export const DEFAULT_CHALLENGE_MS = 5 * 60 * 1000;

function requireTimestamp(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${label} must be a nonnegative Unix millisecond timestamp`);
  }
}

/** The session expires at the earlier inactivity or absolute deadline. */
export function sessionExpiresAt({ createdAt, lastActivityAt }) {
  requireTimestamp(createdAt, 'createdAt');
  requireTimestamp(lastActivityAt, 'lastActivityAt');
  if (lastActivityAt < createdAt) throw new RangeError('lastActivityAt precedes createdAt');
  return Math.min(lastActivityAt + SESSION_IDLE_MS, createdAt + SESSION_ABSOLUTE_MS);
}

export function sessionIsActive(session, now) {
  requireTimestamp(now, 'now');
  return now >= session.lastActivityAt && now < sessionExpiresAt(session);
}

/** A bound challenge must have time to finish before its session expires. */
export function sessionCanIssueChallenge(session, now, challengeLifetimeMs = DEFAULT_CHALLENGE_MS) {
  requireTimestamp(now, 'now');
  if (!Number.isSafeInteger(challengeLifetimeMs) || challengeLifetimeMs <= 0) {
    throw new TypeError('challengeLifetimeMs must be a positive integer');
  }
  if (!sessionIsActive(session, now)) return false;
  // Issuing a challenge is activity, so it renews the idle deadline.
  const renewedDeadline = Math.min(now + SESSION_IDLE_MS, session.createdAt + SESSION_ABSOLUTE_MS);
  return renewedDeadline - now > challengeLifetimeMs;
}
