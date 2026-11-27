import { daysInMonth, formatIsoDate, parseIsoDate } from './calendar-date.mjs';

/**
 * Returns the public birth-date cutoff for the server's UTC challenge-issue date.
 * A private birth date belongs in the browser witness, never in this function.
 */
export function age18CutoffForUtcDate(challengeDate) {
  return ageCutoffForUtcDate(challengeDate, 18);
}

// Same cutoff rule for an admin-configured minimum age; the circuit only compares against the cutoff.
export function ageCutoffForUtcDate(challengeDate, minimumAge) {
  if (!Number.isSafeInteger(minimumAge) || minimumAge < 1) throw new RangeError('Minimum age must be a positive integer');
  const { year, month, day } = parseIsoDate(challengeDate);
  const cutoffYear = year - minimumAge;
  if (cutoffYear < 1) throw new RangeError('Challenge date precedes supported cutoff');

  // Feb 29 in a leap challenge year has no Feb 29 eighteen years earlier.
  // The project owner specified Feb 28 as the cutoff for this case.
  const cutoffDay = Math.min(day, daysInMonth(cutoffYear, month));
  return formatIsoDate({ year: cutoffYear, month, day: cutoffDay });
}

/** Returns the server's current UTC calendar date, not a browser-supplied date. */
export function currentUtcDate(now = new Date()) {
  if (!(now instanceof Date) || Number.isNaN(now.valueOf())) {
    throw new TypeError('Expected a valid Date');
  }
  return now.toISOString().slice(0, 10);
}
