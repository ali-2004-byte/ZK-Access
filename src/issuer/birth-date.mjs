import { parseIsoDate } from '../calendar-date.mjs';

/** Validate a calendar birth date at the issuer boundary and encode YYYYMMDD. */
export function encodeBirthDate(birthDate) {
  const { year, month, day } = parseIsoDate(birthDate);
  return year * 10_000 + month * 100 + day;
}
