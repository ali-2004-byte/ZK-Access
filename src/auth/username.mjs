const USERNAME = /^[a-z0-9._-]{3,32}$/;

/** All account lookup and uniqueness uses this form, never the submitted spelling. */
export function normalizeUsername(value) {
  if (typeof value !== 'string' || !value.isWellFormed()) throw new TypeError('Invalid username');
  const normalized = value.trim().normalize('NFKC').toLowerCase();
  if (!USERNAME.test(normalized)) throw new TypeError('Invalid username');
  return normalized;
}
