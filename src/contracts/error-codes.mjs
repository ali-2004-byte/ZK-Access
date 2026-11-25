// Stable API error codes and HTTP statuses; responses carry only `{ code }`.
export const API_ERRORS = Object.freeze({
  AUTH_REQUIRED: 401,
  AUTH_DENIED: 403,
  CSRF_INVALID: 403,
  LOGIN_FAILED: 401,
  LOGIN_LOCKED: 429,
  RATE_LIMITED: 429,
  MALFORMED_INPUT: 400,
  PRIVATE_FIELD_SUBMITTED: 400,
  PAYLOAD_TOO_LARGE: 413,
  UNSUPPORTED_MEDIA_TYPE: 415,
  CONFIRMATION_REQUIRED: 409,
  CONFLICT: 409,
  CHALLENGE_NOT_FOUND: 404,
  NOT_FOUND: 404,
  NOT_IMPLEMENTED: 501,
  INTERNAL_ERROR: 500,
});

// True when the value is one of the fixed API error codes.
export function isApiErrorCode(code) {
  return typeof code === 'string' && Object.hasOwn(API_ERRORS, code);
}

// Send the fixed error body; an unknown code is a programming error.
export function sendApiError(response, code) {
  if (!isApiErrorCode(code)) throw new TypeError('Unknown API error code');
  response.status(API_ERRORS[code]).json({ code });
}
