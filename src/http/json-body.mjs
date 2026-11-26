// Strict JSON body middleware: JSON media type, size limit, and duplicate-key rejection.
import express from 'express';
import { sendApiError } from '../contracts/error-codes.mjs';
import { parseStrictJson } from '../strict-json.mjs';

// Middleware chain that leaves the parsed body on request.jsonBody or sends a safe error.
export function strictJsonBody(maxBytes) {
  return [
    (request, response, next) => {
      if (!request.is('application/json')) {
        sendApiError(response, 'UNSUPPORTED_MEDIA_TYPE');
        return;
      }
      next();
    },
    express.text({ type: 'application/json', limit: maxBytes }),
    (request, response, next) => {
      try {
        request.jsonBody = parseStrictJson(typeof request.body === 'string' ? request.body : '', maxBytes);
      } catch (error) {
        sendApiError(response, error instanceof RangeError && /size limit/.test(error.message) ?
          'PAYLOAD_TOO_LARGE' : 'MALFORMED_INPUT');
        return;
      }
      next();
    },
  ];
}

// True when the value is a plain JSON object with exactly the required keys plus allowed optional ones.
export function hasExactKeys(value, required, optional = []) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return required.every((key) => Object.hasOwn(value, key)) &&
    keys.every((key) => required.includes(key) || optional.includes(key));
}
