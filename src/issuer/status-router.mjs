import { timingSafeEqual } from 'node:crypto';
import express from 'express';
import { parseStrictJson } from '../strict-json.mjs';
import { BN254_FIELD_MODULUS } from '../zk/field.mjs';

const ALLOWED = new Set(['active', 'revoked', 'unknown']);
const CANONICAL_DECIMAL = /^(0|[1-9][0-9]*)$/;

function tokenMatches(actual, expected) {
  if (typeof actual !== 'string') return false;
  const actualBytes = Buffer.from(actual, 'utf8');
  const expectedBytes = Buffer.from(expected, 'utf8');
  return actualBytes.length === expectedBytes.length && timingSafeEqual(actualBytes, expectedBytes);
}

/** The injected lookup must match both credential ID and commitment in issuer storage. */
export function createIssuerStatusRouter({ serviceToken, lookupStatus }) {
  if (typeof serviceToken !== 'string' || serviceToken.length === 0 || typeof lookupStatus !== 'function') {
    throw new TypeError('Issuer status router requires service token and lookup function');
  }
  const router = express.Router();
  router.post('/internal/credential-status', (request, response, next) => {
    if (!tokenMatches(request.get('X-ZK-Access-Service-Token'), serviceToken)) {
      response.status(403).json({ code: 'AUTH_DENIED' });
      return;
    }
    next();
  }, express.text({ type: 'application/json', limit: '1kb' }), async (request, response) => {
    let input;
    try {
      input = parseStrictJson(request.body, 1024);
      if (input === null || typeof input !== 'object' || Array.isArray(input) ||
          Object.keys(input).length !== 2 || !Object.hasOwn(input, 'credentialId') ||
          !Object.hasOwn(input, 'commitment') || typeof input.credentialId !== 'string' ||
          input.credentialId.length === 0 || typeof input.commitment !== 'string' ||
          !CANONICAL_DECIMAL.test(input.commitment) || BigInt(input.commitment) >= BN254_FIELD_MODULUS) {
        throw new TypeError('Malformed status request');
      }
    } catch {
      response.status(400).json({ code: 'MALFORMED_INPUT' });
      return;
    }
    try {
      const status = await lookupStatus(input.credentialId, input.commitment);
      if (!ALLOWED.has(status)) throw new Error('Unexpected status');
      response.json({ status });
    } catch {
      response.status(503).json({ code: 'ISSUER_UNAVAILABLE' });
    }
  });
  router.use((error, _request, response, _next) => {
    response.status(error?.status === 413 ? 413 : 400).json({ code: 'MALFORMED_INPUT' });
  });
  return router;
}
