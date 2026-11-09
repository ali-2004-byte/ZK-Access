import { parseStrictJson } from '../strict-json.mjs';

const ALLOWED = new Set(['active', 'revoked', 'unknown']);

async function readSmallResponse(response, limit) {
  if (!response.body) throw new Error('Issuer response has no body');
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel();
      throw new Error('Issuer response is oversized');
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

/** Return active, revoked, unknown, or unavailable. Exactly one HTTP attempt. */
export async function checkIssuerStatus(credential, {
  serviceToken,
  issuerOrigin = 'http://127.0.0.1:3001',
  fetchImpl = fetch,
  timeoutMs = 2000,
} = {}) {
  if (typeof serviceToken !== 'string' || serviceToken.length === 0) {
    throw new TypeError('Issuer service token is required');
  }
  const origin = new URL(issuerOrigin);
  if (origin.protocol !== 'http:' || origin.hostname !== '127.0.0.1' ||
      origin.pathname !== '/' || origin.search || origin.hash) {
    throw new TypeError('Issuer origin must be loopback HTTP');
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw new RangeError('Invalid issuer timeout');

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(new URL('/internal/credential-status', origin), {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-zk-access-service-token': serviceToken,
      },
      body: JSON.stringify({ credentialId: credential.credentialId, commitment: credential.commitment }),
      signal: controller.signal,
    });
    if (response.status !== 200 ||
        response.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
      return 'unavailable';
    }
    const parsed = parseStrictJson(await readSmallResponse(response, 256), 256);
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed) ||
        Object.keys(parsed).length !== 1 || !Object.hasOwn(parsed, 'status') || !ALLOWED.has(parsed.status)) {
      return 'unavailable';
    }
    return parsed.status;
  } catch {
    return 'unavailable';
  } finally {
    clearTimeout(timer);
  }
}
