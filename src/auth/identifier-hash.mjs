// Keyed hashes for usernames and IPs in audit events, so short values cannot be guessed back.
import { createHmac } from 'node:crypto';

// Return a hasher bound to a per-service secret key of at least 32 bytes.
export function createIdentifierHasher(key) {
  if (!Buffer.isBuffer(key) || key.length < 32) throw new TypeError('Identifier key must be at least 32 bytes');
  return (scope, value) => createHmac('sha256', key).update(scope).update('\0').update(String(value)).digest('hex');
}
