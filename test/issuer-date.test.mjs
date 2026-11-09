import test from 'node:test';
import assert from 'node:assert/strict';
import { encodeBirthDate } from '../src/issuer/birth-date.mjs';

test('issuer encodes valid calendar dates as 32-bit YYYYMMDD integers', () => {
  assert.equal(encodeBirthDate('2008-02-29'), 20080229);
  assert.equal(encodeBirthDate('2008-11-09'), 20081109);
  assert.ok(encodeBirthDate('9999-12-31') < 2 ** 32);
});

test('issuer rejects malformed and impossible birth dates', () => {
  for (const value of ['2007-02-29', '2026-11-31', '2026-13-01', '2026-1-1', 'not-a-date']) {
    assert.throws(() => encodeBirthDate(value));
  }
});
