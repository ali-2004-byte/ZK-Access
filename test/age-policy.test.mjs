import test from 'node:test';
import assert from 'node:assert/strict';
import { age18CutoffForUtcDate, currentUtcDate } from '../src/age-policy.mjs';

test('age-18 cutoff on an ordinary challenge-issue day', () => {
  assert.equal(age18CutoffForUtcDate('2026-11-09'), '2008-11-09');
});

test('Feb 29 birth reaches 18 on Mar 1 in a non-leap year', () => {
  assert.equal(age18CutoffForUtcDate('2026-02-28'), '2008-02-28');
  assert.equal(age18CutoffForUtcDate('2026-03-01'), '2008-03-01');
  assert.ok('2008-02-29' > age18CutoffForUtcDate('2026-02-28'));
  assert.ok('2008-02-29' <= age18CutoffForUtcDate('2026-03-01'));
});

test('Feb 29 challenge-issue day uses Feb 28 in the cutoff year', () => {
  assert.equal(age18CutoffForUtcDate('2024-02-29'), '2006-02-28');
});

test('current server date is derived in UTC', () => {
  assert.equal(currentUtcDate(new Date('2026-11-08T23:59:59-01:00')), '2026-11-09');
});

test('invalid calendar dates and unsupported years fail', () => {
  for (const value of ['2026-02-29', '2026-13-01', '2026-00-01', '2026-01-00', '2026-1-1']) {
    assert.throws(() => age18CutoffForUtcDate(value));
  }
  assert.throws(() => age18CutoffForUtcDate('0018-01-01'));
});
