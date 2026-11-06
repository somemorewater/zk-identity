import test from 'node:test';
import assert from 'node:assert/strict';
import { cutoffDays, daysSince1900, intToFieldHex, isFieldHex, randomChallengeHex, uuidToFieldHex } from '../src/fieldcodec.js';

test('intToFieldHex is 32-byte little-endian', () => {
  assert.equal(intToFieldHex(1), '01' + '00'.repeat(31));
  assert.equal(intToFieldHex(0x0102), '0201' + '00'.repeat(30));
  assert.equal(intToFieldHex(0), '00'.repeat(32));
  assert.throws(() => intToFieldHex(-1));
  assert.throws(() => intToFieldHex(2n ** 256n));
});

test('uuidToFieldHex is canonical and 64 chars', () => {
  const h = uuidToFieldHex('123e4567-e89b-12d3-a456-426614174000');
  assert.equal(h.length, 64);
  assert.ok(isFieldHex(h));
  assert.ok(h.endsWith('0'.repeat(32)));
  assert.throws(() => uuidToFieldHex('nope'));
});

test('challenges are canonical field hex and unique', () => {
  const a = randomChallengeHex();
  const b = randomChallengeHex();
  assert.ok(isFieldHex(a));
  assert.ok(a.endsWith('00'));
  assert.notEqual(a, b);
});

test('days since 1900 anchors', () => {
  assert.equal(daysSince1900(new Date('1900-01-01T00:00:00Z')), 0);
  assert.equal(daysSince1900(new Date('1970-01-01T00:00:00Z')), 25567);
  assert.equal(daysSince1900(new Date('2000-01-01T00:00:00Z')), 36524);
});

test('cutoff: born exactly 18 years ago qualifies, a day later does not', () => {
  const now = new Date('2026-11-03T12:00:00Z');
  const cutoff = cutoffDays(now);
  assert.equal(cutoff, daysSince1900(new Date('2008-11-03T00:00:00Z')));
  assert.equal(cutoff, 39753);
  const bornExactly18 = daysSince1900(new Date('2008-11-03T00:00:00Z'));
  const bornTomorrow = daysSince1900(new Date('2008-11-04T00:00:00Z'));
  assert.ok(bornExactly18 <= cutoff);
  assert.ok(bornTomorrow > cutoff);
});

test('isFieldHex rejects uppercase and wrong length', () => {
  assert.ok(!isFieldHex('AB'.repeat(32)));
  assert.ok(!isFieldHex('ab'.repeat(31)));
  assert.ok(isFieldHex('ab'.repeat(32)));
});
