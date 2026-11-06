// Pure helpers shared by routes. Field elements are 32-byte little-endian hex.
import { randomBytes } from 'node:crypto';

// Days from 1900-01-01 to 1970-01-01. The circuit counts days since 1900 so
// birth dates before 1970 are representable as unsigned 32-bit integers.
const DAYS_1900_TO_1970 = 25567;
const MS_PER_DAY = 86_400_000;

export const FIELD_HEX = /^[0-9a-f]{64}$/;
export const isFieldHex = (s) => typeof s === 'string' && FIELD_HEX.test(s);

/** Non-negative integer -> 32-byte little-endian hex. */
export function intToFieldHex(n) {
  let x = BigInt(n);
  if (x < 0n) throw new RangeError('negative value');
  const out = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  if (x !== 0n) throw new RangeError('value does not fit in 32 bytes');
  return out.toString('hex');
}

/** UUID -> field hex. 128-bit value, always far below the field modulus. */
export function uuidToFieldHex(uuid) {
  const h = String(uuid).replace(/-/g, '').toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(h)) throw new TypeError('not a uuid');
  return h + '0'.repeat(32);
}

/** 248 random bits (31 bytes + zero high byte): canonical for BN254 Fr. */
export function randomChallengeHex() {
  return randomBytes(31).toString('hex') + '00';
}

export function daysSince1900(date) {
  return Math.floor(date.getTime() / MS_PER_DAY) + DAYS_1900_TO_1970;
}

/** Latest birth date (as days since 1900) that is at least `years` old today (UTC). */
export function cutoffDays(now = new Date(), years = 18) {
  const d = new Date(Date.UTC(now.getUTCFullYear() - years, now.getUTCMonth(), now.getUTCDate()));
  return daysSince1900(d);
}
