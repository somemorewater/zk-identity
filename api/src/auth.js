import { createHash, timingSafeEqual } from 'node:crypto';

export const sha256 = (s) => createHash('sha256').update(s).digest();

export function adminGuard(config) {
  const expected = config.adminKey ? sha256(config.adminKey) : null;
  return async (req, reply) => {
    const k = req.headers['x-admin-key'];
    if (!expected || typeof k !== 'string' || !timingSafeEqual(sha256(k), expected)) {
      return reply.code(401).send({ error: 'unauthorized' });
    }
  };
}

/** Looks up the verifier by sha256(api key) and sets req.verifierId. */
export function verifierGuard(db) {
  return async (req, reply) => {
    const k = req.headers['x-api-key'];
    if (typeof k !== 'string' || k.length < 16 || k.length > 200) {
      return reply.code(401).send({ error: 'unauthorized' });
    }
    const { rows } = await db.query('SELECT id FROM verifiers WHERE api_key_hash = $1', [sha256(k)]);
    if (!rows[0]) return reply.code(401).send({ error: 'unauthorized' });
    req.verifierId = rows[0].id;
  };
}
