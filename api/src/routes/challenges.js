import { verifierGuard } from '../auth.js';
import { cutoffDays, randomChallengeHex, uuidToFieldHex } from '../fieldcodec.js';

export default async function challengeRoutes(app, { db, config }) {
  app.post(
    '/v1/challenges',
    {
      preHandler: verifierGuard(db),
      schema: {
        body: {
          type: 'object',
          required: ['claim_type', 'issuer_id'],
          additionalProperties: false,
          properties: {
            claim_type: { type: 'string', enum: ['age_gte_18'] },
            issuer_id: { type: 'string', format: 'uuid' },
          },
        },
      },
    },
    async (req, reply) => {
      const { issuer_id: issuerId, claim_type: claimType } = req.body;
      const { rows: roots } = await db.query(
        `SELECT r.root FROM issuer_roots r JOIN issuers i ON i.id = r.issuer_id
          WHERE r.issuer_id = $1 AND r.superseded_at IS NULL AND i.status = 'active'`,
        [issuerId],
      );
      if (!roots[0]) return reply.code(404).send({ error: 'issuer_not_found_or_no_active_root' });

      const nonce = randomChallengeHex();
      const cutoff = cutoffDays(new Date(), config.minAgeYears);
      const expiresAt = new Date(Date.now() + config.challengeTtlSeconds * 1000);
      const { rows } = await db.query(
        `INSERT INTO challenges (verifier_id, issuer_id, claim_type, nonce, cutoff_days, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
        [req.verifierId, issuerId, claimType, Buffer.from(nonce, 'hex'), cutoff, expiresAt],
      );

      return reply.code(201).send({
        challenge_id: rows[0].id,
        challenge: nonce,
        verifier_id: uuidToFieldHex(req.verifierId),
        cutoff_days: cutoff,
        merkle_root: roots[0].root.toString('hex'),
        expires_at: expiresAt.toISOString(),
        circuit: 'age_gte_v1',
      });
    },
  );
}
