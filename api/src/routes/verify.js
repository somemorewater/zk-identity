import { verifierGuard } from '../auth.js';
import { intToFieldHex, uuidToFieldHex } from '../fieldcodec.js';

export default async function verifyRoutes(app, { db, verifier }) {
  const audit = (verifierId, claimType, result, reason = null) =>
    db
      .query('INSERT INTO verification_audit (verifier_id, claim_type, result, reason) VALUES ($1,$2,$3,$4)', [
        verifierId,
        claimType,
        result,
        reason,
      ])
      .catch((err) => app.log.error({ err }, 'audit insert failed'));

  app.post(
    '/v1/verify',
    {
      preHandler: verifierGuard(db),
      schema: {
        body: {
          type: 'object',
          required: ['challenge_id', 'proof', 'nullifier'],
          additionalProperties: false,
          properties: {
            challenge_id: { type: 'string', format: 'uuid' },
            proof: { type: 'string', pattern: '^[0-9a-f]{256}$' },
            nullifier: { type: 'string', pattern: '^[0-9a-f]{64}$' },
          },
        },
      },
    },
    async (req, reply) => {
      const verifierId = req.verifierId;
      const idemKey = req.headers['idempotency-key'];
      if (idemKey !== undefined && (typeof idemKey !== 'string' || idemKey.length > 128)) {
        return reply.code(400).send({ error: 'bad_idempotency_key' });
      }

      if (idemKey) {
        const { rows } = await db.query(
          'SELECT status_code, response FROM idempotency_keys WHERE verifier_id = $1 AND key = $2',
          [verifierId, idemKey],
        );
        if (rows[0]) return reply.header('idempotency-replayed', 'true').code(rows[0].status_code).send(rows[0].response);
      }

      const finish = async (status, body, claimType, reason) => {
        await audit(verifierId, claimType, body.valid === true, reason);
        if (idemKey && status < 500) {
          await db
            .query(
              `INSERT INTO idempotency_keys (verifier_id, key, status_code, response)
               VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
              [verifierId, idemKey, status, body],
            )
            .catch((err) => app.log.error({ err }, 'idempotency insert failed'));
        }
        return reply.code(status).send(body);
      };

      // 1. Atomically consume the challenge: single use, unexpired, owned by this verifier.
      //    Consumed even if the proof later fails, so failures cannot be ground against one challenge.
      const { rows: ch } = await db.query(
        `UPDATE challenges SET used_at = now()
          WHERE id = $1 AND verifier_id = $2 AND used_at IS NULL AND expires_at > now()
          RETURNING nonce, cutoff_days, issuer_id, claim_type`,
        [req.body.challenge_id, verifierId],
      );
      if (!ch[0]) return finish(409, { valid: false, error: 'challenge_invalid_expired_or_used' }, null, 'challenge');

      // 2. Current issuer root (revocation = the root changed).
      const { rows: roots } = await db.query(
        'SELECT root FROM issuer_roots WHERE issuer_id = $1 AND superseded_at IS NULL',
        [ch[0].issuer_id],
      );
      if (!roots[0]) return finish(409, { valid: false, error: 'no_active_root' }, ch[0].claim_type, 'no_root');

      // 3. The server, not the client, supplies every public input except the nullifier.
      const publicInputs = [
        roots[0].root.toString('hex'),
        intToFieldHex(ch[0].cutoff_days),
        uuidToFieldHex(verifierId),
        ch[0].nonce.toString('hex'),
        req.body.nullifier,
      ];

      let result;
      try {
        result = await verifier.verify(req.body.proof, publicInputs);
      } catch (err) {
        req.log.error({ err }, 'verifier unavailable');
        return reply.code(503).send({ error: 'verifier_unavailable' });
      }
      if (!result.valid) {
        return finish(422, { valid: false, error: 'invalid_proof' }, ch[0].claim_type, 'invalid_proof');
      }

      // 4. Record the scoped nullifier. A conflict means this credential was already
      //    presented to THIS verifier: learned without learning who.
      const ins = await db.query(
        `INSERT INTO nullifiers (verifier_id, nullifier) VALUES ($1, $2)
         ON CONFLICT DO NOTHING RETURNING 1`,
        [verifierId, Buffer.from(req.body.nullifier, 'hex')],
      );
      return finish(
        200,
        { valid: true, claim: ch[0].claim_type, already_seen: ins.rowCount === 0, verified_at: new Date().toISOString() },
        ch[0].claim_type,
        null,
      );
    },
  );
}
