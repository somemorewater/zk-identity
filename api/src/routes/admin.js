import { randomBytes } from 'node:crypto';
import { adminGuard, sha256 } from '../auth.js';
import { withTx } from '../db.js';

const nameBody = {
  type: 'object',
  required: ['name'],
  additionalProperties: false,
  properties: { name: { type: 'string', minLength: 1, maxLength: 200 } },
};

export default async function adminRoutes(app, { db, config }) {
  const guard = adminGuard(config);

  app.post('/v1/admin/issuers', { preHandler: guard, schema: { body: nameBody } }, async (req, reply) => {
    const { rows } = await db.query('INSERT INTO issuers (name) VALUES ($1) RETURNING id', [req.body.name]);
    return reply.code(201).send({ id: rows[0].id });
  });

  // Publishing a new root supersedes the old one. Omitting a leaf = revocation.
  app.post(
    '/v1/admin/issuers/:id/roots',
    {
      preHandler: guard,
      schema: {
        params: { type: 'object', properties: { id: { type: 'string', format: 'uuid' } } },
        body: {
          type: 'object',
          required: ['root'],
          additionalProperties: false,
          properties: { root: { type: 'string', pattern: '^[0-9a-f]{64}$' } },
        },
      },
    },
    async (req, reply) => {
      const root = Buffer.from(req.body.root, 'hex');
      const result = await withTx(db, async (c) => {
        const issuer = await c.query('SELECT status FROM issuers WHERE id = $1 FOR UPDATE', [req.params.id]);
        if (!issuer.rows[0]) return { code: 404, body: { error: 'issuer_not_found' } };
        if (issuer.rows[0].status !== 'active') return { code: 409, body: { error: 'issuer_suspended' } };
        await c.query('UPDATE issuer_roots SET superseded_at = now() WHERE issuer_id = $1 AND superseded_at IS NULL', [
          req.params.id,
        ]);
        await c.query('INSERT INTO issuer_roots (issuer_id, root) VALUES ($1, $2)', [req.params.id, root]);
        return { code: 201, body: { issuer_id: req.params.id, root: req.body.root } };
      });
      return reply.code(result.code).send(result.body);
    },
  );

  app.post('/v1/admin/verifiers', { preHandler: guard, schema: { body: nameBody } }, async (req, reply) => {
    const apiKey = 'zkv_' + randomBytes(32).toString('hex');
    const { rows } = await db.query('INSERT INTO verifiers (name, api_key_hash) VALUES ($1, $2) RETURNING id', [
      req.body.name,
      sha256(apiKey),
    ]);
    // The key is shown exactly once; only its hash is stored.
    return reply.code(201).send({ id: rows[0].id, api_key: apiKey });
  });
}
