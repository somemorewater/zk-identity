import Fastify from 'fastify';
import adminRoutes from './routes/admin.js';
import challengeRoutes from './routes/challenges.js';
import keyRoutes from './routes/keys.js';
import verifyRoutes from './routes/verify.js';

export function buildApp({ db, verifier, config, logger = true }) {
  const app = Fastify({ logger, bodyLimit: 64 * 1024 });

  app.get('/healthz', async (_req, reply) => {
    try {
      await db.query('SELECT 1');
      return { ok: true };
    } catch {
      return reply.code(503).send({ ok: false });
    }
  });

  const deps = { db, verifier, config };
  app.register(adminRoutes, deps);
  app.register(challengeRoutes, deps);
  app.register(verifyRoutes, deps);
  app.register(keyRoutes, deps);
  return app;
}
