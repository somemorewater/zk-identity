import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

export default async function keyRoutes(app, { config }) {
  app.get('/v1/.well-known/verification-keys', async (_req, reply) => {
    let vk;
    try {
      vk = await readFile(config.vkPath);
    } catch {
      return reply.code(503).send({ error: 'verification_key_unavailable' });
    }
    return {
      circuit: 'age_gte_v1',
      proof_system: 'groth16',
      curve: 'bn254',
      vk_sha256: createHash('sha256').update(vk).digest('hex'),
      vk_base64: vk.toString('base64'),
      public_inputs: ['merkle_root', 'cutoff_days', 'verifier_id', 'challenge', 'nullifier'],
      encoding: 'vk: ark-serialize compressed. Field elements: 32-byte little-endian lowercase hex.',
    };
  });
}
