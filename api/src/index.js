import { buildApp } from './app.js';
import { config } from './config.js';
import { createPool } from './db.js';
import { VerifierClient } from './verifier-client.js';

if (!config.adminKey) console.warn('ADMIN_API_KEY is not set: admin endpoints will reject every request');

const db = createPool(config.databaseUrl);
const verifier = new VerifierClient({ bin: config.verifierBin, vkPath: config.vkPath });
verifier.start();

const app = buildApp({ db, verifier, config });

const shutdown = async () => {
  await app.close();
  verifier.stop();
  await db.end();
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

await app.listen({ port: config.port, host: '0.0.0.0' });
