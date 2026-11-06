import { readdir, readFile } from 'node:fs/promises';
import { config } from './config.js';
import { createPool, withTx } from './db.js';

const dir = new URL('../../db/migrations/', import.meta.url);
const pool = createPool(config.databaseUrl);

try {
  await pool.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
    name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
  const applied = new Set((await pool.query('SELECT name FROM schema_migrations')).rows.map((r) => r.name));
  const files = (await readdir(dir)).filter((f) => f.endsWith('.sql')).sort();
  for (const f of files) {
    if (applied.has(f)) continue;
    const sql = await readFile(new URL(f, dir), 'utf8');
    await withTx(pool, async (c) => {
      await c.query(sql);
      await c.query('INSERT INTO schema_migrations (name) VALUES ($1)', [f]);
    });
    console.log('applied', f);
  }
  console.log('migrations up to date');
} finally {
  await pool.end();
}
