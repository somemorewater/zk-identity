import pg from 'pg';

export function createPool(connectionString) {
  return new pg.Pool({ connectionString, max: 10 });
}

/** Run `fn(client)` inside a transaction. */
export async function withTx(pool, fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}
