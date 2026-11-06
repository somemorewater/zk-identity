import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { VerifierClient } from '../src/verifier-client.js';

const fake = fileURLToPath(new URL('./fixtures/fake-verifier.js', import.meta.url));
const quiet = { error() {} };
const inputs = ['a', 'b', 'c', 'd', 'e'];

test('routes concurrent requests to the right callers', async () => {
  const c = new VerifierClient({ bin: process.execPath, vkPath: fake, log: quiet });
  // Reuse node as the "binary": node <fake-verifier.js>
  c.start();
  try {
    const [ok, bad] = await Promise.all([c.verify('good', inputs), c.verify('bad', inputs)]);
    assert.equal(ok.valid, true);
    assert.equal(bad.valid, false);
    assert.equal(bad.error, 'nope');
  } finally {
    c.stop();
  }
});

test('times out when the verifier hangs', async () => {
  const c = new VerifierClient({ bin: process.execPath, vkPath: fake, timeoutMs: 150, log: quiet });
  c.start();
  try {
    await assert.rejects(c.verify('hang', inputs), /timeout/);
  } finally {
    c.stop();
  }
});

test('rejects in-flight requests when the verifier crashes, then recovers', async () => {
  const c = new VerifierClient({ bin: process.execPath, vkPath: fake, log: quiet });
  c.start();
  try {
    await assert.rejects(c.verify('crash', inputs), /exited/);
    await new Promise((r) => setTimeout(r, 1500)); // restart delay is 1s
    assert.equal((await c.verify('good', inputs)).valid, true);
  } finally {
    c.stop();
  }
});
