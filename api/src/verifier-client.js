// Talks to the Rust `zk-verifier` sidecar over line-delimited JSON on stdio.
// Swap this for a gRPC client later without touching the routes.
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { createInterface } from 'node:readline';

export class VerifierClient {
  #pending = new Map();
  #child = null;
  #stopped = false;

  constructor({ bin, vkPath, timeoutMs = 5000, log = console }) {
    this.bin = bin;
    this.vkPath = vkPath;
    this.timeoutMs = timeoutMs;
    this.log = log;
  }

  start() {
    const child = spawn(this.bin, [this.vkPath], { stdio: ['pipe', 'pipe', 'inherit'] });
    this.#child = child;
    createInterface({ input: child.stdout }).on('line', (line) => this.#onLine(line));
    child.stdin.on('error', () => {}); // EPIPE is handled via 'exit'
    child.on('error', (err) => {
      this.log.error?.(`verifier spawn error: ${err.message}`);
      this.#failAll(err);
      this.#scheduleRestart();
    });
    child.on('exit', (code) => {
      this.log.error?.(`verifier exited (${code})`);
      this.#failAll(new Error('verifier exited'));
      this.#scheduleRestart();
    });
  }

  #scheduleRestart() {
    if (this.#stopped) return;
    this.#child = null;
    setTimeout(() => !this.#stopped && !this.#child && this.start(), 1000).unref();
  }

  #onLine(line) {
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      return;
    }
    if (msg.ready) return;
    const entry = this.#pending.get(msg.id);
    if (!entry) return;
    this.#pending.delete(msg.id);
    clearTimeout(entry.timer);
    entry.resolve({ valid: msg.valid === true, error: msg.error ?? null });
  }

  #failAll(err) {
    for (const [id, entry] of this.#pending) {
      clearTimeout(entry.timer);
      entry.reject(err);
      this.#pending.delete(id);
    }
  }

  /** @returns {Promise<{valid: boolean, error: string|null}>} */
  verify(proofHex, publicInputs) {
    return new Promise((resolve, reject) => {
      if (!this.#child || !this.#child.stdin.writable) return reject(new Error('verifier unavailable'));
      const id = randomUUID();
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error('verifier timeout'));
      }, this.timeoutMs);
      this.#pending.set(id, { resolve, reject, timer });
      this.#child.stdin.write(JSON.stringify({ id, proof: proofHex, public_inputs: publicInputs }) + '\n');
    });
  }

  stop() {
    this.#stopped = true;
    this.#failAll(new Error('verifier stopped'));
    this.#child?.kill();
  }
}
