# Privacy-First ZK Identity Verification Service

A verifier asks "is this person over 18?" and gets a cryptographic **yes/no**: no date of birth, no name,
no document, no cross-service identifier. Holders prove the claim in zero knowledge (Groth16 on BN254);
the service verifies it, prevents replay, and supports revocation.

**Stack:** Rust (arkworks circuits, CLI, verifier sidecar) · Node.js/Fastify API · PostgreSQL

## Features

- **Zero-knowledge age proofs:** holders prove `age >= 18` without revealing a date of birth, name, document, or raw credential.
- **Groth16 on BN254:** compact proofs verified by a long-running Rust sidecar.
- **Credential revocation:** publishers rotate Merkle roots; omitting a leaf revokes it.
- **Replay protection:** every challenge is single-use, server-issued, and bound into the proof.
- **Scoped nullifiers:** verifiers can detect repeat credentials without learning a cross-verifier identifier.
- **Minimal storage:** the database stores hashes, roots, nullifiers, and audit metadata — no PII or raw proofs.
- **Idempotent verification:** optional `Idempotency-Key` support for safe client retries.

## Status: read this first

| Component | State |
|---|---|
| Node API helpers + verifier-client (9 tests, incl. crash/timeout/concurrency against a fake sidecar) | ran and passing |
| All JS syntax-checked, `demo.sh` syntax-checked | ran |
| **Rust workspace (circuit, CLI, verifier)** | **written but NOT compiled or run** by its author |
| **API routes against a real Postgres** | **written but NOT run** |

The Rust code was written against arkworks 0.4 from memory in an environment with no Rust toolchain or network.
Expect a handful of compile errors on first `cargo build` (trait imports and gadget signatures are the likely
spots). Start with `cargo test --release -p zk-circuits`: the circuit tests are the most valuable thing in the repo,
including a field-wraparound attack test. Fix compile errors there first, then work outward.

## How it works

```
 Issuer ── publishes Merkle root of credential leaves ──▶ API (POST /v1/admin/issuers/:id/roots)
   │ leaf = Poseidon(secret, dob_days)
   ▼
 Holder (zk-cli) ◀── challenge, cutoff, verifier_id, merkle_root ── API (POST /v1/challenges, by a Verifier)
   │ Groth16 proof + nullifier
   ▼
 API (POST /v1/verify) ──stdin/stdout JSON──▶ zk-verifier (Rust) ──▶ valid / invalid
   │                                                           
   └─ PostgreSQL: challenges (single use) · nullifiers (per verifier) · issuer roots · audit (no PII)
```

**The circuit** (`crates/zk-circuits/src/circuit.rs`) proves, privately:
1. the holder knows `(secret, dob_days)` whose leaf is under the issuer's published `merkle_root` (depth 16);
2. `dob_days <= cutoff_days` with all operands range-checked to 32 bits (prevents field wraparound);
3. `nullifier = Poseidon(secret, verifier_id)`;
4. the proof is bound to a server-issued `challenge`.

**Public inputs** (order matters): `merkle_root, cutoff_days, verifier_id, challenge, nullifier`.
The server supplies all of them except the nullifier, so a client cannot pick its own root, cutoff or challenge.

## Repository layout

```text
crates/zk-circuits/   Groth16 circuit, Merkle tree, Poseidon helpers, codecs
crates/zk-cli/        Issuer/holder CLI: setup, issue, root, prove, verify
crates/zk-verifier/   Long-running proof-verification sidecar (line-delimited JSON)
api/src/              Fastify API, auth guards, database pool, migrations
api/test/             Node.js unit tests and fixtures
db/migrations/        PostgreSQL schema
scripts/demo.sh       End-to-end demo workflow
docs/THREAT_MODEL.md  Security assumptions and threat model
```

## Prerequisites

- Rust stable (1.70 or newer) and Cargo
- Node.js 20 or newer
- Docker with Docker Compose
- `make` and `curl` for the quickstart and demo

## Quickstart

```bash
make setup          # build Rust, run DEV-ONLY trusted setup -> keys/pk.bin, keys/vk.bin
make db migrate     # Postgres in Docker + schema
make api            # terminal 1: API on :3000 (needs ADMIN_API_KEY, defaults to dev-admin-key)
make demo           # terminal 2: end-to-end scenario (adult, replay, same-credential, minor, revocation)
make test           # cargo test --release + node tests
```

PostgreSQL is exposed on host port **5438** by `docker-compose.yml`. The API and
`make migrate` read `DATABASE_URL`; the Makefile exports a development default
for the local Docker database.

## Configuration

`.env.example` documents the available development settings. The API does not
load `.env` automatically: export the variables in your shell or rely on the
Makefile's exported defaults. The API reads the following environment
variables directly:

| Variable | Purpose | Default |
|---|---|---|
| `DATABASE_URL` | PostgreSQL connection string | Local Docker database on port 5438 |
| `ADMIN_API_KEY` | Key for admin endpoints; empty disables them | `dev-admin-key` via Makefile |
| `VERIFIER_BIN` | Path to the Rust verifier sidecar | `../target/release/zk-verifier` |
| `VK_PATH` | Path to the serialized verifying key | `../keys/vk.bin` |
| `CHALLENGE_TTL_SECONDS` | Challenge lifetime in seconds | `300` |
| `PORT` | HTTP listen port | `3000` |

Never use the development credentials or the single-party trusted setup in
production. See the limitations and threat model for details.

## API

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /v1/admin/issuers` | `x-admin-key` | register an issuer |
| `POST /v1/admin/issuers/:id/roots` | `x-admin-key` | publish a new credential-tree root (supersedes the old one; omitting a leaf revokes it) |
| `POST /v1/admin/verifiers` | `x-admin-key` | create a verifier; API key returned once, only its hash is stored |
| `POST /v1/challenges` | `x-api-key` | get a single-use challenge, cutoff, `verifier_id`, current `merkle_root` |
| `POST /v1/verify` | `x-api-key` | submit `{challenge_id, proof, nullifier}` (optional `Idempotency-Key`) → `{valid, claim, already_seen}` |
| `GET /v1/.well-known/verification-keys` | none | verifying key + metadata |
| `GET /healthz` | none | liveness + DB check |

## Design decisions worth discussing

- **Nullifier scoped per verifier, not per challenge.** `H(secret, verifier_id)` lets a verifier detect "same
  credential again" (`already_seen`, useful against duplicate accounts) while two verifiers cannot link a user.
  Replay protection comes from the single-use challenge, which the proof is bound to.
- **Challenge consumed atomically before verification** (`UPDATE … WHERE used_at IS NULL … RETURNING`),
  so concurrent submissions race safely and failures can't be ground against one challenge.
- **Canonical field encodings enforced** in Rust (`fr_from_hex`): non-canonical bytes are rejected, otherwise one
  nullifier could have many byte representations and bypass the `(verifier_id, nullifier)` primary key.
- **Unconstrained public inputs are malleable in Groth16**, so `challenge` is forced into a constraint.
- **Data minimisation in the schema**: no DOB, secret, raw proof, or user identifier is ever stored.
- **Verifier as a sidecar over stdio JSON**: keeps proof verification in memory-safe Rust, isolated from the HTTP
  process, restartable (the Node client fails in-flight requests and respawns). Swapping to gRPC or `napi-rs` only
  touches `api/src/verifier-client.js`.

## Known limitations (deliberate MVP scope)

- **Trusted setup is a single-party dev setup.** Whoever ran `zk-cli setup` could forge proofs. Production needs an MPC ceremony.
- **No in-circuit issuer signature.** Authenticity comes from the issuer publishing the Merkle root through an
  authenticated admin channel. A v2 would verify an EdDSA signature in-circuit so credentials are self-authenticating.
- **Holders need a current Merkle path.** The CLI reads the issuer's full tree file; a real system needs a
  path-serving endpoint or a witness-update protocol.
- **Only the current root is accepted.** A root rotation between challenge and verify invalidates in-flight proofs.
  Accept the previous root for a grace window to smooth this.
- Idempotency-key handling is not race-proof for two *concurrent* requests with the same key.
- No rate limiting, webhooks/outbox, issuer key rotation, or circuit versioning yet.
- Poseidon constants come from arkworks' generator, not circomlib: not interoperable with Circom/snarkjs tooling.
- Date arithmetic is UTC and day-granular.

## Roadmap

1. Get `cargo test` green; record proving time / verification time / proof size (add a `bench/` table here).
2. Integration tests for the API against Postgres (replay, expiry, concurrency, revocation).
3. Rate limiting (`@fastify/rate-limit`), request IDs, metrics.
4. gRPC verifier boundary (`tonic`) or `napi-rs` binding; load test showing verifications/sec per worker.
5. In-circuit EdDSA credential signatures; issuer key rotation; circuit versioning table.
6. Webhooks via outbox pattern; revoke-by-leaf with a witness-update service.
7. TypeScript migration of `api/` with generated OpenAPI.

See `docs/THREAT_MODEL.md`.

## License

Released under the [MIT License](LICENSE).
