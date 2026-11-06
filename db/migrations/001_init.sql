-- Privacy by construction: no table below stores a date of birth, a secret,
-- a raw proof, or any user identifier. Only hashes and metadata.

CREATE TABLE issuers (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Append-only history of published credential-tree roots.
-- Publishing a root that omits a leaf is how a credential is revoked.
CREATE TABLE issuer_roots (
  id             BIGSERIAL PRIMARY KEY,
  issuer_id      UUID NOT NULL REFERENCES issuers(id),
  root           BYTEA NOT NULL CHECK (octet_length(root) = 32),
  published_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  superseded_at  TIMESTAMPTZ
);
-- At most one current root per issuer.
CREATE UNIQUE INDEX issuer_roots_one_current ON issuer_roots (issuer_id) WHERE superseded_at IS NULL;

CREATE TABLE verifiers (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name          TEXT NOT NULL,
  api_key_hash  BYTEA NOT NULL UNIQUE,   -- sha256 of a 256-bit random key
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE challenges (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  verifier_id  UUID NOT NULL REFERENCES verifiers(id),
  issuer_id    UUID NOT NULL REFERENCES issuers(id),
  claim_type   TEXT NOT NULL,
  nonce        BYTEA NOT NULL CHECK (octet_length(nonce) = 32),
  cutoff_days  INTEGER NOT NULL,          -- days since 1900-01-01, fixed at issue time
  expires_at   TIMESTAMPTZ NOT NULL,
  used_at      TIMESTAMPTZ
);
CREATE INDEX challenges_expires_idx ON challenges (expires_at);

-- One row per (verifier, credential). The nullifier is H(secret, verifier_id):
-- stable for a verifier (so it can detect "same credential again"), but
-- unlinkable across verifiers and reveals nothing about the credential.
CREATE TABLE nullifiers (
  verifier_id   UUID NOT NULL REFERENCES verifiers(id),
  nullifier     BYTEA NOT NULL CHECK (octet_length(nullifier) = 32),
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (verifier_id, nullifier)
);

CREATE TABLE verification_audit (
  id           BIGSERIAL PRIMARY KEY,
  verifier_id  UUID NOT NULL,
  claim_type   TEXT,
  result       BOOLEAN NOT NULL,
  reason       TEXT,                      -- short failure code only
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE idempotency_keys (
  verifier_id  UUID NOT NULL,
  key          TEXT NOT NULL,
  status_code  INTEGER NOT NULL,
  response     JSONB NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (verifier_id, key)
);
