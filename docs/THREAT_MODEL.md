# Threat model

## Goal
A verifier learns exactly one fact (holder is at least 18, per a trusted issuer) and nothing else.
The service itself must not become a store of personal data.

## Assets
- Holder secrets and dates of birth (never leave the holder; never stored by the service)
- Integrity of the "valid" verdict
- Unlinkability of a holder across verifiers
- Availability of verification

## Actors
Malicious holder (wants a false "over 18"), colluding verifiers (want to link users), network attacker,
curious/compromised service operator, malicious or compromised issuer.

## Threats and mitigations

| Threat | Mitigation | Residual risk |
|---|---|---|
| Minor forges a proof | Soundness of Groth16; 32-bit range checks on `dob`, `cutoff`, and `cutoff - dob` (wraparound test in `circuit.rs`) | Soundness depends on an honest trusted setup (dev setup is NOT honest-by-construction) |
| Proof replay | Challenge is a public input, single-use, expiring, bound to one verifier; consumed atomically | None known |
| Replay by a different verifier | `verifier_id` is a public input, set by the server | None known |
| Client chooses its own root/cutoff | Server supplies all public inputs except the nullifier | None |
| Proof malleability via unconstrained input | `challenge` forced into a constraint | Review whenever public inputs change |
| Duplicate nullifier via non-canonical encoding | Strict canonical decoding in Rust; lowercase 64-hex regex in the API | None known |
| Cross-verifier linkage | `nullifier = H(secret, verifier_id)` differs per verifier; Poseidon is preimage-resistant | Verifiers can still collude via side channels (IP, timing, out-of-band IDs) |
| Operator reads DB | No DOB, secrets, proofs or identities stored; audit holds result + failure code only | Metadata (timing, volume) is visible |
| Stolen verifier API key | Keys are 256-bit random, stored as SHA-256; shown once | No rotation endpoint yet |
| Revoked credential still accepted | Verification uses the *current* published root only | Revocation latency = root publication latency |
| Malicious issuer | Out of scope: the issuer is the trust anchor and can mint any credential | Mitigate with multi-issuer policies and audits |
| Verifier sidecar crash / DoS | Client timeout, fail in-flight, auto-restart; 64 KB body limit; fixed-size proof regex | No rate limiting yet |
| Malformed proof bytes | arkworks deserialization validates curve and subgroup membership | Keep arkworks updated |
| Holder device compromise | Out of scope | Secret in `cred.json` is plaintext on disk |

## Explicit non-goals
Document verification / KYC at issuance, device binding, liveness, sybil resistance across verifiers,
post-quantum security (Groth16/BN254 is not PQ-secure).
