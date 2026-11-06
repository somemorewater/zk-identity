use anyhow::{ensure, Result};
use ark_bn254::Fr;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::merkle::{self, MerkleTree, DEPTH};
use crate::poseidon::{hash, hash_var, DOMAIN_LEAF, DOMAIN_NODE, DOMAIN_NULLIFIER};

/// Public inputs, in the exact order the circuit allocates them.
#[derive(Clone, Debug)]
pub struct PublicInputs {
    pub merkle_root: Fr,
    pub cutoff_days: Fr,
    pub verifier_id: Fr,
    pub challenge: Fr,
    pub nullifier: Fr,
}

impl PublicInputs {
    pub fn to_vec(&self) -> Vec<Fr> {
        vec![self.merkle_root, self.cutoff_days, self.verifier_id, self.challenge, self.nullifier]
    }
}

/// Proves, without revealing `secret`, `dob_days` or the leaf position:
///  1. the holder knows a credential leaf `H(LEAF, secret, dob_days)` under `merkle_root`
///  2. `dob_days <= cutoff_days` (i.e. at least N years old)
///  3. `nullifier = H(NULLIFIER, secret, verifier_id)` - stable per (credential, verifier),
///     unlinkable across verifiers
///  4. the proof is bound to `challenge` (anti-replay)
///
/// All fields are `Option` so the same struct can be used for setup (blank) and proving.
#[derive(Clone, Default)]
pub struct AgeProofCircuit {
    // public
    pub merkle_root: Option<Fr>,
    pub cutoff_days: Option<Fr>,
    pub verifier_id: Option<Fr>,
    pub challenge: Option<Fr>,
    pub nullifier: Option<Fr>,
    // private
    pub secret: Option<Fr>,
    pub dob_days: Option<Fr>,
    pub siblings: Option<Vec<Fr>>,
    pub path_bits: Option<Vec<bool>>,
}

impl AgeProofCircuit {
    pub fn blank() -> Self {
        Self::default()
    }
}

/// Constrain `x` to fit in 32 bits. Both operands of the age comparison MUST be
/// range-checked, otherwise a prover could pick a "negative" field element
/// (e.g. p - 1) as `dob_days` and wrap around the inequality.
fn enforce_u32(x: &FpVar<Fr>) -> Result<(), SynthesisError> {
    let bits = x.to_bits_le()?; // canonical (strict) decomposition
    for b in bits.iter().skip(32) {
        b.enforce_equal(&Boolean::constant(false))?;
    }
    Ok(())
}

impl ConstraintSynthesizer<Fr> for AgeProofCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Public inputs. ORDER MATTERS: must match PublicInputs::to_vec.
        let root = FpVar::new_input(cs.clone(), || self.merkle_root.ok_or(SynthesisError::AssignmentMissing))?;
        let cutoff = FpVar::new_input(cs.clone(), || self.cutoff_days.ok_or(SynthesisError::AssignmentMissing))?;
        let verifier_id = FpVar::new_input(cs.clone(), || self.verifier_id.ok_or(SynthesisError::AssignmentMissing))?;
        let challenge = FpVar::new_input(cs.clone(), || self.challenge.ok_or(SynthesisError::AssignmentMissing))?;
        let nullifier = FpVar::new_input(cs.clone(), || self.nullifier.ok_or(SynthesisError::AssignmentMissing))?;

        // Private witness.
        let secret = FpVar::new_witness(cs.clone(), || self.secret.ok_or(SynthesisError::AssignmentMissing))?;
        let dob = FpVar::new_witness(cs.clone(), || self.dob_days.ok_or(SynthesisError::AssignmentMissing))?;

        // 1. Membership.
        let mut cur = hash_var(cs.clone(), DOMAIN_LEAF, &[secret.clone(), dob.clone()])?;
        for level in 0..DEPTH {
            let sib = FpVar::new_witness(cs.clone(), || {
                self.siblings.as_ref().map(|s| s[level]).ok_or(SynthesisError::AssignmentMissing)
            })?;
            let is_right = Boolean::new_witness(cs.clone(), || {
                self.path_bits.as_ref().map(|b| b[level]).ok_or(SynthesisError::AssignmentMissing)
            })?;
            let left = FpVar::conditionally_select(&is_right, &sib, &cur)?;
            let right = FpVar::conditionally_select(&is_right, &cur, &sib)?;
            cur = hash_var(cs.clone(), DOMAIN_NODE, &[left, right])?;
        }
        cur.enforce_equal(&root)?;

        // 2. Age predicate: dob <= cutoff, all three values within 32 bits.
        enforce_u32(&dob)?;
        enforce_u32(&cutoff)?;
        enforce_u32(&(&cutoff - &dob))?;

        // 3. Scoped nullifier.
        let nf = hash_var(cs.clone(), DOMAIN_NULLIFIER, &[secret, verifier_id])?;
        nf.enforce_equal(&nullifier)?;

        // 4. Bind the challenge. A Groth16 public input that appears in no
        //    constraint is malleable (any value verifies), so force it into one.
        let _challenge_sq = challenge.square()?;

        Ok(())
    }
}

/// Build the circuit assignment and public inputs for one credential.
/// Does NOT check the age predicate, so tests can build failing cases.
pub fn build_circuit(
    tree: &MerkleTree,
    index: usize,
    secret: Fr,
    dob_days: Fr,
    cutoff_days: u32,
    verifier_id: Fr,
    challenge: Fr,
) -> Result<(AgeProofCircuit, PublicInputs)> {
    let leaf = merkle::leaf(secret, dob_days);
    ensure!(
        tree.leaves.get(index) == Some(&leaf),
        "credential does not match leaf {index} of the issuer tree"
    );
    let path = tree.path(index)?;
    let public = PublicInputs {
        merkle_root: tree.root(),
        cutoff_days: Fr::from(cutoff_days as u64),
        verifier_id,
        challenge,
        nullifier: hash(DOMAIN_NULLIFIER, &[secret, verifier_id]),
    };
    let circuit = AgeProofCircuit {
        merkle_root: Some(public.merkle_root),
        cutoff_days: Some(public.cutoff_days),
        verifier_id: Some(public.verifier_id),
        challenge: Some(public.challenge),
        nullifier: Some(public.nullifier),
        secret: Some(secret),
        dob_days: Some(dob_days),
        siblings: Some(path.siblings),
        path_bits: Some(path.bits),
    };
    Ok((circuit, public))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    const CUTOFF: u32 = 39_753; // 2008-11-03 in days since 1900-01-01

    fn satisfied(c: AgeProofCircuit) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        cs.is_satisfied().unwrap()
    }

    fn fixture(dob: Fr) -> (AgeProofCircuit, PublicInputs) {
        let secret = Fr::from(42u64);
        let mut tree = MerkleTree::default();
        tree.leaves.push(merkle::leaf(Fr::from(11u64), Fr::from(30_000u64)));
        tree.leaves.push(merkle::leaf(secret, dob));
        tree.leaves.push(merkle::leaf(Fr::from(13u64), Fr::from(31_000u64)));
        build_circuit(&tree, 1, secret, dob, CUTOFF, Fr::from(7u64), Fr::from(99u64)).unwrap()
    }

    #[test]
    fn valid_adult_is_satisfied() {
        assert!(satisfied(fixture(Fr::from(36_000u64)).0));
    }

    #[test]
    fn exactly_at_cutoff_is_satisfied() {
        assert!(satisfied(fixture(Fr::from(CUTOFF as u64)).0));
    }

    #[test]
    fn one_day_too_young_fails() {
        assert!(!satisfied(fixture(Fr::from(CUTOFF as u64 + 1)).0));
    }

    #[test]
    fn field_wraparound_attack_fails() {
        // dob = -1 mod p would make (cutoff - dob) a tiny number if it were not
        // range-checked. The 32-bit constraint on dob must reject it.
        let minus_one = Fr::from(0u64) - Fr::from(1u64);
        assert!(!satisfied(fixture(minus_one).0));
    }

    #[test]
    fn wrong_root_fails() {
        let (mut c, _) = fixture(Fr::from(36_000u64));
        c.merkle_root = Some(Fr::from(5u64));
        assert!(!satisfied(c));
    }

    #[test]
    fn wrong_nullifier_fails() {
        let (mut c, _) = fixture(Fr::from(36_000u64));
        c.nullifier = Some(Fr::from(5u64));
        assert!(!satisfied(c));
    }

    #[test]
    fn leaf_mismatch_is_rejected_at_build_time() {
        let mut tree = MerkleTree::default();
        tree.leaves.push(merkle::leaf(Fr::from(1u64), Fr::from(2u64)));
        assert!(build_circuit(&tree, 0, Fr::from(9u64), Fr::from(2u64), CUTOFF, Fr::from(1u64), Fr::from(1u64)).is_err());
    }
}
