use anyhow::{anyhow, Result};
use ark_bn254::{Bn254, Fr};
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::UniformRand;
use rand::rngs::OsRng;

use crate::circuit::{AgeProofCircuit, PublicInputs};

/// Circuit-specific trusted setup. DEV ONLY: whoever runs this knows the toxic
/// waste. A production deployment needs a multi-party ceremony.
pub fn setup() -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>)> {
    Groth16::<Bn254>::circuit_specific_setup(AgeProofCircuit::blank(), &mut OsRng)
        .map_err(|e| anyhow!("setup failed: {e}"))
}

pub fn prove(pk: &ProvingKey<Bn254>, circuit: AgeProofCircuit) -> Result<Proof<Bn254>> {
    Groth16::<Bn254>::prove(pk, circuit, &mut OsRng).map_err(|e| anyhow!("proving failed: {e}"))
}

pub fn prepare_vk(vk: &VerifyingKey<Bn254>) -> PreparedVerifyingKey<Bn254> {
    prepare_verifying_key(vk)
}

pub fn verify(pvk: &PreparedVerifyingKey<Bn254>, inputs: &PublicInputs, proof: &Proof<Bn254>) -> Result<bool> {
    Groth16::<Bn254>::verify_with_processed_vk(pvk, &inputs.to_vec(), proof)
        .map_err(|e| anyhow!("verification error: {e}"))
}

pub fn to_bytes<T: CanonicalSerialize>(t: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    t.serialize_compressed(&mut buf).expect("serialization to Vec cannot fail");
    buf
}

/// Deserialization validates curve and subgroup membership.
pub fn from_bytes<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T> {
    T::deserialize_compressed(bytes).map_err(|e| anyhow!("deserialize: {e}"))
}

pub fn random_fr() -> Fr {
    Fr::rand(&mut OsRng)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{build_circuit, merkle, MerkleTree};

    #[test]
    fn end_to_end_prove_and_verify() {
        let (pk, vk) = setup().unwrap();
        let pvk = prepare_vk(&vk);

        let secret = Fr::from(42u64);
        let dob = Fr::from(36_000u64);
        let mut tree = MerkleTree::default();
        tree.leaves.push(merkle::leaf(secret, dob));
        let (circuit, public) =
            build_circuit(&tree, 0, secret, dob, 39_753, Fr::from(7u64), Fr::from(99u64)).unwrap();

        let proof = prove(&pk, circuit).unwrap();

        // Survives a serialization round-trip.
        let proof: Proof<Bn254> = from_bytes(&to_bytes(&proof)).unwrap();
        assert!(verify(&pvk, &public, &proof).unwrap());

        // Any public input change must invalidate the proof.
        let mut other_challenge = public.clone();
        other_challenge.challenge = Fr::from(100u64);
        assert!(!verify(&pvk, &other_challenge, &proof).unwrap());

        let mut other_verifier = public.clone();
        other_verifier.verifier_id = Fr::from(8u64);
        assert!(!verify(&pvk, &other_verifier, &proof).unwrap());

        let mut other_cutoff = public.clone();
        other_cutoff.cutoff_days = Fr::from(30_000u64);
        assert!(!verify(&pvk, &other_cutoff, &proof).unwrap());
    }
}
