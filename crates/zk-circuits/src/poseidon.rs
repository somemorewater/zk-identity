use std::sync::OnceLock;

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{
        constraints::PoseidonSpongeVar, find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge,
    },
    CryptographicSponge,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

/// Domain separation tags, absorbed first so a leaf hash can never collide
/// with an inner-node hash or a nullifier.
pub const DOMAIN_LEAF: u64 = 1;
pub const DOMAIN_NODE: u64 = 2;
pub const DOMAIN_NULLIFIER: u64 = 3;

/// Poseidon over BN254 Fr: rate 2, capacity 1, alpha 5, 8 full + 57 partial
/// rounds, round constants generated with arkworks' Grain LFSR.
/// NOT compatible with circomlib's Poseidon constants.
pub fn poseidon_config() -> &'static PoseidonConfig<Fr> {
    static CFG: OnceLock<PoseidonConfig<Fr>> = OnceLock::new();
    CFG.get_or_init(|| {
        let (full_rounds, partial_rounds, alpha, rate, capacity) = (8usize, 57usize, 5u64, 2usize, 1usize);
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
            Fr::MODULUS_BIT_SIZE as u64,
            rate,
            full_rounds as u64,
            partial_rounds as u64,
            0,
        );
        PoseidonConfig::new(full_rounds, partial_rounds, alpha, mds, ark, rate, capacity)
    })
}

/// Native hash.
pub fn hash(domain: u64, inputs: &[Fr]) -> Fr {
    let mut sponge = PoseidonSponge::<Fr>::new(poseidon_config());
    sponge.absorb(&Fr::from(domain));
    for x in inputs {
        sponge.absorb(x);
    }
    sponge.squeeze_field_elements::<Fr>(1)[0]
}

/// In-circuit hash. Must mirror `hash` exactly.
pub fn hash_var(
    cs: ConstraintSystemRef<Fr>,
    domain: u64,
    inputs: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::<Fr>::new(cs, poseidon_config());
    sponge.absorb(&FpVar::constant(Fr::from(domain)))?;
    for x in inputs {
        sponge.absorb(x)?;
    }
    let out = sponge.squeeze_field_elements(1)?;
    Ok(out[0].clone())
}
