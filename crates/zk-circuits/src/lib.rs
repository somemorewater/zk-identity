//! Age-proof circuit, Poseidon Merkle tree and Groth16 helpers.
//!
//! Field elements cross every boundary (CLI, verifier sidecar, HTTP API) as
//! 32-byte little-endian hex strings. See `codec`.

pub mod circuit;
pub mod codec;
pub mod merkle;
pub mod poseidon;
pub mod proving;

pub use ark_bn254::{Bn254, Fr};
pub use ark_groth16::{PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
pub use circuit::{build_circuit, AgeProofCircuit, PublicInputs};
pub use codec::{fr_from_hex, fr_to_hex};
pub use merkle::{MerklePath, MerkleTree, DEPTH};
pub use proving::{from_bytes, prepare_vk, prove, random_fr, setup, to_bytes, verify};
