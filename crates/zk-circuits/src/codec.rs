use anyhow::{bail, Result};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

/// Canonical encoding: 32 bytes, little-endian, lowercase hex (64 chars).
pub fn fr_to_hex(x: &Fr) -> String {
    let mut bytes = x.into_bigint().to_bytes_le();
    bytes.resize(32, 0);
    hex::encode(bytes)
}

/// Strict decoder. Rejects wrong length, uppercase, and non-canonical values
/// (>= field modulus). Accepting non-canonical encodings would let one field
/// element have several byte representations, which would defeat nullifier
/// uniqueness checks done on raw bytes.
pub fn fr_from_hex(s: &str) -> Result<Fr> {
    if s.len() != 64 {
        bail!("field element must be 64 hex chars, got {}", s.len());
    }
    let bytes = hex::decode(s)?;
    let fr = Fr::from_le_bytes_mod_order(&bytes);
    if fr_to_hex(&fr) != s {
        bail!("non-canonical field element encoding");
    }
    Ok(fr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let x = Fr::from(123456789u64);
        assert_eq!(fr_from_hex(&fr_to_hex(&x)).unwrap(), x);
    }

    #[test]
    fn rejects_non_canonical_and_uppercase() {
        // 2^256 - 1 is far above the BN254 scalar modulus.
        assert!(fr_from_hex(&"ff".repeat(32)).is_err());
        let x = fr_to_hex(&Fr::from(0xabcdefu64)).to_uppercase();
        assert!(fr_from_hex(&x).is_err());
        assert!(fr_from_hex("00").is_err());
    }
}
