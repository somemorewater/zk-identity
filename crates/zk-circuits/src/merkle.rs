use anyhow::{bail, Result};
use ark_bn254::Fr;

use crate::poseidon::{hash, DOMAIN_LEAF, DOMAIN_NODE};

/// Fixed depth => up to 65,536 credentials per issuer tree.
pub const DEPTH: usize = 16;

pub fn leaf(secret: Fr, dob_days: Fr) -> Fr {
    hash(DOMAIN_LEAF, &[secret, dob_days])
}

pub fn node(left: Fr, right: Fr) -> Fr {
    hash(DOMAIN_NODE, &[left, right])
}

#[derive(Clone, Debug)]
pub struct MerklePath {
    /// Sibling hash at each level, leaf level first.
    pub siblings: Vec<Fr>,
    /// `true` when the node on the path is the RIGHT child at that level.
    pub bits: Vec<bool>,
}

/// Append-only tree with empty-subtree defaults. Recomputed from the leaf
/// list on demand: simple and fine for an MVP issuer tool.
#[derive(Clone, Debug, Default)]
pub struct MerkleTree {
    pub leaves: Vec<Fr>,
}

impl MerkleTree {
    fn zeros() -> Vec<Fr> {
        let mut z = vec![Fr::from(0u64)];
        for i in 0..DEPTH {
            z.push(node(z[i], z[i]));
        }
        z
    }

    fn layers(&self) -> Vec<Vec<Fr>> {
        let zeros = Self::zeros();
        let mut layers: Vec<Vec<Fr>> = vec![self.leaves.clone()];
        for level in 0..DEPTH {
            let cur = &layers[level];
            let mut next = Vec::with_capacity(cur.len() / 2 + 1);
            let mut i = 0;
            while i < cur.len() {
                let l = cur[i];
                let r = if i + 1 < cur.len() { cur[i + 1] } else { zeros[level] };
                next.push(node(l, r));
                i += 2;
            }
            if next.is_empty() {
                next.push(zeros[level + 1]);
            }
            layers.push(next);
        }
        layers
    }

    pub fn root(&self) -> Fr {
        self.layers()[DEPTH][0]
    }

    pub fn path(&self, index: usize) -> Result<MerklePath> {
        if index >= self.leaves.len() {
            bail!("leaf index {index} out of range ({} leaves)", self.leaves.len());
        }
        let zeros = Self::zeros();
        let layers = self.layers();
        let mut idx = index;
        let mut siblings = Vec::with_capacity(DEPTH);
        let mut bits = Vec::with_capacity(DEPTH);
        for level in 0..DEPTH {
            let sib = layers[level].get(idx ^ 1).copied().unwrap_or(zeros[level]);
            siblings.push(sib);
            bits.push(idx & 1 == 1);
            idx >>= 1;
        }
        Ok(MerklePath { siblings, bits })
    }

    /// Native recomputation of the root from a leaf and path (used in tests).
    pub fn root_from_path(leaf: Fr, path: &MerklePath) -> Fr {
        let mut cur = leaf;
        for (sib, is_right) in path.siblings.iter().zip(path.bits.iter()) {
            cur = if *is_right { node(*sib, cur) } else { node(cur, *sib) };
        }
        cur
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_recompute_to_root() {
        let mut t = MerkleTree::default();
        for i in 0..5u64 {
            t.leaves.push(leaf(Fr::from(i + 1), Fr::from(30000 + i)));
        }
        let root = t.root();
        for i in 0..5 {
            let p = t.path(i).unwrap();
            assert_eq!(MerkleTree::root_from_path(t.leaves[i], &p), root);
        }
        assert!(t.path(5).is_err());
    }

    #[test]
    fn adding_a_leaf_changes_root() {
        let mut t = MerkleTree::default();
        let empty = t.root();
        t.leaves.push(leaf(Fr::from(1u64), Fr::from(2u64)));
        assert_ne!(empty, t.root());
    }
}
