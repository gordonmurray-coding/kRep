//! Membership accumulator over anchored attestations.
//!
//! Proves "this attestation id really is anchored" without the verifier
//! re-scanning the chain per attestation. The set is reproducible by anyone
//! with a node — see [`crate::scan`] — so the root is not something a prover
//! gets to choose.
//!
//! Leaves are sorted and de-duplicated before the tree is built, which makes
//! the root a function of the *set* rather than of insertion order. Two people
//! who scan the same chain range must get the same root, or the accumulator is
//! useless as a shared reference point.

use crate::hash::{hash_leaf, hash_node, Field};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleTree {
    /// Level 0 is the leaves; the last level holds the root alone. Only the
    /// occupied prefix of each level is materialised.
    levels: Vec<Vec<Field>>,
    leaves: Vec<Field>,
    /// Hash of an empty subtree at each height, for the unoccupied remainder.
    /// Empty for minimal-depth trees, which have no padding.
    empties: Vec<Field>,
}

/// A path from a leaf to the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    pub leaf_index: usize,
    /// Sibling at each level, bottom-up.
    pub siblings: Vec<Field>,
}

impl MerkleTree {
    /// Build to a fixed depth, padding with a designated empty leaf.
    ///
    /// A circuit's array sizes are static, so it walks a path of one known
    /// length; a minimal-depth tree whose shape follows the leaf count would
    /// need a different circuit per accumulator size.
    ///
    /// The padding costs nothing. An empty subtree of a given height has one
    /// value regardless of where it sits, so those are precomputed once and the
    /// occupied prefix is the only thing actually hashed. Materialising all
    /// `2^depth` slots instead — the obvious implementation, and the one this
    /// replaced — meant about two million permutations for a depth-20 tree
    /// holding four thousand leaves, which dominated everything else by orders
    /// of magnitude.
    pub fn build_fixed_depth(values: impl IntoIterator<Item = Vec<u8>>, depth: usize) -> MerkleTree {
        let mut leaves: Vec<Field> = values.into_iter().map(|v| hash_leaf(&v)).collect();
        leaves.sort_unstable_by_key(|f| f.to_string());
        leaves.dedup();
        assert!(leaves.len() <= 1usize << depth, "{} leaves exceed depth {depth}", leaves.len());

        // Hash of an empty subtree at each height.
        let mut empties = Vec::with_capacity(depth + 1);
        empties.push(empty_leaf());
        for level in 0..depth {
            let below = empties[level];
            empties.push(hash_node(&below, &below));
        }

        let mut levels = vec![leaves.clone()];
        for level in 0..depth {
            let prev = &levels[level];
            let filler = empties[level];
            let mut next = Vec::with_capacity(prev.len().div_ceil(2));
            for pair in prev.chunks(2) {
                let right = pair.get(1).copied().unwrap_or(filler);
                next.push(hash_node(&pair[0], &right));
            }
            if next.is_empty() {
                next.push(empties[level + 1]);
            }
            levels.push(next);
        }
        MerkleTree { levels, leaves, empties }
    }

    /// Build from raw values. Sorted and de-duplicated, so the root depends
    /// only on which values are present.
    pub fn build(values: impl IntoIterator<Item = Vec<u8>>) -> MerkleTree {
        let mut leaves: Vec<Field> = values.into_iter().map(|v| hash_leaf(&v)).collect();
        leaves.sort_unstable_by_key(|f| f.to_string());
        leaves.dedup();
        Self::from_sorted_leaves(leaves)
    }

    fn from_sorted_leaves(leaves: Vec<Field>) -> MerkleTree {
        if leaves.is_empty() {
            return MerkleTree { levels: vec![vec![]], leaves, empties: Vec::new() };
        }
        let mut levels = vec![leaves.clone()];
        while levels.last().expect("non-empty").len() > 1 {
            let prev = levels.last().expect("non-empty");
            let mut next = Vec::with_capacity(prev.len().div_ceil(2));
            for pair in prev.chunks(2) {
                // An odd node is paired with itself. Because leaves are
                // de-duplicated first, this cannot be confused with a genuine
                // duplicate-sibling pair.
                let right = pair.get(1).unwrap_or(&pair[0]);
                next.push(hash_node(&pair[0], right));
            }
            levels.push(next);
        }
        MerkleTree { levels, leaves, empties: Vec::new() }
    }

    pub fn root(&self) -> Option<Field> {
        self.levels.last().and_then(|l| l.first()).copied()
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn index_of(&self, value: &[u8]) -> Option<usize> {
        let leaf = hash_leaf(value);
        self.leaves.iter().position(|l| *l == leaf)
    }

    pub fn prove(&self, value: &[u8]) -> Option<MerkleProof> {
        let mut index = self.index_of(value)?;
        let mut siblings = Vec::with_capacity(self.levels.len());
        for (height, level) in self.levels[..self.levels.len() - 1].iter().enumerate() {
            let sibling = if index.is_multiple_of(2) {
                match (level.get(index + 1), self.empties.get(height)) {
                    (Some(s), _) => *s,
                    // Past the occupied prefix the sibling is an empty subtree.
                    // A minimal-depth tree has no padding and pairs an odd node
                    // with itself instead — the two must agree with how the
                    // corresponding build filled it, or proofs silently fail.
                    (None, Some(filler)) => *filler,
                    (None, None) => level[index],
                }
            } else {
                level[index - 1]
            };
            siblings.push(sibling);
            index /= 2;
        }
        Some(MerkleProof { leaf_index: self.index_of(value)?, siblings })
    }
}

/// The value padding an unoccupied slot. Distinct from any real leaf because
/// real leaves absorb their own byte length, and this absorbs none.
pub fn empty_leaf() -> Field {
    crate::hash::hash_leaf_fields(&[])
}

/// Recompute a root from a value and its path. This is the half a circuit
/// performs: it never sees the tree, only the leaf and the siblings.
pub fn verify(root: &Field, value: &[u8], proof: &MerkleProof) -> bool {
    let mut node = hash_leaf(value);
    let mut index = proof.leaf_index;
    for sibling in &proof.siblings {
        node = if index.is_multiple_of(2) { hash_node(&node, sibling) } else { hash_node(sibling, &node) };
        index /= 2;
    }
    node == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vals(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| format!("attestation-{i}").into_bytes()).collect()
    }

    #[test]
    fn every_member_proves_and_verifies() {
        for n in [1usize, 2, 3, 4, 5, 8, 9, 17, 64] {
            let values = vals(n);
            let tree = MerkleTree::build(values.clone());
            let root = tree.root().expect("non-empty tree has a root");
            assert_eq!(tree.len(), n);
            for v in &values {
                let proof = tree.prove(v).unwrap_or_else(|| panic!("{n} leaves: no proof for a member"));
                assert!(verify(&root, v, &proof), "{n} leaves: member failed to verify");
            }
        }
    }

    #[test]
    fn a_non_member_has_no_proof_and_cannot_be_faked() {
        let tree = MerkleTree::build(vals(8));
        let root = tree.root().unwrap();
        assert!(tree.prove(b"attestation-99").is_none(), "no proof should exist");

        // Nor can a member's path be reused to vouch for something else — this
        // is the attack the accumulator exists to stop.
        let stolen = tree.prove(b"attestation-3").unwrap();
        assert!(!verify(&root, b"attestation-99", &stolen));
    }

    #[test]
    fn the_root_is_a_function_of_the_set_not_the_order() {
        // Two people scanning the same chain must agree, whatever order they
        // encountered things in.
        let mut a = vals(16);
        let mut b = a.clone();
        b.reverse();
        b.push(a[3].clone()); // and a duplicate must not change it either
        a.push(a[7].clone());
        assert_eq!(MerkleTree::build(a).root(), MerkleTree::build(b).root());
    }

    #[test]
    fn changing_any_member_changes_the_root() {
        let base = MerkleTree::build(vals(9)).root().unwrap();
        let mut changed = vals(9);
        changed[4] = b"tampered".to_vec();
        assert_ne!(MerkleTree::build(changed).root().unwrap(), base);

        let mut extra = vals(9);
        extra.push(b"one-more".to_vec());
        assert_ne!(MerkleTree::build(extra).root().unwrap(), base);
    }

    #[test]
    fn a_tampered_path_does_not_verify() {
        let tree = MerkleTree::build(vals(8));
        let root = tree.root().unwrap();
        let good = tree.prove(b"attestation-5").unwrap();

        let mut flipped = good.clone();
        flipped.siblings[0] += crate::hash::Field::from(1u128);
        assert!(!verify(&root, b"attestation-5", &flipped), "a corrupted sibling must fail");

        // Claiming a different position with the same siblings must also fail,
        // since position decides which side each hash goes on.
        let mut moved = good;
        moved.leaf_index ^= 1;
        assert!(!verify(&root, b"attestation-5", &moved));
    }

    #[test]
    fn fixed_depth_proofs_verify_and_the_padding_is_free() {
        // The padding optimisation must not change what the tree means: every
        // member still proves, non-members still cannot, and the root is
        // stable across however many empty slots follow.
        for n in [1usize, 2, 3, 5, 16, 17] {
            let values = vals(n);
            let tree = MerkleTree::build_fixed_depth(values.clone(), 10);
            let root = tree.root().expect("root");
            assert_eq!(tree.len(), n);
            for v in &values {
                let proof = tree.prove(v).unwrap_or_else(|| panic!("{n}: no proof"));
                assert_eq!(proof.siblings.len(), 10, "a fixed-depth path is always depth long");
                assert!(verify(&root, v, &proof), "{n}: member failed to verify");
            }
            assert!(tree.prove(b"not-a-member").is_none());
        }
    }

    #[test]
    fn depth_changes_the_root_even_for_the_same_members() {
        // A root is only meaningful alongside the depth it was built at, since
        // the padding participates in it. Verifier and circuit must agree.
        let a = MerkleTree::build_fixed_depth(vals(4), 8).root().unwrap();
        let b = MerkleTree::build_fixed_depth(vals(4), 10).root().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn an_empty_set_has_no_root() {
        let tree = MerkleTree::build(Vec::<Vec<u8>>::new());
        assert!(tree.is_empty());
        assert_eq!(tree.root(), None, "an empty accumulator must not present a usable root");
    }
}
