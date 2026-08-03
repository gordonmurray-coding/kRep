//! Non-membership accumulator over defaulted pseudonyms.
//!
//! A sparse Merkle tree keyed by pseudonym. Every one of the 2^256 possible
//! keys has a slot; almost all are empty, and an empty subtree of any height
//! has a known hash, so the tree is cheap despite its depth.
//!
//! That is exactly the property "0 defaults" needs. Proving *presence* is what
//! ordinary Merkle trees do; proving that you are **absent** from a set is what
//! stops a prover truncating their chain and claiming a clean record. Here the
//! prover shows the slot for their pseudonym is empty, which says nothing about
//! who they are.
//!
//! The tree is keyed by the pseudonym itself rather than by an index, so its
//! shape is fixed by the key space. Anyone rebuilding it from the same set of
//! defaults gets the same root, and there is no ordering to disagree about.

use crate::hash::{hash_leaf, hash_node, Digest32};
use std::collections::HashMap;

/// Height in bits — one level per bit of the 32-byte key.
pub const DEPTH: usize = 256;

/// What occupies a slot. Absence is the interesting case.
const EMPTY: Digest32 = [0u8; 32];

#[derive(Debug, Clone)]
pub struct SparseMerkleTree {
    /// Occupied leaves, keyed by pseudonym.
    entries: HashMap<Digest32, Digest32>,
    /// Hash of an empty subtree at each height; index 0 is an empty leaf.
    empties: Vec<Digest32>,
}

/// A path proving what occupies (or does not occupy) one key's slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtProof {
    pub key: Digest32,
    /// Sibling at each level, from the leaf upward.
    pub siblings: Vec<Digest32>,
    /// The leaf value found there — `None` means the slot is empty, which is
    /// the whole point of this structure.
    pub value: Option<Digest32>,
}

impl SmtProof {
    pub fn proves_absence(&self) -> bool {
        self.value.is_none()
    }
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SparseMerkleTree {
    pub fn new() -> SparseMerkleTree {
        // Precompute the hash of an empty subtree at every height, so the
        // 2^256 unoccupied slots cost nothing to represent.
        let mut empties = Vec::with_capacity(DEPTH + 1);
        empties.push(EMPTY);
        for level in 0..DEPTH {
            let below = empties[level];
            empties.push(hash_node(&below, &below));
        }
        SparseMerkleTree { entries: HashMap::new(), empties }
    }

    /// Record a pseudonym as having defaulted. The value stored is a hash of
    /// the key, so the leaf commits to which key it belongs to.
    pub fn insert(&mut self, key: Digest32) {
        self.entries.insert(key, hash_leaf(&key));
    }

    pub fn from_keys(keys: impl IntoIterator<Item = Digest32>) -> SparseMerkleTree {
        let mut t = SparseMerkleTree::new();
        for k in keys {
            t.insert(k);
        }
        t
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, key: &Digest32) -> bool {
        self.entries.contains_key(key)
    }

    fn bit(key: &Digest32, level: usize) -> bool {
        // Level 0 is the leaf; the root splits on the most significant bit, so
        // level `l` from the bottom looks at bit `DEPTH - 1 - l`.
        let idx = DEPTH - 1 - level;
        key[idx / 8] & (1 << (7 - (idx % 8))) != 0
    }

    /// Hash of the subtree rooted at `level` covering the given prefix.
    ///
    /// Only keys sharing the prefix matter; if none do, the answer is the
    /// precomputed empty hash and the recursion stops immediately. That is what
    /// keeps a 256-deep tree tractable.
    fn subtree(&self, level: usize, prefix: &[bool]) -> Digest32 {
        let members: Vec<&Digest32> = self
            .entries
            .keys()
            .filter(|k| prefix.iter().enumerate().all(|(i, b)| Self::bit(k, DEPTH - 1 - i) == *b))
            .collect();
        if members.is_empty() {
            return self.empties[level];
        }
        if level == 0 {
            return self.entries[members[0]];
        }
        let mut left = prefix.to_vec();
        left.push(false);
        let mut right = prefix.to_vec();
        right.push(true);
        hash_node(&self.subtree(level - 1, &left), &self.subtree(level - 1, &right))
    }

    pub fn root(&self) -> Digest32 {
        self.subtree(DEPTH, &[])
    }

    /// Prove what is at `key` — present or absent.
    pub fn prove(&self, key: &Digest32) -> SmtProof {
        let mut siblings = Vec::with_capacity(DEPTH);
        let mut prefix: Vec<bool> = Vec::with_capacity(DEPTH);
        // Walk down from the root, recording the sibling subtree at each step.
        for level in (0..DEPTH).rev() {
            let going_right = Self::bit(key, level);
            let mut sib = prefix.clone();
            sib.push(!going_right);
            siblings.push(self.subtree(level, &sib));
            prefix.push(going_right);
        }
        siblings.reverse(); // bottom-up, matching verification
        SmtProof { key: *key, siblings, value: self.entries.get(key).copied() }
    }
}

/// Recompute the root from a proof. Works identically for presence and
/// absence; the difference is only what sits at the leaf.
pub fn verify(root: &Digest32, proof: &SmtProof) -> bool {
    if proof.siblings.len() != DEPTH {
        return false;
    }
    let mut node = proof.value.unwrap_or(EMPTY);
    for (level, sibling) in proof.siblings.iter().enumerate() {
        node = if SparseMerkleTree::bit(&proof.key, level) {
            hash_node(sibling, &node)
        } else {
            hash_node(&node, sibling)
        };
    }
    node == *root
}

/// Does this proof establish that `key` has *not* defaulted, against `root`?
pub fn verify_absence(root: &Digest32, proof: &SmtProof) -> bool {
    proof.proves_absence() && verify(root, proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> Digest32 {
        let mut k = [0u8; 32];
        k[0] = b;
        k[31] = b.wrapping_mul(7);
        k
    }

    #[test]
    fn an_empty_tree_proves_everyone_innocent() {
        let t = SparseMerkleTree::new();
        let root = t.root();
        for b in [0u8, 1, 200] {
            let p = t.prove(&key(b));
            assert!(p.proves_absence());
            assert!(verify_absence(&root, &p), "nobody has defaulted, so nobody is in the tree");
        }
    }

    #[test]
    fn a_defaulter_is_present_and_everyone_else_is_absent() {
        let mut t = SparseMerkleTree::new();
        t.insert(key(7));
        let root = t.root();

        let guilty = t.prove(&key(7));
        assert!(!guilty.proves_absence(), "a defaulter must not be able to prove absence");
        assert!(verify(&root, &guilty));
        assert!(!verify_absence(&root, &guilty), "presence must never pass as absence");

        for b in [1u8, 8, 99, 255] {
            let clean = t.prove(&key(b));
            assert!(verify_absence(&root, &clean), "key {b} never defaulted");
        }
    }

    #[test]
    fn recording_a_default_changes_the_root() {
        let mut t = SparseMerkleTree::new();
        let before = t.root();
        t.insert(key(3));
        let after = t.root();
        assert_ne!(before, after, "a new default must be visible in the root");

        // And an old absence proof must stop verifying against the new root —
        // otherwise a defaulter could keep using yesterday's clean bill.
        let stale = SparseMerkleTree::new().prove(&key(3));
        assert!(!verify_absence(&after, &stale));
    }

    #[test]
    fn an_absence_proof_cannot_be_moved_to_another_key() {
        let mut t = SparseMerkleTree::new();
        t.insert(key(5));
        let root = t.root();

        // Take an honest absence proof and relabel it as the defaulter's.
        let mut stolen = t.prove(&key(200));
        stolen.key = key(5);
        assert!(!verify_absence(&root, &stolen), "the key is bound into the path");
    }

    #[test]
    fn the_root_does_not_depend_on_insertion_order() {
        // Two people scanning the same chain must agree on who has defaulted.
        let a = SparseMerkleTree::from_keys([key(1), key(9), key(40)]);
        let b = SparseMerkleTree::from_keys([key(40), key(1), key(9), key(1)]);
        assert_eq!(a.root(), b.root());
        assert_eq!(a.len(), b.len(), "a repeated default is still one defaulter");
    }

    #[test]
    fn keys_sharing_long_prefixes_stay_distinct() {
        // Adjacent keys exercise the deep part of the tree, where a sloppy
        // prefix comparison would collapse two slots into one.
        let mut near_a = [0xffu8; 32];
        let mut near_b = [0xffu8; 32];
        near_b[31] = 0xfe;
        let t = SparseMerkleTree::from_keys([near_a]);
        let root = t.root();
        assert!(verify(&root, &t.prove(&near_a)));
        assert!(verify_absence(&root, &t.prove(&near_b)), "one bit apart is still a different pseudonym");
        near_a[0] = 0x7f;
        assert!(verify_absence(&root, &t.prove(&near_a)));
    }
}
