//! The hash the accumulators are built on.
//!
//! # Choosing it
//!
//! This is SHA-256, which Noir supports natively and which the project already
//! uses for Nostr event ids. It is a placeholder in one specific sense: SHA-256
//! is expensive inside a circuit — thousands of constraints per compression —
//! so a production circuit proving membership across a 30-deep Merkle path will
//! want a ZK-friendly hash such as Poseidon instead.
//!
//! That swap has to happen in *both* places at once. The accumulator a verifier
//! rebuilds from chain data and the hash the circuit computes must agree
//! exactly, or every proof fails. Hence the indirection: everything below goes
//! through [`hash_leaf`] and [`hash_node`], and changing the primitive is a
//! change to this file only.
//!
//! Leaves and internal nodes are domain-separated. Without that, an internal
//! node's preimage could be presented as a leaf, letting a prover claim
//! membership for a value that was never inserted.

use sha2::{Digest, Sha256};

pub type Digest32 = [u8; 32];

const LEAF_TAG: u8 = 0x00;
const NODE_TAG: u8 = 0x01;

pub fn hash_leaf(value: &[u8]) -> Digest32 {
    let mut h = Sha256::new();
    h.update([LEAF_TAG]);
    h.update(value);
    h.finalize().into()
}

pub fn hash_node(left: &Digest32, right: &Digest32) -> Digest32 {
    let mut h = Sha256::new();
    h.update([NODE_TAG]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaves_and_nodes_live_in_separate_domains() {
        // If these collided, an attacker could present the preimage of an
        // internal node as though it were a leaf and prove membership of
        // something never inserted.
        let a = [1u8; 32];
        let b = [2u8; 32];
        let mut concat = Vec::new();
        concat.extend_from_slice(&a);
        concat.extend_from_slice(&b);
        assert_ne!(hash_leaf(&concat), hash_node(&a, &b));
    }

    #[test]
    fn hashing_is_order_sensitive() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_ne!(hash_node(&a, &b), hash_node(&b, &a), "a sibling's side must matter");
    }
}
