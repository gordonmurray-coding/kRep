//! The hash the accumulators are built on.
//!
//! # Choosing it
//!
//! This is SHA-256, and it is provisional. SHA-256 is expensive inside a
//! circuit, so a proof walking a deep Merkle path wants a ZK-friendly hash.
//!
//! Two things have to be true of whatever replaces it, and they constrain the
//! choice more than "which hash is cheapest" does.
//!
//! **Rust and Noir must compute it identically.** The verifier rebuilds the
//! root from chain data in Rust; the circuit recomputes paths in Noir. If the
//! two disagree by so much as a round constant, every proof fails. Reference
//! vectors captured from the real toolchain live in
//! `tests/noir_hash.vectors.json` — a candidate implementation is only usable
//! if it reproduces them.
//!
//! **The value type changes with it.** Poseidon and Pedersen operate on BN254
//! field elements, not bytes, and the field is 254 bits while an attestation id
//! is 256. Ids do not fit. Reducing them modulo the field order is not
//! injective — roughly four fifths of the id space wraps — so the encoding must
//! split each id into two 128-bit limbs instead. That changes the leaf and node
//! types throughout the accumulator, so switching is *not* a change confined to
//! this file, contrary to what an earlier version of this comment claimed.
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
