//! Poseidon2 over BN254 — the hash shared by attestation ids and the M6
//! accumulators.
//!
//! # Why this one
//!
//! Poseidon2 is arithmetic in the proof system's own field, so a Merkle path
//! costs tens of constraints per level rather than the thousands a bit-oriented
//! hash like SHA-256 would.
//!
//! The harder requirement is that Rust and Noir agree *exactly*. The verifier
//! rebuilds the accumulator root from chain data in Rust; the circuit
//! recomputes paths in Noir. One differing round constant and the roots differ
//! and every proof fails. Poseidon2 is a family, not a function, so this uses
//! Noir's own `bn254_blackbox_solver` — pinned to the same version as the
//! installed nargo — rather than a reimplementation whose parameters would have
//! to be guessed. `tests/poseidon2_matches_noir.rs` checks it against output
//! captured from the real compiler.
//!
//! # Bytes do not fit in the field
//!
//! BN254 scalars are 254 bits; an attestation id is 256. Reducing an id modulo
//! the field order is not injective — roughly four fifths of the id space wraps
//! — so every 32-byte value is split into two 128-bit limbs instead, which
//! always fit and always round trip.
//!
//! # Construction
//!
//! The stdlib exposes only the permutation, so the sponge is defined here and
//! the circuit must mirror it: capacity holds a domain tag, inputs are absorbed
//! into the rate three at a time, and the first state element is squeezed out.
//! Leaves and nodes use different tags, so an internal node's preimage can
//! never be presented as a leaf.

use acir_field::{AcirField, FieldElement};
use bn254_blackbox_solver::poseidon2_permutation;

/// A BN254 scalar — what both the accumulator and the circuit operate on.
pub type Field = FieldElement;

/// A 32-byte value as it appears on chain: an attestation id, a pubkey, a txid.
/// Distinct from [`Field`] on purpose — these do not fit in one scalar, and
/// conflating them is how the wrap-around bug gets in.
pub type Digest32 = [u8; 32];

/// Poseidon2's state width, as the backend reports it.
pub const WIDTH: usize = 4;
/// Elements absorbed per permutation; the remaining slot is capacity.
pub const RATE: usize = WIDTH - 1;

const IV_LEAF: u128 = 1;
const IV_NODE: u128 = 2;

pub fn zero() -> Field {
    Field::from(0u128)
}

/// Split a 32-byte value into two field elements that always fit.
pub fn limbs(bytes: &[u8; 32]) -> [Field; 2] {
    let mut hi = [0u8; 16];
    let mut lo = [0u8; 16];
    hi.copy_from_slice(&bytes[..16]);
    lo.copy_from_slice(&bytes[16..]);
    [Field::from(u128::from_be_bytes(hi)), Field::from(u128::from_be_bytes(lo))]
}

/// Absorb `inputs` under a domain tag and squeeze one element.
fn sponge(iv: u128, inputs: &[Field]) -> Field {
    let mut state = [zero(), zero(), zero(), Field::from(iv)];
    for chunk in inputs.chunks(RATE) {
        for (slot, x) in chunk.iter().enumerate() {
            state[slot] += *x;
        }
        let out = poseidon2_permutation(&state).expect("fixed-width permutation");
        state.copy_from_slice(&out[..WIDTH]);
    }
    state[0]
}

/// Hash a leaf's field encoding.
pub fn hash_leaf_fields(fields: &[Field]) -> Field {
    sponge(IV_LEAF, fields)
}

/// Hash a leaf given as bytes, by splitting it into limbs.
pub fn hash_leaf(value: &[u8]) -> Field {
    let mut fields = Vec::with_capacity(value.len().div_ceil(16));
    for chunk in value.chunks(16) {
        let mut buf = [0u8; 16];
        buf[16 - chunk.len()..].copy_from_slice(chunk);
        fields.push(Field::from(u128::from_be_bytes(buf)));
    }
    // Length is absorbed so that two different values cannot pad to the same
    // field sequence.
    fields.push(Field::from(value.len() as u128));
    hash_leaf_fields(&fields)
}

pub fn hash_node(left: &Field, right: &Field) -> Field {
    sponge(IV_NODE, &[*left, *right])
}

/// Hash arbitrary bytes under a domain tag and serialize to 32 bytes.
///
/// Bytes are split into 16-byte limbs so every chunk fits the field, and the
/// length is absorbed so a short value and a zero-padded longer one cannot
/// collide. The output is a field element rendered big-endian — it always fits
/// in 32 bytes, with the top two bits clear.
pub fn hash_tagged_bytes(tag: u128, value: &[u8]) -> [u8; 32] {
    let mut fields = Vec::with_capacity(value.len().div_ceil(16) + 1);
    for chunk in value.chunks(16) {
        let mut buf = [0u8; 16];
        buf[16 - chunk.len()..].copy_from_slice(chunk);
        fields.push(Field::from(u128::from_be_bytes(buf)));
    }
    fields.push(Field::from(value.len() as u128));
    to_be_32(&sponge(tag, &fields))
}

/// A field element as 32 big-endian bytes, left-padded.
///
/// The backend returns the minimal representation, so a small element comes
/// back short. Anything comparing a field to a fixed-width value — an
/// attestation id, a proof's public inputs — needs the padded form, and doing
/// the padding at each call site is how the two disagree.
pub fn to_be_32(f: &Field) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let be = f.to_be_bytes();
    let n = be.len().min(32);
    bytes[32 - n..].copy_from_slice(&be[be.len() - n..]);
    bytes
}

/// Hex rendering, for fixtures and diagnostics.
pub fn to_hex(f: &Field) -> String {
    format!("0x{}", f.to_hex())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaves_and_nodes_live_in_separate_domains() {
        // Without distinct tags an internal node's preimage could be presented
        // as a leaf and prove membership of something never inserted.
        let a = Field::from(1u128);
        let b = Field::from(2u128);
        assert_ne!(hash_leaf_fields(&[a, b]), hash_node(&a, &b));
    }

    #[test]
    fn hashing_is_order_sensitive() {
        let a = Field::from(1u128);
        let b = Field::from(2u128);
        assert_ne!(hash_node(&a, &b), hash_node(&b, &a), "a sibling's side must matter");
    }

    #[test]
    fn limbs_always_fit_and_round_trip() {
        // The whole reason for splitting: an id larger than the field order
        // must not silently wrap onto another id's value.
        let max = [0xffu8; 32];
        let [hi, lo] = limbs(&max);
        assert_eq!(hi, Field::from(u128::MAX));
        assert_eq!(lo, Field::from(u128::MAX));

        // Two ids differing only above the field order stay distinct.
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[0] = 0x30;
        b[0] = 0x40;
        assert_ne!(limbs(&a), limbs(&b));
        assert_ne!(hash_leaf(&a), hash_leaf(&b));
    }

    #[test]
    fn length_is_bound_into_a_leaf() {
        // Otherwise a short value and a zero-padded longer one could collide.
        assert_ne!(hash_leaf(&[1u8]), hash_leaf(&[0u8, 1u8]));
        assert_ne!(hash_leaf(&[]), hash_leaf(&[0u8]));
    }
}
