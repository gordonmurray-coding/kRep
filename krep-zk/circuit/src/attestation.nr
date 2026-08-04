//! Recomputing an attestation id from its body, inside the circuit.
//!
//! The accumulator can only hold ids — an attestation's body never goes on
//! chain. So proving anything about an attestation's *contents* means rehashing
//! the body here and checking the result against what was anchored. That is why
//! v2 ids are Poseidon2: a handful of permutations rather than a blake3
//! implementation Noir does not ship.
//!
//! Byte offsets mirror `AttestationBody::canonical_bytes` and must move with
//! it. The layout is fixed-width precisely so these can be constants.

use crate::hash;

pub global BODY_BYTES: u32 = 152;
pub global SIG_BYTES: u32 = 128; // two 64-byte schnorr signatures
pub global ID_DOMAIN_V2: Field = 0x6b7265702f61762f32; // "krep/av/2"

// Field offsets within the canonical body.
global OFF_ANCHOR_TXID: u32 = 1;
global OFF_ANCHOR_INDEX: u32 = 33;
global OFF_OWNER: u32 = 38;
global OFF_OUTCOME: u32 = 102;

global OUTCOME_SUCCESS: u8 = 0;

/// Pack up to 16 bytes big-endian into one field element, matching how the
/// Rust side chunks a byte string before absorbing it.
fn pack16<let N: u32>(bytes: [u8; N], start: u32, len: u32) -> Field {
    let mut acc: Field = 0;
    for i in 0..16 {
        if i < len {
            acc = acc * 256 + bytes[start + i] as Field;
        }
    }
    acc
}

/// The v2 attestation id: Poseidon2 over the body followed by both signatures.
///
/// Signatures are absorbed as opaque bytes. The circuit does not verify them —
/// it only needs the id to bind to them, so that matching the anchored id
/// proves this body is the one the settlement committed to.
pub fn id_v2(body: [u8; BODY_BYTES], sigs: [u8; SIG_BYTES]) -> [u8; 32] {
    let total = BODY_BYTES + SIG_BYTES;
    let chunks = (total + 15) / 16;
    let mut fields: [Field; 19] = [0; 19];
    for c in 0..chunks {
        let start = c * 16;
        let len = if start + 16 <= total { 16 } else { total - start };
        let mut acc: Field = 0;
        for i in 0..16 {
            if i < len {
                let idx = start + i;
                let byte = if idx < BODY_BYTES { body[idx] } else { sigs[idx - BODY_BYTES] };
                acc = acc * 256 + byte as Field;
            }
        }
        fields[c] = acc;
    }
    // The length is absorbed too, or a short value and a zero-padded longer
    // one would collide.
    fields[chunks] = total as Field;
    hash::sponge(ID_DOMAIN_V2, fields).to_be_bytes()
}

/// The accumulator leaf this attestation must appear as.
///
/// Everything is derived from the body: the outpoint it anchors to lives inside
/// the signed bytes, so it cannot be supplied separately and made to disagree.
pub fn anchor_leaf(body: [u8; BODY_BYTES], id: [u8; 32]) -> Field {
    // txid (32) ‖ output index little-endian (4) ‖ id (32) = 68 bytes.
    let mut leaf: [u8; 68] = [0; 68];
    for i in 0..32 {
        leaf[i] = body[OFF_ANCHOR_TXID + i];
    }
    for i in 0..4 {
        leaf[32 + i] = body[OFF_ANCHOR_INDEX + i];
    }
    for i in 0..32 {
        leaf[36 + i] = id[i];
    }
    let fields: [Field; 6] = [
        pack16(leaf, 0, 16),
        pack16(leaf, 16, 16),
        pack16(leaf, 32, 16),
        pack16(leaf, 48, 16),
        pack16(leaf, 64, 4),
        68,
    ];
    hash::hash_leaf(fields)
}

/// The pseudonym this attestation belongs to.
pub fn owner(body: [u8; BODY_BYTES]) -> [u8; 32] {
    let mut out: [u8; 32] = [0; 32];
    for i in 0..32 {
        out[i] = body[OFF_OWNER + i];
    }
    out
}

/// Was this a success? Anything else is not what "N successes" claims.
pub fn is_success(body: [u8; BODY_BYTES]) -> bool {
    body[OFF_OUTCOME] == OUTCOME_SUCCESS
}
