//! Poseidon2 sponge, mirroring `krep-zk/src/hash.rs` exactly.
//!
//! The Rust side builds the accumulator roots from chain data; this side
//! recomputes paths against them. Any divergence — a different domain tag, a
//! different absorb order — makes every proof fail, so these two files are one
//! specification written twice and must be changed together.

global WIDTH: u32 = 4;
global RATE: u32 = 3;
global IV_LEAF: Field = 1;
global IV_NODE: Field = 2;

/// Absorb `inputs` under a domain tag and squeeze one element.
///
/// `inputs` is padded to a multiple of RATE by the caller's array size, which
/// is safe here because every call site has a fixed shape.
pub fn sponge<let N: u32>(iv: Field, inputs: [Field; N]) -> Field {
    let mut state: [Field; WIDTH] = [0, 0, 0, iv];
    let chunks = (N + RATE - 1) / RATE;
    for c in 0..chunks {
        for i in 0..RATE {
            let idx = c * RATE + i;
            if idx < N {
                state[i] = state[i] + inputs[idx];
            }
        }
        state = std::hash::poseidon2_permutation(state);
    }
    state[0]
}

pub fn hash_leaf<let N: u32>(fields: [Field; N]) -> Field {
    sponge(IV_LEAF, fields)
}

pub fn hash_node(left: Field, right: Field) -> Field {
    sponge(IV_NODE, [left, right])
}
