//! Does the Rust side compute the same Poseidon2 as the circuit will?
//!
//! This is the question that decides whether M6 can use Poseidon2 at all. The
//! verifier rebuilds the accumulator root in Rust; the circuit recomputes paths
//! in Noir. If they disagree anywhere — one round constant, one MDS entry — the
//! roots differ and every proof fails, silently and unfixably.
//!
//! The vectors were produced by executing a Noir program under the installed
//! nargo and printing what it computed. They are not derived from a spec, a
//! paper, or this crate's own documentation.

use acir_field::{AcirField, FieldElement};
use bn254_blackbox_solver::{poseidon2_config_state_size, poseidon2_permutation};

fn field(dec: &str) -> FieldElement {
    FieldElement::try_from_str(dec).expect("decimal field element")
}

fn hex_of(f: &FieldElement) -> String {
    format!("0x{}", f.to_hex().trim_start_matches('0'))
}

#[test]
fn state_size_matches_what_noir_demanded() {
    // Noir refused a 3-element input with "expected 4, got 3".
    assert_eq!(poseidon2_config_state_size(), 4);
}

#[test]
fn poseidon2_reproduces_the_vectors_noir_printed() {
    let cases: [([&str; 4], &str); 2] = [
        (["0", "0", "0", "0"], "0x18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e"),
        (["1", "2", "3", "4"], "0x224785a48a72c75e2cbb698143e71d5d41bd89a2b9a7185871e39a54ce5785b1"),
    ];
    for (input, expected_first) in cases {
        let state: Vec<FieldElement> = input.iter().map(|d| field(d)).collect();
        let out = poseidon2_permutation(&state).expect("permutation runs");
        assert_eq!(out.len(), 4);
        assert_eq!(
            hex_of(&out[0]),
            *expected_first,
            "Rust and Noir disagree on poseidon2_permutation({input:?}) — Poseidon2 is unusable if so"
        );
    }
}
