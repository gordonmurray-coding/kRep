//! kRep selective disclosure — SPEC 1.5.
//!
//! Proves, without revealing which chain: *"the pseudonym I control appears as
//! the owner of at least `min_successes` anchored attestations, and does not
//! appear among the pseudonyms recorded as having defaulted."*
//!
//! Two accumulators, because the claim has two halves that need different
//! machinery:
//!
//! - **anchored ids** — a Merkle tree over `(spent outpoint, id)` pairs
//!   derived from settled transactions. Membership proves a success really was
//!   anchored, and so really cost its author fees and locked capital.
//! - **defaulted pseudonyms** — a sparse Merkle tree keyed by pseudonym.
//!   *Non*-membership proves the prover is not on it.
//!
//! The second is not decoration. "≥N successes" needs only membership; "0
//! defaults" is an absence claim, and a chain alone cannot establish one —
//! omitting an entry mid-chain breaks its `prev` links and is caught, but
//! truncating after the last success is invisible. Scanning the chain for
//! slashes against a pseudonym would settle it and would also name the
//! pseudonym, destroying the unlinkability this proof exists for.
//!
//! Both roots are public inputs, and both are rebuildable from chain data by
//! anyone with a node, so the prover does not get to choose them.
//!
//! # Known gap: the two halves are not yet bound together
//!
//! As written, this proves that *some* attestations are anchored and that *a*
//! pseudonym has not defaulted — but nothing forces those attestations to be
//! owned by that pseudonym. A prover could pair somebody else's anchored
//! successes with their own clean pseudonym.
//!
//! Closing it means proving `owner == pseudonym` for each attestation, which
//! means recomputing the attestation id from its body inside the circuit, since
//! the id is all the accumulator can hold — the body never goes on chain. The
//! id is `blake3(body ‖ signatures)`, and blake3 is neither in Noir's stdlib
//! nor cheap in a circuit.
//!
//! Three ways out, none of them free:
//!
//! 1. Bring blake3 into the circuit from an external Noir library. No format
//!    change, but expensive, and every attestation body must be a witness.
//! 2. Give attestations a second, circuit-friendly id (Poseidon2 over the same
//!    body) and anchor both. Costs 32 more payload bytes per attestation and a
//!    domain-tag bump, but keeps the constraint count low.
//! 3. Re-key attestation ids to Poseidon2 outright. Cheapest in-circuit,
//!    invalidates every chain anchored so far.
//!
//! This is a design decision about kRep's attestation format, not a circuit
//! problem, so it is flagged rather than guessed at — the same way SPEC 1.5
//! flagged the unilateral-default problem that M2 went on to solve.

mod hash;

/// Depth of the anchored-ids tree the verifier built.
global ANCHOR_DEPTH: u32 = 20;
/// One level per bit of a pseudonym.
global SMT_DEPTH: u32 = 256;
/// Successes provable in one proof.
global MAX_SUCCESSES: u32 = 4;
/// Field elements a single anchor leaf encodes to: outpoint txid (2 limbs),
/// output index, id (2 limbs), and the byte length the Rust side absorbs.
global LEAF_FIELDS: u32 = 6;

fn main(
    // ---- public: what the verifier independently rebuilt from the chain ----
    anchored_root: pub Field,
    defaults_root: pub Field,
    min_successes: pub u32,
    // ---- private: the prover's evidence ----
    // Each success, encoded exactly as the Rust accumulator encodes its leaf.
    leaves: [[Field; LEAF_FIELDS]; MAX_SUCCESSES],
    leaf_paths: [[Field; ANCHOR_DEPTH]; MAX_SUCCESSES],
    leaf_indices: [Field; MAX_SUCCESSES],
    // How many of the slots above are real; the rest are ignored padding.
    used: u32,
    // The pseudonym, as the two 128-bit limbs the Rust side splits it into,
    // plus its bit decomposition for walking the sparse tree.
    pseudonym_bits: [bool; SMT_DEPTH],
    defaults_path: [Field; SMT_DEPTH],
) {
    assert(used >= min_successes, "fewer successes than claimed");
    assert(used <= MAX_SUCCESSES, "more successes than this circuit carries");

    // --- half one: every claimed success is genuinely anchored ---
    for i in 0..MAX_SUCCESSES {
        // Padding slots are skipped rather than checked, so an honest prover
        // with fewer than MAX_SUCCESSES successes is not forced to invent any.
        if (i as u32) < used {
            let leaf = hash::hash_leaf(leaves[i]);
            let computed = merkle_root(leaf, leaf_paths[i], leaf_indices[i]);
            assert(computed == anchored_root, "an attestation is not in the anchored set");
        }
    }

    // --- half two: the prover is absent from the defaults ---
    // An empty slot hashes from zero. Recomputing the root from *zero* rather
    // than from a leaf value is exactly what makes this a proof of absence.
    let mut node: Field = 0;
    for level in 0..SMT_DEPTH {
        let sibling = defaults_path[level];
        // Bit `level` counted from the leaf decides which side we sit on.
        node = if pseudonym_bits[level] {
            hash::hash_node(sibling, node)
        } else {
            hash::hash_node(node, sibling)
        };
    }
    assert(node == defaults_root, "this pseudonym has defaulted, or the path is wrong");
}

/// Walk a Merkle path. `index` is the leaf's position, whose low bits decide
/// which side each sibling goes on.
fn merkle_root(leaf: Field, path: [Field; ANCHOR_DEPTH], index: Field) -> Field {
    let bits: [bool; ANCHOR_DEPTH] = index.to_le_bits();
    let mut node = leaf;
    for level in 0..ANCHOR_DEPTH {
        node = if bits[level] {
            hash::hash_node(path[level], node)
        } else {
            hash::hash_node(node, path[level])
        };
    }
    node
}
