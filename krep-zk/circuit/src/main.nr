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
//! # How the two halves are bound together
//!
//! The danger in a proof like this is that it establishes two true things that
//! have nothing to do with each other: that *some* attestations are anchored,
//! and that *a* pseudonym is clean. A prover could otherwise pair somebody
//! else's successes with their own unblemished record.
//!
//! Everything therefore derives from one witness per attestation — its body and
//! signatures — rather than being supplied alongside it:
//!
//! - the **id** is recomputed here by rehashing body ‖ signatures, so it cannot
//!   be some other attestation's id;
//! - the **outpoint** the leaf commits to is read out of the body, where it sits
//!   inside the signed bytes, so it cannot be pointed at a different settlement;
//! - the **owner** is read out of the body and required to equal the pseudonym
//!   the absence proof is about;
//! - the **outcome** is read out of the body and required to be a success.
//!
//! The pseudonym's bits, which walk the sparse tree, are likewise derived from
//! its bytes rather than accepted as a separate input — otherwise a prover
//! could walk the tree as one identity while claiming attestations as another.

mod attestation;
mod hash;

/// Depth of the anchored-ids tree the verifier built.
global ANCHOR_DEPTH: u32 = 20;
/// One level per bit of a pseudonym.
global SMT_DEPTH: u32 = 256;
/// Successes provable in one proof.
global MAX_SUCCESSES: u32 = 4;

fn main(
    // ---- public: what the verifier independently rebuilt from the chain ----
    anchored_root: pub Field,
    defaults_root: pub Field,
    min_successes: pub u32,
    // ---- private: the prover's evidence ----
    // The pseudonym being vouched for. Never revealed.
    pseudonym: [u8; 32],
    // One attestation per slot: its canonical body and both signatures. Every
    // other fact about it is derived from these.
    bodies: [[u8; attestation::BODY_BYTES]; MAX_SUCCESSES],
    sigs: [[u8; attestation::SIG_BYTES]; MAX_SUCCESSES],
    leaf_paths: [[Field; ANCHOR_DEPTH]; MAX_SUCCESSES],
    leaf_indices: [Field; MAX_SUCCESSES],
    // How many slots are real; the rest are padding an honest prover with fewer
    // successes should not have to invent.
    used: u32,
    defaults_path: [Field; SMT_DEPTH],
) {
    assert(used >= min_successes, "fewer successes than claimed");
    assert(used <= MAX_SUCCESSES, "more successes than this circuit carries");

    // --- half one: N anchored successes, all owned by this pseudonym ---
    for i in 0..MAX_SUCCESSES {
        if (i as u32) < used {
            let body = bodies[i];

            // Recompute the id rather than trusting one. This is what ties the
            // body in hand to the id the settlement actually committed.
            let id = attestation::id_v2(body, sigs[i]);
            let leaf = attestation::anchor_leaf(body, id);
            let computed = merkle_root(leaf, leaf_paths[i], leaf_indices[i]);
            assert(computed == anchored_root, "an attestation is not in the anchored set");

            // It has to be *this* pseudonym's, or the absence proof below is
            // about someone else entirely.
            let owner = attestation::owner(body);
            for b in 0..32 {
                assert(owner[b] == pseudonym[b], "attestation belongs to another pseudonym");
            }

            // And it has to be a success. "N anchored attestations" and "N
            // successes" are not the same claim.
            assert(attestation::is_success(body), "attestation is not a success");
        }
    }

    // --- half two: this pseudonym is absent from the defaults ---
    // An empty slot hashes up from zero; recomputing the root from zero rather
    // than from a leaf value is what makes this a proof of absence.
    let bits = pseudonym_bits(pseudonym);
    let mut node: Field = 0;
    for level in 0..SMT_DEPTH {
        let sibling = defaults_path[level];
        node = if bits[level] {
            hash::hash_node(sibling, node)
        } else {
            hash::hash_node(node, sibling)
        };
    }
    assert(node == defaults_root, "this pseudonym has defaulted, or the path is wrong");
}

/// Bits of the pseudonym, ordered from the leaf upward, matching how the Rust
/// sparse tree indexes them: level 0 is the least significant bit of the last
/// byte.
fn pseudonym_bits(key: [u8; 32]) -> [bool; SMT_DEPTH] {
    let mut bits: [bool; SMT_DEPTH] = [false; SMT_DEPTH];
    for level in 0..SMT_DEPTH {
        let idx = SMT_DEPTH - 1 - level;
        let byte = key[idx / 8];
        bits[level] = ((byte >> ((7 - (idx % 8)) as u8)) & 1) == 1;
    }
    bits
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
