//! kRep M6 — accumulators for selective disclosure.
//!
//! SPEC 1.5 wants to prove *"this fresh key controls a chain with ≥N successes
//! and 0 defaults"* without revealing which chain. It proposes doing that
//! against "a global Merkle root of all anchored attestations (maintained by
//! anyone — it's reproducible from chain data)".
//!
//! That is not quite reproducible. What Kaspa carries is the 32-byte
//! attestation *id*; the body — outcome, role, counterparty, owner — never goes
//! on chain, which is the `amount_bucket`-not-amounts privacy decision working
//! as designed. A third party can rebuild the set of anchored ids and nothing
//! more, so a root over attestation *contents* cannot be rebuilt by the person
//! checking the proof.
//!
//! So the statement splits across two accumulators, both genuinely rebuildable
//! from chain data:
//!
//! - [`merkle`] — anchored attestation ids. Membership proves an attestation
//!   really was committed by a settlement. The prover supplies the bodies
//!   privately and the circuit checks each id against this root.
//! - [`smt`] — pseudonyms recorded as having defaulted. **Non**-membership
//!   proves the prover is not among them.
//!
//! # Why the second one is necessary
//!
//! "≥N successes" needs only membership. "0 defaults" needs to prove an
//! absence, and a chain alone cannot: a prover can always present a prefix and
//! withhold the tail. Omitting an entry *within* a range breaks the `prev`
//! links and is caught, but truncating after the last success is invisible.
//!
//! Scanning the chain for slashes naming a pseudonym would settle it — and
//! would also reveal the pseudonym, destroying the unlinkability the proof
//! exists for. A sparse Merkle tree over defaulted pseudonyms gives the same
//! answer without naming anyone.
//!
//! M2 is what makes this buildable: the escrow covenant records *which
//! pseudonym* defaulted, on chain, at a known offset, without that pseudonym's
//! cooperation.

pub mod hash;
pub mod merkle;
pub mod scan;
pub mod smt;

pub use hash::{Digest32, Field};
pub use merkle::{MerkleProof, MerkleTree};
pub use smt::{SparseMerkleTree, SmtProof};
