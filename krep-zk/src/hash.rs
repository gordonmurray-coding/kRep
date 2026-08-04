//! Re-export of the shared Poseidon2 sponge.
//!
//! This lives in `krep-core` because attestation ids use it too. Keeping one
//! copy is not tidiness: a circuit recomputing an attestation id from its body
//! must absorb it exactly as the id function did, and two implementations would
//! drift.

pub use krep_core::field::*;
