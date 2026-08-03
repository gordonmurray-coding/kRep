//! FabMesh job board — kRep M3.
//!
//! A job board with no operator: postings, claims and acceptances are Nostr
//! events on public relays. There is no server of record to enjoin and nobody
//! to subpoena, and anyone can run a relay. What makes that safe is that none
//! of it is trusted — a relay can drop or reorder events, but it cannot forge
//! one, and every claim that matters is backed by something on Kaspa: a bond
//! transaction, an escrow address, an anchored reputation chain.
//!
//! # Event kinds
//!
//! SPEC 2.2 leaves the kinds "TBD". These are the choices:
//!
//! | kind | meaning | replaceable |
//! |---|---|---|
//! | 30402 | job posting | yes, per `d` tag |
//! | 1403 | claim on a job | no |
//! | 1404 | acceptance of a claim | no |
//!
//! 30402 sits in the parameterized-replaceable range, so a buyer editing a job
//! replaces their earlier version rather than littering the relay, and the `d`
//! tag is the job's stable identifier. Claims and acceptances are ordinary
//! events because their whole purpose is to be an immutable record of who said
//! what, when — a replaceable claim could be rewritten after acceptance.

pub mod event;
pub mod job;
pub mod relay;

pub use event::{Event, EventError};
pub use job::{Acceptance, Claim, JobPost, KIND_ACCEPT, KIND_CLAIM, KIND_JOB};
