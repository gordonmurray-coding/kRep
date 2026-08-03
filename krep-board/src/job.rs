//! What the events carry.
//!
//! Job content is JSON because it is transport, exactly as attestation JSON is
//! transport — nothing here is signed by shape, only by the enclosing event.

use crate::event::{Event, EventError, Result};
use serde::{Deserialize, Serialize};

/// Parameterized-replaceable job posting, keyed by its `d` tag.
pub const KIND_JOB: u32 = 30402;
/// A maker's claim on a job.
pub const KIND_CLAIM: u32 = 1403;
/// A buyer designating the winning claim.
pub const KIND_ACCEPT: u32 = 1404;

/// SPEC 2.1's job bounty.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobPost {
    pub v: u8,
    pub kind: String,
    /// blake3 of the design file. The public sees this, not the design.
    pub file_hash: String,
    /// Where the *encrypted* file lives. The decryption key goes only to the
    /// accepted maker, by DM.
    pub file_ptr: String,
    pub process: String,
    pub material: String,
    pub tolerance_class: String,
    pub qty: u32,
    pub reward: u64,
    pub maker_bond: u64,
    pub deadline: u64,
    /// Coarse on purpose — continent or country. The precise address is
    /// exchanged privately after acceptance, and is the irreducible leak the
    /// spec is honest about.
    pub ship_region: String,
    /// The escrow terms hash. A maker checks the escrow they are claiming
    /// against actually matches this before bonding anything.
    pub escrow_template: String,
    /// The buyer's reputation chain head, if they publish one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buyer_rep_hint: Option<String>,
}

impl JobPost {
    pub fn to_event(&self, key: &secp256k1::Keypair, job_id: &str, created_at: u64) -> Event {
        let tags = vec![
            vec!["d".into(), job_id.into()],
            // Coarse, queryable facets so a maker can filter without fetching
            // every posting on the relay.
            vec!["process".into(), self.process.clone()],
            vec!["region".into(), self.ship_region.clone()],
            vec!["escrow".into(), self.escrow_template.clone()],
        ];
        Event::sign(key, KIND_JOB, tags, serde_json::to_string(self).expect("serializable"), created_at)
    }

    pub fn from_event(e: &Event) -> Result<(String, JobPost)> {
        if e.kind != KIND_JOB {
            return Err(EventError::Malformed(format!("kind {} is not a job posting", e.kind)));
        }
        let id = e.tag("d").ok_or_else(|| EventError::Malformed("job posting has no d tag".into()))?;
        let post: JobPost =
            serde_json::from_str(&e.content).map_err(|err| EventError::Malformed(format!("job content: {err}")))?;
        Ok((id.to_string(), post))
    }
}

/// A maker's claim: their reputation, and proof they have funded the bond.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claim {
    pub v: u8,
    /// Head of the maker's kRep chain — what a buyer scores them on.
    pub rep_head: String,
    /// The maker's reputation pseudonym. The escrow will bind this, and it is
    /// the identity any default lands on.
    pub rep_pubkey: String,
    /// Payment key the escrow should pay on settlement.
    pub payment_pubkey: String,
    /// Transaction that funded the bond, so a buyer can check it exists rather
    /// than take the claim's word for it.
    pub bond_txid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl Claim {
    pub fn to_event(&self, key: &secp256k1::Keypair, job_addr: &str, created_at: u64) -> Event {
        // An `a` tag addresses a parameterized-replaceable event, so the claim
        // points at the job rather than at one particular revision of it.
        let tags = vec![vec!["a".into(), job_addr.into()]];
        Event::sign(key, KIND_CLAIM, tags, serde_json::to_string(self).expect("serializable"), created_at)
    }

    pub fn from_event(e: &Event) -> Result<(String, Claim)> {
        if e.kind != KIND_CLAIM {
            return Err(EventError::Malformed(format!("kind {} is not a claim", e.kind)));
        }
        let job = e.tag("a").ok_or_else(|| EventError::Malformed("claim has no a tag".into()))?;
        let claim: Claim =
            serde_json::from_str(&e.content).map_err(|err| EventError::Malformed(format!("claim content: {err}")))?;
        Ok((job.to_string(), claim))
    }
}

/// The buyer designating a winner, and telling them where to bond.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Acceptance {
    pub v: u8,
    /// Event id of the winning claim.
    pub claim_id: String,
    /// The funded escrow address the maker should claim against.
    pub escrow_address: String,
    /// Outpoint holding the opened escrow, so the maker can go straight to it.
    pub escrow_outpoint: String,
}

impl Acceptance {
    pub fn to_event(&self, key: &secp256k1::Keypair, job_addr: &str, created_at: u64) -> Event {
        let tags = vec![
            vec!["a".into(), job_addr.into()],
            vec!["e".into(), self.claim_id.clone()],
        ];
        Event::sign(key, KIND_ACCEPT, tags, serde_json::to_string(self).expect("serializable"), created_at)
    }

    pub fn from_event(e: &Event) -> Result<Acceptance> {
        if e.kind != KIND_ACCEPT {
            return Err(EventError::Malformed(format!("kind {} is not an acceptance", e.kind)));
        }
        serde_json::from_str(&e.content).map_err(|err| EventError::Malformed(format!("acceptance content: {err}")))
    }
}

/// NIP-01 address of a parameterized-replaceable event: `kind:pubkey:d`.
pub fn job_address(author: &secp256k1::XOnlyPublicKey, job_id: &str) -> String {
    format!("{KIND_JOB}:{}:{job_id}", hex::encode(author.serialize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, Secp256k1};

    fn key(b: u8) -> Keypair {
        Keypair::from_seckey_slice(&Secp256k1::new(), &[b; 32]).unwrap()
    }

    fn post() -> JobPost {
        JobPost {
            v: 1,
            kind: "fab_job".into(),
            file_hash: hex::encode([7u8; 32]),
            file_ptr: "https://blossom.example/abc".into(),
            process: "fdm".into(),
            material: "petg".into(),
            tolerance_class: "standard".into(),
            qty: 2,
            reward: 100_000_000,
            maker_bond: 50_000_000,
            deadline: 1_800_000_000,
            ship_region: "EU".into(),
            escrow_template: hex::encode([3u8; 32]),
            buyer_rep_hint: Some(hex::encode([1u8; 32])),
        }
    }

    #[test]
    fn a_job_round_trips_through_an_event() {
        let buyer = key(1);
        let e = post().to_event(&buyer, "job-42", 1_700_000_000);
        e.verify().unwrap();
        let (id, back) = JobPost::from_event(&e).unwrap();
        assert_eq!(id, "job-42");
        assert_eq!(back, post());
        // Facets are exposed as tags so relays can filter without parsing content.
        assert_eq!(e.tag("process"), Some("fdm"));
        assert_eq!(e.tag("region"), Some("EU"));
        assert_eq!(e.tag("escrow"), Some(post().escrow_template.as_str()));
    }

    #[test]
    fn the_design_itself_is_never_in_the_posting() {
        // Only a hash and an encrypted pointer are public; the decryption key
        // goes to the accepted maker alone.
        let e = post().to_event(&key(1), "job-42", 1);
        assert!(e.content.contains(&hex::encode([7u8; 32])), "hash is public");
        assert!(!e.content.contains("BEGIN"), "no key material in a posting");
    }

    #[test]
    fn claims_and_acceptances_bind_to_the_job_they_answer() {
        let buyer = key(1);
        let maker = key(2);
        let addr = job_address(&buyer.x_only_public_key().0, "job-42");

        let claim = Claim {
            v: 1,
            rep_head: hex::encode([9u8; 32]),
            rep_pubkey: hex::encode(key(3).x_only_public_key().0.serialize()),
            payment_pubkey: hex::encode(maker.x_only_public_key().0.serialize()),
            bond_txid: hex::encode([4u8; 32]),
            note: None,
        };
        let ce = claim.to_event(&maker, &addr, 2);
        ce.verify().unwrap();
        let (job, back) = Claim::from_event(&ce).unwrap();
        assert_eq!(job, addr, "a claim must say which job it answers");
        assert_eq!(back, claim);

        let accept = Acceptance {
            v: 1,
            claim_id: ce.id.clone(),
            escrow_address: "kaspatest:qq".into(),
            escrow_outpoint: format!("{}:0", hex::encode([5u8; 32])),
        };
        let ae = accept.to_event(&buyer, &addr, 3);
        ae.verify().unwrap();
        assert_eq!(ae.tag("a"), Some(addr.as_str()));
        assert_eq!(ae.tag("e"), Some(ce.id.as_str()), "acceptance names the winning claim");
        assert_eq!(Acceptance::from_event(&ae).unwrap(), accept);
    }

    #[test]
    fn kinds_are_not_interchangeable() {
        let e = post().to_event(&key(1), "j", 1);
        assert!(Claim::from_event(&e).is_err());
        assert!(Acceptance::from_event(&e).is_err());
    }

    #[test]
    fn a_job_address_identifies_the_posting_not_a_revision() {
        // Editing a job replaces it under the same address, so claims made
        // against the address stay attached across edits.
        let buyer = key(1);
        let a = post().to_event(&buyer, "job-42", 10);
        let mut edited = post();
        edited.reward += 1;
        let b = edited.to_event(&buyer, "job-42", 20);
        assert_ne!(a.id, b.id, "different revisions are different events");
        assert_eq!(a.tag("d"), b.tag("d"), "but the same job");
        assert_eq!(job_address(&buyer.x_only_public_key().0, "job-42"), format!("{KIND_JOB}:{}:job-42", a.pubkey));
    }
}
