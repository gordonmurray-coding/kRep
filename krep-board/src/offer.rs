//! Seller-side listings: what somebody offers, and the record standing behind it.
//!
//! M3 built the demand side — a buyer posts a job and makers compete for it.
//! That only works if discovery starts with someone who already knows what they
//! want and has funded an escrow for it. An offer is the other direction: a
//! seller says what they can make, and a buyer browses.
//!
//! # The record travels with the offer
//!
//! An offer carries the seller's whole reputation chain rather than a pointer to
//! it. Two reasons, and the second is the important one.
//!
//! A browser rendering twenty listings cannot make twenty extra round trips, and
//! a chain is small — a few hundred bytes per entry. But mainly: a pointer would
//! have to be resolved *by somebody*, and whoever resolves it is a party you are
//! now trusting. Shipping the chain inside the signed event means the reader
//! verifies the same bytes the seller signed, against their own accumulator, with
//! nobody in between.
//!
//! # Why an offer cannot advertise a stranger's record
//!
//! In kRep a pseudonym is also its Nostr identity, so the event's signature is
//! made by the very key the chain belongs to. `from_event` requires the embedded
//! chain's owner to equal the event's author and rejects the offer otherwise.
//!
//! Without that check the listing would be worthless: anyone could copy a
//! reputable trader's chain into their own listing and inherit their standing.
//! It is the same failure the selective-disclosure circuit guards against — two
//! true things, bound to nobody in particular — and it needs closing here too,
//! because a buyer reading a marketplace is exactly the person who would not
//! notice.

use crate::event::{Event, EventError, Result};
use krep_core::chain::Chain;
use serde::{Deserialize, Serialize};

/// Parameterized-replaceable seller listing, keyed by its `d` tag.
///
/// Not NIP-99's 30402: this codebase already spends that on job postings, and
/// two incompatible shapes sharing a kind means a reader silently drops whichever
/// one it cannot parse. Not NIP-15's 30018 either, whose product schema means
/// something else. A distinct kind is the honest option, and it is provisional.
pub const KIND_OFFER: u32 = 30405;

/// What a seller advertises. Terms here are indicative — the money is only ever
/// governed by an escrow, which is agreed afterwards and commits to its own
/// copy of everything that matters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Offer {
    pub v: u8,
    /// One line: what this is.
    pub title: String,
    /// A paragraph at most. Buyers scan.
    pub summary: String,
    /// Coarse and queryable, so a relay can filter without shipping everything.
    pub process: String,
    pub materials: Vec<String>,
    /// Continent or country. Never an address — that is exchanged privately
    /// after both sides have committed, and stays the spec's honest leak.
    pub region: String,
    /// Indicative floor, in sompi. What the escrow says is what binds.
    pub from_price: u64,
    pub lead_days: u32,
    /// The seller's record. Its owner must be the event's author.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rep_chain: Option<Chain>,
}

impl Offer {
    pub fn to_event(&self, key: &secp256k1::Keypair, offer_id: &str, created_at: u64) -> Event {
        let tags = vec![
            vec!["d".into(), offer_id.into()],
            vec!["process".into(), self.process.clone()],
            vec!["region".into(), self.region.clone()],
        ];
        Event::sign(
            key,
            KIND_OFFER,
            tags,
            serde_json::to_string(self).expect("serializable"),
            created_at,
        )
    }

    /// Parse and bind. Returns the offer id and the offer.
    pub fn from_event(e: &Event) -> Result<(String, Offer)> {
        if e.kind != KIND_OFFER {
            return Err(EventError::Malformed(format!("kind {} is not an offer", e.kind)));
        }
        let id = e.tag("d").ok_or_else(|| EventError::Malformed("offer has no d tag".into()))?;
        let offer: Offer = serde_json::from_str(&e.content)
            .map_err(|err| EventError::Malformed(format!("offer content: {err}")))?;

        // The binding. An offer signed by one pseudonym may not advertise
        // another's record, or reputation would be transferable by copy-paste.
        if let Some(chain) = &offer.rep_chain {
            let owner = hex::encode(chain.owner.serialize());
            if owner != e.pubkey {
                return Err(EventError::Malformed(format!(
                    "offer is signed by {} but advertises a record owned by {owner} — \
                     a listing cannot borrow somebody else's reputation",
                    e.pubkey
                )));
            }
        }
        if offer.title.trim().is_empty() {
            return Err(EventError::Malformed("offer has no title".into()));
        }
        Ok((id.to_string(), offer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use krep_core::{
        countersign, create_partial, derive_context_keypair, AttestationBody, Outcome, Outpoint, Role,
    };
    use secp256k1::Keypair;

    fn kp(tag: &str) -> Keypair {
        let mut seed = [0u8; 32];
        seed[..tag.len()].copy_from_slice(tag.as_bytes());
        derive_context_keypair(&seed, "offer-test")
    }

    fn chain_of(owner: &Keypair, cp: &Keypair) -> Chain {
        let body = AttestationBody {
            v: 2,
            anchor: Outpoint { txid: [0x21; 32], index: 0 },
            role: Role::Provider,
            owner: owner.x_only_public_key().0,
            counterparty: cp.x_only_public_key().0,
            outcome: Outcome::Success,
            amount_bucket: 2,
            prev: None,
            index: 0,
            ts: 1_785_000_000,
        };
        let mut c = Chain::new(owner.x_only_public_key().0);
        c.append(countersign(cp, create_partial(owner, body).unwrap()).unwrap()).unwrap();
        c
    }

    fn offer_of(chain: Option<Chain>) -> Offer {
        Offer {
            v: 1,
            title: "FDM printing, PLA and PETG".into(),
            summary: "Small mechanical parts, 0.2mm layers.".into(),
            process: "fdm".into(),
            materials: vec!["PLA".into(), "PETG".into()],
            region: "EU".into(),
            from_price: 50_000_000,
            lead_days: 3,
            rep_chain: chain,
        }
    }

    #[test]
    fn an_offer_round_trips_through_an_event() {
        let seller = kp("seller");
        let o = offer_of(Some(chain_of(&seller, &kp("buyer"))));
        let e = o.to_event(&seller, "offer-1", 1_785_000_000);
        assert!(e.verify().is_ok());
        let (id, back) = Offer::from_event(&e).unwrap();
        assert_eq!(id, "offer-1");
        assert_eq!(back, o);
    }

    #[test]
    fn an_offer_cannot_advertise_somebody_elses_record() {
        // The whole point of a marketplace listing is the record beside it. If a
        // seller could paste a reputable stranger's chain into their own
        // listing, every score on the page would mean nothing.
        let (me, reputable) = (kp("nobody"), kp("reputable"));
        let theirs = chain_of(&reputable, &kp("buyer"));
        let e = offer_of(Some(theirs)).to_event(&me, "offer-2", 1_785_000_000);
        // The event itself is perfectly valid — this is not a forgery.
        assert!(e.verify().is_ok());
        let err = Offer::from_event(&e).unwrap_err().to_string();
        assert!(err.contains("cannot borrow somebody else"), "{err}");
    }

    #[test]
    fn an_offer_may_carry_no_record_at_all() {
        // A seller with no history should be able to list. They simply show up
        // with nothing, which is a true and useful thing for a buyer to see.
        let seller = kp("newcomer");
        let e = offer_of(None).to_event(&seller, "offer-3", 1_785_000_000);
        let (_, back) = Offer::from_event(&e).unwrap();
        assert!(back.rep_chain.is_none());
    }

    #[test]
    fn a_job_posting_is_not_an_offer() {
        // The two kinds exist separately so neither is silently dropped by a
        // reader expecting the other.
        let e = Event::sign(&kp("x"), crate::job::KIND_JOB, vec![], "{}".into(), 1);
        assert!(Offer::from_event(&e).unwrap_err().to_string().contains("is not an offer"));
    }

    #[test]
    fn tags_let_a_relay_filter_without_shipping_everything() {
        let e = offer_of(None).to_event(&kp("seller"), "offer-4", 1);
        assert_eq!(e.tag("process"), Some("fdm"));
        assert_eq!(e.tag("region"), Some("EU"));
        assert_eq!(e.tag("d"), Some("offer-4"));
    }
}
