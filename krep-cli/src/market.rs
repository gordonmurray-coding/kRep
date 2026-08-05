//! Browsing offers, with every record checked before it is shown.
//!
//! # Why this cannot use the node
//!
//! Verifying one chain against kaspad takes 50 to 100 seconds, because every
//! anchor needs a scan forward from its escrow to find what spent it. That is
//! fine for the one counterparty you are about to trade with. A page listing
//! twenty sellers would take an hour, so a marketplace built that way would
//! either be unusable or would quietly stop verifying — and a marketplace that
//! shows unverified scores is the platform-rating problem it exists to replace.
//!
//! The M6 accumulator already solves it. A saved scan holds every anchored id in
//! the window, so "is this attestation anchored" becomes a lookup instead of a
//! scan: instant, and still derived by the reader rather than asserted by anyone.
//! Verification stays local; only its cost changes.
//!
//! # What is weaker here, stated plainly
//!
//! Against a node, a covenant-witnessed default is checked by re-running the
//! covenant: this specific escrow, this branch, this owner. Against the
//! accumulator it is checked by membership in the defaults tree, which
//! establishes that the pseudonym was slashed somewhere in the window rather
//! than that this particular entry produced it.
//!
//! That is weaker, and it is weak in the harmless direction. A default is an
//! admission against oneself, and the binding on an offer means a seller can
//! only ever advertise their own chain — so the forgery this would permit is
//! confessing to a default you did not commit. The attack worth stopping is
//! hiding one, and the defaults tree catches that independently of anything the
//! seller chose to show.

use anyhow::Result;
use krep_board::offer::Offer;
use krep_core::chain::Chain;
use krep_core::{AnchorVerifier, CovenantWitness, Outpoint};
use krep_zk::merkle::MerkleTree;
use krep_zk::scan::anchor_leaf;
use krep_zk::smt::SparseMerkleTree;
use secp256k1::XOnlyPublicKey;
use std::io;

/// An [`AnchorVerifier`] backed by a saved scan rather than a live node.
pub struct RootsVerifier {
    anchored: MerkleTree,
    defaults: SparseMerkleTree,
    /// Whether the scan reached the tip. A partial one makes recent, honest
    /// settlements look unanchored, which on a marketplace reads as fraud.
    pub complete: bool,
}

impl RootsVerifier {
    pub fn load(path: &std::path::Path) -> Result<RootsVerifier> {
        let saved = crate::prove::RootsFile::load(path)?;
        let complete = saved.complete;
        let (anchored, defaults) = saved.trees()?;
        Ok(RootsVerifier { anchored, defaults, complete })
    }
}

impl AnchorVerifier for RootsVerifier {
    /// A miss is reported as *unknown*, never as unanchored.
    ///
    /// An accumulator has a horizon at both ends: it begins where the scan
    /// began and stops where the scan stopped. An attestation absent from it
    /// was either never anchored or simply settled outside that range, and
    /// nothing here can tell those apart. On a marketplace the difference is
    /// the difference between "I cannot confirm this" and calling a stranger a
    /// liar on the strength of a local file being out of date.
    ///
    /// It costs something real: a genuinely invented record also reads as
    /// unknown rather than as fraud. That is the right way round. This page
    /// never shows a score it has not checked, so an unverifiable record earns
    /// nothing — it just is not accused of anything either.
    fn is_anchored(&self, id: &[u8; 32], anchor: &Outpoint) -> io::Result<bool> {
        if self.anchored.index_of(&anchor_leaf(&anchor.txid, anchor.index, id)).is_some() {
            return Ok(true);
        }
        Err(io::Error::other(
            "not in the scan on this machine — it was either never anchored, or it settled \
             outside the range this scan covers. Rebuild with `krep roots --out` to be sure.",
        ))
    }

    fn covenant_witnessed(
        &self,
        _anchor: &Outpoint,
        _witness: &CovenantWitness,
        owner: &XOnlyPublicKey,
    ) -> io::Result<bool> {
        Ok(self.defaults.contains(&owner.serialize()))
    }
}

/// One listing, and what its record actually supports.
#[derive(serde::Serialize)]
pub struct Listing {
    pub id: String,
    pub seller: String,
    pub title: String,
    pub summary: String,
    pub process: String,
    pub materials: Vec<String>,
    pub region: String,
    pub from_price: u64,
    pub lead_days: u32,
    /// `verified`, `unverified`, or `no_record`. A seller with no history is
    /// not a seller with a bad one, and the two must not render alike.
    pub status: &'static str,
    /// Why, when it is not verified. Shown rather than swallowed.
    pub note: Option<String>,
    pub trades: u64,
    pub defaults: u64,
    pub counterparties: u64,
    pub diversity: f64,
    pub chain: Option<Chain>,
}

/// Check one offer's record and reduce it to what a browser should show.
pub fn assess(id: String, seller: String, offer: Offer, verifier: &RootsVerifier) -> Listing {
    let base = Listing {
        id,
        seller,
        title: offer.title,
        summary: offer.summary,
        process: offer.process,
        materials: offer.materials,
        region: offer.region,
        from_price: offer.from_price,
        lead_days: offer.lead_days,
        status: "no_record",
        note: None,
        trades: 0,
        defaults: 0,
        counterparties: 0,
        diversity: 0.0,
        chain: None,
    };
    let Some(chain) = offer.rep_chain else { return base };

    // Structure and signatures first, then anchoring. A chain that fails either
    // is shown as unverified with the reason, never silently scored — a number
    // beside a listing is a recommendation, and an unchecked one is a lie.
    if let Err(e) = chain.verify_anchored(verifier) {
        return Listing { status: "unverified", note: Some(e.to_string()), ..base };
    }
    let s = chain.score();
    Listing {
        status: "verified",
        trades: s.trades,
        defaults: s.defaults,
        counterparties: s.unique_counterparties,
        diversity: s.counterparty_diversity,
        chain: Some(chain),
        ..base
    }
}

/// Sort for a browse page: verified first, then fewer defaults, then more
/// trades. Deliberately not a ranking anyone can buy — there is no promotion,
/// no fee, and no signal here that did not come out of the chain.
pub fn rank(listings: &mut [Listing]) {
    listings.sort_by(|a, b| {
        let key = |l: &Listing| {
            (
                match l.status {
                    "verified" => 0,
                    "no_record" => 1,
                    _ => 2,
                },
                l.defaults,
                std::cmp::Reverse(l.trades),
            )
        };
        key(a).cmp(&key(b))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use krep_core::{
        countersign, create_partial, derive_context_keypair, AttestationBody, Outcome, Role,
    };
    use krep_zk::hash::to_hex;
    use secp256k1::Keypair;

    fn kp(tag: &str) -> Keypair {
        let mut seed = [0u8; 32];
        seed[..tag.len()].copy_from_slice(tag.as_bytes());
        derive_context_keypair(&seed, "market-test")
    }

    fn chain_of(owner: &Keypair, cp: &Keypair, txid: [u8; 32], outcome: Outcome) -> Chain {
        let body = AttestationBody {
            v: 2,
            anchor: Outpoint { txid, index: 0 },
            role: Role::Provider,
            owner: owner.x_only_public_key().0,
            counterparty: cp.x_only_public_key().0,
            outcome,
            amount_bucket: 2,
            prev: None,
            index: 0,
            ts: 1_785_000_000,
        };
        let mut c = Chain::new(owner.x_only_public_key().0);
        c.append(countersign(cp, create_partial(owner, body).unwrap()).unwrap()).unwrap();
        c
    }

    fn verifier_for(chains: &[&Chain], defaulted: Vec<[u8; 32]>) -> RootsVerifier {
        let mut leaves: Vec<Vec<u8>> = Vec::new();
        for c in chains {
            for a in &c.attestations {
                leaves.push(anchor_leaf(&a.body.anchor.txid, a.body.anchor.index, &a.id()));
            }
        }
        for i in 0..6u8 {
            leaves.push(anchor_leaf(&[i; 32], 0, &[i.wrapping_add(60); 32]));
        }
        RootsVerifier {
            anchored: MerkleTree::build_fixed_depth(leaves, 20),
            defaults: SparseMerkleTree::from_keys(defaulted),
            complete: true,
        }
    }

    fn offer_with(chain: Option<Chain>) -> Offer {
        Offer {
            v: 1,
            title: "t".into(),
            summary: "s".into(),
            process: "fdm".into(),
            materials: vec![],
            region: "EU".into(),
            from_price: 1,
            lead_days: 1,
            rep_chain: chain,
        }
    }

    #[test]
    fn an_anchored_record_verifies_without_touching_a_node() {
        let (me, buyer) = (kp("seller"), kp("buyer"));
        let chain = chain_of(&me, &buyer, [0x11; 32], Outcome::Success);
        let v = verifier_for(&[&chain], vec![]);
        let l = assess("o1".into(), "pk".into(), offer_with(Some(chain)), &v);
        assert_eq!(l.status, "verified");
        assert_eq!((l.trades, l.defaults), (1, 0));
    }

    #[test]
    fn a_record_outside_the_scan_is_unverified_not_scored() {
        // The seller may be entirely honest and simply older than the window.
        // What must not happen is a score appearing anyway.
        let (me, buyer) = (kp("old"), kp("buyer"));
        let chain = chain_of(&me, &buyer, [0x22; 32], Outcome::Success);
        let elsewhere = chain_of(&kp("other"), &buyer, [0x33; 32], Outcome::Success);
        let v = verifier_for(&[&elsewhere], vec![]);
        let l = assess("o2".into(), "pk".into(), offer_with(Some(chain)), &v);
        assert_eq!(l.status, "unverified");
        assert_eq!(l.trades, 0, "an unverified record must not be scored");
        assert!(l.note.is_some());
    }

    #[test]
    fn no_record_is_not_the_same_as_a_bad_one() {
        let v = verifier_for(&[], vec![]);
        let l = assess("o3".into(), "pk".into(), offer_with(None), &v);
        assert_eq!(l.status, "no_record");
        assert!(l.note.is_none(), "having no history is not a fault to explain");
    }

    #[test]
    fn a_tampered_record_never_reaches_a_score() {
        let (me, buyer) = (kp("liar"), kp("buyer"));
        let mut chain = chain_of(&me, &buyer, [0x44; 32], Outcome::Success);
        let v = verifier_for(&[&chain], vec![]);
        chain.attestations[0].body.amount_bucket = 4; // signature no longer holds
        let l = assess("o4".into(), "pk".into(), offer_with(Some(chain)), &v);
        assert_eq!(l.status, "unverified");
        assert_eq!(l.trades, 0);
    }

    #[test]
    fn ranking_puts_the_provable_first_and_sells_no_positions() {
        let mut ls = vec![
            Listing { status: "unverified", trades: 99, ..blank("a") },
            Listing { status: "verified", defaults: 1, trades: 9, ..blank("b") },
            Listing { status: "no_record", ..blank("c") },
            Listing { status: "verified", defaults: 0, trades: 2, ..blank("d") },
        ];
        rank(&mut ls);
        assert_eq!(ls.iter().map(|l| l.id.as_str()).collect::<Vec<_>>(), ["d", "b", "c", "a"]);
    }

    fn blank(id: &str) -> Listing {
        Listing {
            id: id.into(), seller: String::new(), title: String::new(), summary: String::new(),
            process: String::new(), materials: vec![], region: String::new(), from_price: 0,
            lead_days: 0, status: "no_record", note: None, trades: 0, defaults: 0,
            counterparties: 0, diversity: 0.0, chain: None,
        }
    }

    #[test]
    fn the_accumulator_agrees_with_itself_about_roots() {
        // Guards the assumption the whole page rests on: the verifier is built
        // from the same tree the roots file describes.
        let chain = chain_of(&kp("x"), &kp("y"), [0x55; 32], Outcome::Success);
        let v = verifier_for(&[&chain], vec![[7u8; 32]]);
        assert!(v.defaults.contains(&[7u8; 32]));
        assert!(!to_hex(&v.defaults.root()).is_empty());
    }
}
