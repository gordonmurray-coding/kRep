//! Phase 0 coverage: chain link verification, fork/omission detection, and
//! signature rejection.
//!
//! The threat model these tests encode: the chain owner is the adversary. They
//! hold their own key, so they can re-sign anything they like — what they
//! cannot do is forge the counterparty's signature. Every "drop a bad
//! attestation" attack therefore has to break either a `prev` link, an `index`,
//! or a counterparty signature. Each of those is asserted below.

use krep_core::chain::Chain;
use krep_core::{
    countersign, create_partial, derive_context_keypair, AnchorVerifier, Attestation,
    AttestationBody, KrepError, Outcome, Outpoint, Role,
};
use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};

fn kp(tag: &str) -> Keypair {
    // Deterministic per-tag test keys via the real derivation function.
    let mut seed = [0u8; 32];
    seed[..tag.len().min(32)].copy_from_slice(&tag.as_bytes()[..tag.len().min(32)]);
    derive_context_keypair(&seed, "test")
}

fn xonly(k: &Keypair) -> XOnlyPublicKey {
    k.x_only_public_key().0
}

fn anchor(n: u8) -> Outpoint {
    Outpoint { txid: [n; 32], index: 0 }
}

fn body(
    owner: &Keypair,
    counterparty: &Keypair,
    index: u64,
    prev: Option<[u8; 32]>,
    ts: u64,
) -> AttestationBody {
    AttestationBody {
        v: 1,
        anchor: anchor(index as u8 + 1),
        role: Role::Provider,
        owner: xonly(owner),
        counterparty: xonly(counterparty),
        outcome: Outcome::Success,
        amount_bucket: 2,
        prev,
        index,
        ts,
    }
}

/// Full two-party co-signing round trip.
fn cosign(owner: &Keypair, cp: &Keypair, b: AttestationBody) -> Attestation {
    let partial = create_partial(owner, b).expect("owner signs");
    countersign(cp, partial).expect("counterparty signs")
}

/// Build an `n`-long valid chain owned by `owner`, each entry with a distinct
/// counterparty so diversity scoring stays sane.
fn build_chain(owner: &Keypair, n: u64) -> (Chain, Vec<Keypair>) {
    let mut chain = Chain::new(xonly(owner));
    let mut cps = Vec::new();
    for i in 0..n {
        let cp = kp(&format!("cp{i}"));
        let att = cosign(owner, &cp, body(owner, &cp, i, chain.head(), 1_700_000_000 + i));
        chain.append(att).expect("append valid attestation");
        cps.push(cp);
    }
    (chain, cps)
}

// ---------------------------------------------------------------------------
// chain link verification
// ---------------------------------------------------------------------------

#[test]
fn valid_chain_verifies_and_links() {
    let owner = kp("owner");
    let (chain, _) = build_chain(&owner, 4);

    chain.verify().expect("valid chain must verify");
    assert_eq!(chain.attestations.len(), 4);

    // Every entry's prev is the previous entry's id, and index is positional.
    assert_eq!(chain.attestations[0].body.prev, None);
    for i in 1..chain.attestations.len() {
        assert_eq!(
            chain.attestations[i].body.prev,
            Some(chain.attestations[i - 1].id()),
            "prev at {i} must be the id of {}",
            i - 1
        );
        assert_eq!(chain.attestations[i].body.index, i as u64);
    }
    assert_eq!(chain.head(), Some(chain.attestations[3].id()));
}

#[test]
fn append_rejects_wrong_prev() {
    let owner = kp("owner");
    let (mut chain, _) = build_chain(&owner, 2);
    let cp = kp("cp-new");

    // Correct index, but prev points at something that is not the head.
    let att = cosign(&owner, &cp, body(&owner, &cp, 2, Some([0xab; 32]), 1_700_000_100));
    let err = chain.append(att).unwrap_err();
    assert!(
        matches!(&err, KrepError::Chain { index: 2, reason } if reason.contains("prev")),
        "expected prev-link rejection, got {err:?}"
    );
}

#[test]
fn append_rejects_wrong_index() {
    let owner = kp("owner");
    let (mut chain, _) = build_chain(&owner, 2);
    let cp = kp("cp-new");

    // Correct prev (the real head), but a skipped index.
    let att = cosign(&owner, &cp, body(&owner, &cp, 7, chain.head(), 1_700_000_100));
    let err = chain.append(att).unwrap_err();
    assert!(
        matches!(&err, KrepError::Chain { index: 2, reason } if reason.contains("index")),
        "expected index rejection, got {err:?}"
    );
}

#[test]
fn append_rejects_foreign_owner() {
    let owner = kp("owner");
    let stranger = kp("stranger");
    let cp = kp("cp-new");
    let (mut chain, _) = build_chain(&owner, 1);

    // A perfectly valid attestation — but from someone else's chain.
    let att = cosign(&stranger, &cp, body(&stranger, &cp, 0, None, 1_700_000_100));
    let err = chain.append(att).unwrap_err();
    assert!(
        matches!(&err, KrepError::Chain { reason, .. } if reason.contains("owner")),
        "expected owner rejection, got {err:?}"
    );
}

#[test]
fn chain_rejects_timestamp_regression() {
    let owner = kp("owner");
    let cp0 = kp("cp0");
    let cp1 = kp("cp1");
    let mut chain = Chain::new(xonly(&owner));

    let a0 = cosign(&owner, &cp0, body(&owner, &cp0, 0, None, 1_700_000_500));
    chain.append(a0).unwrap();
    let a1 = cosign(&owner, &cp1, body(&owner, &cp1, 1, chain.head(), 1_700_000_100));
    // `append` does not check monotonic time, but full verification must.
    chain.append(a1).unwrap();

    let err = chain.verify().unwrap_err();
    assert!(
        matches!(&err, KrepError::Chain { index: 1, reason } if reason.contains("timestamp")),
        "expected timestamp regression, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// fork / omission detection — tampering with prev or index must fail
// ---------------------------------------------------------------------------

#[test]
fn omitting_a_middle_attestation_breaks_the_chain() {
    let owner = kp("owner");
    let (chain, _) = build_chain(&owner, 3);
    let dropped_id = chain.attestations[1].id();

    // The classic attack: quietly drop the entry you don't like.
    let mut censored = chain.clone();
    censored.attestations.remove(1);

    let err = censored.verify().unwrap_err();
    assert!(
        matches!(&err, KrepError::Chain { index: 1, reason } if reason.contains("index")),
        "omission must break the chain, got {err:?}"
    );

    // And the counterparty of the dropped entry still holds a co-signed object
    // whose id is absent from the censored chain — that's the evidence.
    assert!(!censored.attestations.iter().any(|a| a.id() == dropped_id));
}

#[test]
fn omitting_the_tail_and_renumbering_still_fails_on_prev() {
    let owner = kp("owner");
    let (chain, _) = build_chain(&owner, 3);

    // Attacker drops entry 1 and renumbers entry 2 -> 1, keeping its prev.
    let mut forged = chain.clone();
    forged.attestations.remove(1);
    forged.attestations[1].body.index = 1;

    // Index now looks right, so the prev link is what catches it.
    let err = forged.verify().unwrap_err();
    assert!(
        matches!(&err, KrepError::Chain { index: 1, reason } if reason.contains("prev")),
        "renumbered omission must break the prev link, got {err:?}"
    );
}

#[test]
fn tampering_with_prev_invalidates_signatures() {
    let owner = kp("owner");
    let cp = kp("cp0");
    let a0 = cosign(&owner, &cp, body(&owner, &cp, 0, None, 1_700_000_000));
    let mut a1 = cosign(&owner, &cp, body(&owner, &cp, 1, Some(a0.id()), 1_700_000_001));

    // `prev` is inside the canonical bytes, so rewriting it breaks both sigs.
    a1.body.prev = Some([0x11; 32]);
    let err = a1.verify().unwrap_err();
    assert!(matches!(err, KrepError::BadSignature(_)), "got {err:?}");
}

#[test]
fn tampering_with_index_invalidates_signatures() {
    let owner = kp("owner");
    let cp = kp("cp0");
    let a0 = cosign(&owner, &cp, body(&owner, &cp, 0, None, 1_700_000_000));
    let mut a1 = cosign(&owner, &cp, body(&owner, &cp, 1, Some(a0.id()), 1_700_000_001));

    // Renumber an otherwise well-formed entry: still passes field validation,
    // so the signature check is what has to catch it.
    a1.body.index = 5;
    a1.body.validate_fields().expect("renumbering alone stays well-formed");
    let err = a1.verify().unwrap_err();
    assert!(matches!(err, KrepError::BadSignature(_)), "got {err:?}");
}

#[test]
fn owner_cannot_resign_a_rewrite_without_the_counterparty() {
    let owner = kp("owner");
    let cp = kp("cp0");
    let a0 = cosign(&owner, &cp, body(&owner, &cp, 0, None, 1_700_000_000));

    // Turn a default into a success and re-sign with the key the attacker owns.
    let mut forged_body = a0.body.clone();
    forged_body.outcome = Outcome::Default;
    let resigned = create_partial(&owner, forged_body.clone()).unwrap();
    let forged = Attestation {
        body: forged_body,
        sig_owner: resigned.sig_owner,
        sig_counterparty: a0.sig_counterparty, // stale — signed the old body
    };

    let err = forged.verify().unwrap_err();
    assert!(
        matches!(&err, KrepError::BadSignature(m) if m.contains("counterparty")),
        "counterparty signature must not survive a rewrite, got {err:?}"
    );
}

#[test]
fn attestation_id_binds_both_signatures() {
    let owner = kp("owner");
    let cp = kp("cp0");
    let a = cosign(&owner, &cp, body(&owner, &cp, 0, None, 1_700_000_000));
    let id_before = a.id();

    let mut mutated = a.clone();
    mutated.sig_counterparty = cosign(&owner, &cp, body(&owner, &cp, 0, None, 1_700_000_999))
        .sig_counterparty;
    assert_ne!(id_before, mutated.id(), "id must commit to the signatures");
}

// ---------------------------------------------------------------------------
// signature rejection for a wrong key
// ---------------------------------------------------------------------------

#[test]
fn countersign_rejects_a_key_that_is_not_the_counterparty() {
    let owner = kp("owner");
    let cp = kp("cp0");
    let stranger = kp("stranger");

    let partial = create_partial(&owner, body(&owner, &cp, 0, None, 1_700_000_000)).unwrap();
    let err = countersign(&stranger, partial).unwrap_err();
    assert!(
        matches!(&err, KrepError::BadField(m) if m.contains("counterparty")),
        "got {err:?}"
    );
}

#[test]
fn create_partial_rejects_a_key_that_is_not_the_owner() {
    let owner = kp("owner");
    let cp = kp("cp0");
    let stranger = kp("stranger");

    let err = create_partial(&stranger, body(&owner, &cp, 0, None, 1_700_000_000)).unwrap_err();
    assert!(matches!(&err, KrepError::BadField(m) if m.contains("owner")), "got {err:?}");
}

#[test]
fn signature_from_wrong_key_is_rejected() {
    let owner = kp("owner");
    let cp = kp("cp0");
    let stranger = kp("stranger");
    let b = body(&owner, &cp, 0, None, 1_700_000_000);

    // Stranger signs the exact same digest — valid schnorr, wrong pubkey.
    let secp = Secp256k1::new();
    let msg = secp256k1::Message::from_digest(b.signing_digest());
    let rogue = secp.sign_schnorr_no_aux_rand(&msg, &stranger);

    let good = cosign(&owner, &cp, b.clone());

    let forged_owner_sig =
        Attestation { body: b.clone(), sig_owner: rogue, sig_counterparty: good.sig_counterparty };
    let err = forged_owner_sig.verify().unwrap_err();
    assert!(matches!(&err, KrepError::BadSignature(m) if m.contains("owner")), "got {err:?}");

    let forged_cp_sig =
        Attestation { body: b, sig_owner: good.sig_owner, sig_counterparty: rogue };
    let err = forged_cp_sig.verify().unwrap_err();
    assert!(matches!(&err, KrepError::BadSignature(m) if m.contains("counterparty")), "got {err:?}");
}

#[test]
fn swapped_signatures_are_rejected() {
    let owner = kp("owner");
    let cp = kp("cp0");
    let a = cosign(&owner, &cp, body(&owner, &cp, 0, None, 1_700_000_000));

    let swapped = Attestation {
        body: a.body.clone(),
        sig_owner: a.sig_counterparty,
        sig_counterparty: a.sig_owner,
    };
    assert!(swapped.verify().is_err(), "signatures must not be interchangeable");
}

// ---------------------------------------------------------------------------
// field validation + anchoring gate
// ---------------------------------------------------------------------------

#[test]
fn field_validation_rejects_malformed_bodies() {
    let owner = kp("owner");
    let cp = kp("cp0");

    let mut b = body(&owner, &cp, 0, None, 1_700_000_000);
    b.amount_bucket = 0;
    assert!(b.validate_fields().is_err(), "bucket 0 must be rejected");
    b.amount_bucket = 5;
    assert!(b.validate_fields().is_err(), "bucket 5 must be rejected");

    let mut b = body(&owner, &cp, 0, None, 1_700_000_000);
    b.v = 2;
    assert!(b.validate_fields().is_err(), "unknown version must be rejected");

    let mut b = body(&owner, &cp, 0, None, 1_700_000_000);
    b.counterparty = xonly(&owner);
    assert!(b.validate_fields().is_err(), "self-trade must be rejected");

    // index/prev consistency
    let b = body(&owner, &cp, 0, Some([1; 32]), 1_700_000_000);
    assert!(b.validate_fields().is_err(), "index 0 must have null prev");
    let b = body(&owner, &cp, 1, None, 1_700_000_000);
    assert!(b.validate_fields().is_err(), "index > 0 must have a prev");
}

struct RejectAllAnchor;
impl AnchorVerifier for RejectAllAnchor {
    fn is_anchored(&self, _id: &[u8; 32], _anchor: &Outpoint) -> std::io::Result<bool> {
        Ok(false)
    }
}

#[test]
fn unanchored_chain_fails_verification() {
    let owner = kp("owner");
    let (chain, _) = build_chain(&owner, 2);

    chain.verify().expect("structurally valid");
    let err = chain.verify_anchored(&RejectAllAnchor).unwrap_err();
    assert!(
        matches!(&err, KrepError::Chain { index: 0, reason } if reason.contains("anchored")),
        "unanchored attestations must never pass, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// canonical encoding + derivation
// ---------------------------------------------------------------------------

#[test]
fn canonical_bytes_are_fixed_width_and_field_sensitive() {
    let owner = kp("owner");
    let cp = kp("cp0");
    let b = body(&owner, &cp, 3, Some([7; 32]), 1_700_000_000);

    // 1 + 32 + 4 + 1 + 32 + 32 + 1 + 1 + 32 + 8 + 8
    assert_eq!(b.canonical_bytes().len(), 152);

    let mut flipped = b.clone();
    flipped.role = Role::Client;
    assert_ne!(b.canonical_bytes(), flipped.canonical_bytes());
    assert_ne!(b.signing_digest(), flipped.signing_digest());

    let mut rebucketed = b.clone();
    rebucketed.amount_bucket = 3;
    assert_ne!(b.signing_digest(), rebucketed.signing_digest());
}

#[test]
fn json_is_transport_only_and_round_trips() {
    let owner = kp("owner");
    let cp = kp("cp0");
    let a = cosign(&owner, &cp, body(&owner, &cp, 0, None, 1_700_000_000));

    let json = serde_json::to_string(&a).unwrap();
    let back: Attestation = serde_json::from_str(&json).unwrap();
    assert_eq!(a.id(), back.id());
    assert_eq!(a.body.canonical_bytes(), back.body.canonical_bytes());
    back.verify().expect("round-tripped attestation still verifies");
}

#[test]
fn context_derivation_is_deterministic_and_unlinkable() {
    let seed = [42u8; 32];
    let a = derive_context_keypair(&seed, "fabmesh");
    let a_again = derive_context_keypair(&seed, "fabmesh");
    let b = derive_context_keypair(&seed, "gpu-rental");

    assert_eq!(xonly(&a), xonly(&a_again), "same seed+context must be stable");
    assert_ne!(xonly(&a), xonly(&b), "different contexts must not collide");

    let other_seed = [43u8; 32];
    assert_ne!(xonly(&a), xonly(&derive_context_keypair(&other_seed, "fabmesh")));
}

#[test]
fn scoring_counts_outcomes_and_diversity() {
    let owner = kp("owner");
    let cp = kp("cp-repeat");
    let mut chain = Chain::new(xonly(&owner));

    // Three trades, all with the same counterparty — a wash-trading ring of two.
    for i in 0..3u64 {
        let mut b = body(&owner, &cp, i, chain.head(), 1_700_000_000 + i);
        if i == 2 {
            b.outcome = Outcome::Default;
        }
        chain.append(cosign(&owner, &cp, b)).unwrap();
    }

    let s = chain.score();
    assert_eq!(s.trades, 3);
    assert_eq!(s.defaults, 1);
    assert_eq!(s.unique_counterparties, 1);
    assert!((s.default_rate - 1.0 / 3.0).abs() < 1e-12);
    assert!(
        (s.counterparty_diversity - 1.0 / 3.0).abs() < 1e-12,
        "a 2-key ring must show low diversity"
    );
    assert_eq!(s.volume_hist, [0, 3, 0, 0]);
}
