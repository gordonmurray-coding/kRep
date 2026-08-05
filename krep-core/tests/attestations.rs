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
    let forged = Attestation::co_signed(
        forged_body,
        resigned.sig_owner,
        *a0.sig_counterparty().unwrap(), // stale — signed the old body
    );

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
    mutated.auth = krep_core::Authorization::CoSigned {
        sig_owner: *a.sig_owner().unwrap(),
        sig_counterparty: *cosign(&owner, &cp, body(&owner, &cp, 0, None, 1_700_000_999))
            .sig_counterparty()
            .unwrap(),
    };
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

    let forged_owner_sig = Attestation::co_signed(b.clone(), rogue, *good.sig_counterparty().unwrap());
    let err = forged_owner_sig.verify().unwrap_err();
    assert!(matches!(&err, KrepError::BadSignature(m) if m.contains("owner")), "got {err:?}");

    let forged_cp_sig = Attestation::co_signed(b, *good.sig_owner().unwrap(), rogue);
    let err = forged_cp_sig.verify().unwrap_err();
    assert!(matches!(&err, KrepError::BadSignature(m) if m.contains("counterparty")), "got {err:?}");
}

#[test]
fn swapped_signatures_are_rejected() {
    let owner = kp("owner");
    let cp = kp("cp0");
    let a = cosign(&owner, &cp, body(&owner, &cp, 0, None, 1_700_000_000));

    let swapped =
        Attestation::co_signed(a.body.clone(), *a.sig_counterparty().unwrap(), *a.sig_owner().unwrap());
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
    b.v = 3;
    assert!(b.validate_fields().is_err(), "unknown version must be rejected");
    b.v = 2;
    assert!(b.validate_fields().is_ok(), "v2 is the circuit-recomputable id scheme");

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
    fn covenant_witnessed(
        &self,
        _anchor: &Outpoint,
        _witness: &krep_core::CovenantWitness,
        _owner: &secp256k1::XOnlyPublicKey,
    ) -> std::io::Result<bool> {
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

// ---------------------------------------------------------------------------
// covenant-witnessed attestations (M2 unilateral default path)
// ---------------------------------------------------------------------------

use krep_core::{Authorization, CovenantWitness};

fn witness() -> CovenantWitness {
    CovenantWitness { redeem_script: vec![0x51, 0x52, 0x53], branch: 7, owner_offset: 38 }
}

fn covenant_att(owner: &Keypair, cp: &Keypair, outcome: Outcome) -> Attestation {
    let mut b = body(owner, cp, 0, None, 1_700_000_000);
    b.outcome = outcome;
    Attestation { body: b, auth: Authorization::Covenant { covenant_witness: witness() } }
}

#[test]
fn a_defaulter_signs_nothing_at_all() {
    let owner = kp("defaulter");
    let cp = kp("buyer");
    let att = covenant_att(&owner, &cp, Outcome::Default);

    // The whole point: no signature from either side. A defaulter will not sign
    // their own default as counterparty *or* as owner.
    assert!(att.sig_owner().is_none());
    assert!(att.sig_counterparty().is_none());
    assert!(att.covenant_witness().is_some());
    assert!(att.needs_chain_proof(), "its authority is on-chain, not in the object");

    // Field sanity passes offline, but that is all offline can establish.
    att.verify().expect("a covenant-witnessed default is structurally valid");
}

#[test]
fn covenant_witnesses_cannot_manufacture_praise() {
    let owner = kp("liar");
    let cp = kp("victim");
    // Success must be co-signed. If a covenant could witness one, anyone able
    // to drive a covenant of their own could mint reputation for themselves.
    let err = covenant_att(&owner, &cp, Outcome::Success).verify().unwrap_err();
    assert!(matches!(&err, KrepError::BadField(m) if m.contains("co-signed")), "got {err:?}");

    // Outcomes the subject would refuse to sign are exactly what it is for.
    covenant_att(&owner, &cp, Outcome::Default).verify().unwrap();
    covenant_att(&owner, &cp, Outcome::DisputedResolved).verify().unwrap();
}

#[test]
fn covenant_ids_cannot_collide_with_co_signed_ids() {
    let owner = kp("owner");
    let cp = kp("cp0");
    let b = body(&owner, &cp, 0, None, 1_700_000_000);

    let signed = cosign(&owner, &cp, b.clone());
    let witnessed = Attestation { body: b, auth: Authorization::Covenant { covenant_witness: witness() } };

    // Separate domain tags, so the two forms are computationally distinct even
    // over an identical body.
    assert_ne!(signed.id(), witnessed.id());

    // And the witness binds into the id: changing which covenant, which branch
    // or where the owner was recorded all yield a different attestation.
    for mutate in [
        |w: &mut CovenantWitness| w.branch = 8,
        |w: &mut CovenantWitness| w.owner_offset = 6,
        |w: &mut CovenantWitness| w.redeem_script.push(0x99),
    ] {
        let mut m = witness();
        mutate(&mut m);
        let other =
            Attestation { body: witnessed.body.clone(), auth: Authorization::Covenant { covenant_witness: m } };
        assert_ne!(witnessed.id(), other.id(), "witness fields must bind into the id");
    }
}

#[test]
fn an_unproven_covenant_witness_never_scores() {
    let owner = kp("defaulter");
    let cp = kp("buyer");
    let att = covenant_att(&owner, &cp, Outcome::Default);
    let mut chain = Chain::new(xonly(&owner));
    chain.append(att).unwrap();

    // Anchored is not enough for a covenant witness: the covenant's authority
    // has to be established separately, or committing arbitrary bytes to a
    // payload would be enough to defame anyone.
    struct AnchoredButUnwitnessed;
    impl AnchorVerifier for AnchoredButUnwitnessed {
        fn is_anchored(&self, _id: &[u8; 32], _a: &Outpoint) -> std::io::Result<bool> {
            Ok(true)
        }
        fn covenant_witnessed(
            &self,
            _a: &Outpoint,
            _w: &CovenantWitness,
            _o: &XOnlyPublicKey,
        ) -> std::io::Result<bool> {
            Ok(false)
        }
    }
    let err = chain.verify_anchored(&AnchoredButUnwitnessed).unwrap_err();
    assert!(
        matches!(&err, KrepError::Chain { index: 0, reason } if reason.contains("covenant witness")),
        "got {err:?}"
    );

    // With the covenant established, it stands.
    chain.verify_anchored(&krep_core::TrustEverythingAnchor).unwrap();
}

#[test]
fn json_round_trips_and_v1_chains_still_parse() {
    let owner = kp("owner");
    let cp = kp("cp0");

    // Covenant-witnessed round trip.
    let witnessed = covenant_att(&owner, &cp, Outcome::Default);
    let back: Attestation = serde_json::from_str(&serde_json::to_string(&witnessed).unwrap()).unwrap();
    assert_eq!(back.id(), witnessed.id());
    assert_eq!(back.covenant_witness(), witnessed.covenant_witness());

    // Co-signed round trip, and the JSON still uses the original field names —
    // chains anchored before this change must keep verifying.
    let signed = cosign(&owner, &cp, body(&owner, &cp, 0, None, 1_700_000_000));
    let json = serde_json::to_string(&signed).unwrap();
    assert!(json.contains("sig_owner") && json.contains("sig_counterparty"));
    assert!(!json.contains("covenant_witness"));
    let back: Attestation = serde_json::from_str(&json).unwrap();
    assert_eq!(back.id(), signed.id(), "v1 attestation ids must be unchanged");
    back.verify().unwrap();
}

// ---------------------------------------------------------------------------
// v2 ids — the scheme a circuit can recompute
// ---------------------------------------------------------------------------

#[test]
fn the_body_version_selects_the_id_hash() {
    let owner = kp("owner");
    let cp = kp("cp0");

    let mut v1 = body(&owner, &cp, 0, None, 1_700_000_000);
    v1.v = 1;
    let mut v2 = v1.clone();
    v2.v = 2;

    let a = cosign(&owner, &cp, v1);
    let b = cosign(&owner, &cp, v2);

    // Same parties, same trade, different id scheme — and the version is inside
    // the signed bytes, so neither can be relabelled as the other.
    assert_ne!(a.id(), b.id());
    a.verify().unwrap();
    b.verify().unwrap();
}

#[test]
fn a_v2_id_still_binds_every_field_and_both_signatures() {
    let owner = kp("owner");
    let cp = kp("cp0");
    let mut base = body(&owner, &cp, 0, None, 1_700_000_000);
    base.v = 2;
    let att = cosign(&owner, &cp, base.clone());
    let id = att.id();

    // Body fields.
    for mutate in [
        (|b: &mut AttestationBody| b.outcome = Outcome::Default) as fn(&mut AttestationBody),
        |b: &mut AttestationBody| b.amount_bucket = 3,
        |b: &mut AttestationBody| b.ts += 1,
        |b: &mut AttestationBody| b.role = Role::Client,
    ] {
        let mut changed = base.clone();
        mutate(&mut changed);
        assert_ne!(cosign(&owner, &cp, changed).id(), id, "a v2 id must bind every body field");
    }

    // And the signatures. Swapping the two keeps the body byte-identical, so
    // this isolates the question: does the id cover the signatures at all? An
    // id that did not could be reused across a differently-signed object.
    let swapped = Attestation::co_signed(
        base,
        *att.sig_counterparty().unwrap(),
        *att.sig_owner().unwrap(),
    );
    assert_ne!(swapped.id(), id, "a v2 id must bind the signatures, not just the body");
}

#[test]
fn a_v2_id_fits_the_payload_commitment_scheme() {
    let owner = kp("owner");
    let cp = kp("cp0");
    let mut b = body(&owner, &cp, 0, None, 1_700_000_000);
    b.v = 2;
    let id = cosign(&owner, &cp, b).id();

    // Still exactly 32 bytes, so `payload_commits` and the 64-byte terminal
    // payload are unaffected by the change of hash.
    assert_eq!(id.len(), 32);
    // A field element rendered big-endian leaves the top bits clear; this is a
    // property of the encoding, not an accident worth relying on elsewhere.
    assert!(id[0] < 0x40, "a BN254 element never sets the top two bits");
}

/// The commitment hash has to be reproducible by someone who does not run this
/// binary, or a counterparty cannot check a job's design file for themselves.
/// Pinned to blake3's own vector for the empty input.
#[test]
fn commitment_hash_is_plain_blake3() {
    assert_eq!(
        hex::encode(krep_core::commitment_hash(b"")),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );
    // No trailing newline is added, which is the difference between this and
    // `echo text | b3sum` — a mismatch that would look like a dishonest
    // counterparty rather than a shell habit.
    assert_ne!(krep_core::commitment_hash(b"abc"), krep_core::commitment_hash(b"abc\n"));
}
