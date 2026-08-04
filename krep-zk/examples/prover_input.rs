//! Emit a `Prover.toml` for the selective-disclosure circuit from genuinely
//! co-signed v2 attestations and real accumulators, so the circuit is exercised
//! against the code a verifier runs rather than hand-written fixtures.
//!
//! Run as `cargo run -p krep-zk --example prover_input > Prover.toml`. The
//! output is not checked in: a witness names a pseudonym and carries every body
//! in full, and a file of that shape does not belong in a source tree even when
//! the pseudonyms in it are invented. This exists to exercise the circuit
//! directly; `krep prove` is the path for a real chain.
//!
//! `KREP_SUBJECT=defaulter` emits the case the circuit must refuse: a pseudonym
//! that really was slashed trying to prove a clean record.
//! `KREP_TAMPER=owner` emits a prover pairing somebody else's anchored success
//! with their own pseudonym — the attack the binding step exists to stop.

use krep_core::{countersign, create_partial, derive_context_keypair, Attestation, AttestationBody, Outcome, Outpoint, Role};
use krep_zk::hash::Field;
use krep_zk::merkle::MerkleTree;
use krep_zk::scan::anchor_leaf;
use krep_zk::smt::SparseMerkleTree;
use secp256k1::Keypair;

const ANCHOR_DEPTH: usize = 20;
const MAX_SUCCESSES: usize = 4;

fn pseudonym(tag: &str) -> Keypair {
    let mut seed = [0u8; 32];
    seed[..tag.len().min(32)].copy_from_slice(&tag.as_bytes()[..tag.len().min(32)]);
    derive_context_keypair(&seed, "fabmesh")
}

/// A real co-signed v2 attestation between two pseudonyms.
fn attest(owner: &Keypair, cp: &Keypair, anchor_txid: [u8; 32], outcome: Outcome) -> Attestation {
    let body = AttestationBody {
        v: 2,
        anchor: Outpoint { txid: anchor_txid, index: 0 },
        role: Role::Provider,
        owner: owner.x_only_public_key().0,
        counterparty: cp.x_only_public_key().0,
        outcome,
        amount_bucket: 2,
        prev: None,
        index: 0,
        ts: 1_785_000_000,
    };
    countersign(cp, create_partial(owner, body).expect("owner signs")).expect("counterparty signs")
}

fn q(f: &Field) -> String {
    format!("\"{}\"", krep_zk::hash::to_hex(f))
}
fn bytes_toml(b: &[u8]) -> String {
    format!("[{}]", b.iter().map(|x| format!("\"{x}\"")).collect::<Vec<_>>().join(", "))
}

fn main() {
    let me = pseudonym("clean-maker");
    let buyer = pseudonym("a-buyer");
    let defaulter = pseudonym("defaulted-maker");

    // Our own success, plus one belonging to somebody else.
    let mine = attest(&me, &buyer, [0x11; 32], Outcome::Success);
    let theirs = attest(&defaulter, &buyer, [0x22; 32], Outcome::Success);

    // The anchored accumulator, as a verifier would rebuild it from chain data.
    let mut leaves = vec![
        anchor_leaf(&mine.body.anchor.txid, 0, &mine.id()),
        anchor_leaf(&theirs.body.anchor.txid, 0, &theirs.id()),
    ];
    for i in 0..30u8 {
        leaves.push(anchor_leaf(&[i; 32], 0, &[i.wrapping_add(9); 32]));
    }
    let tree = MerkleTree::build_fixed_depth(leaves, ANCHOR_DEPTH);
    let anchored_root = tree.root().expect("root");

    // The defaults tree, holding the pseudonym that was slashed.
    let defaults = SparseMerkleTree::from_keys([defaulter.x_only_public_key().0.serialize()]);

    let tamper = std::env::var("KREP_TAMPER").unwrap_or_default();
    let subject_is_defaulter = std::env::var("KREP_SUBJECT").as_deref() == Ok("defaulter");

    // Which attestation is offered, and which pseudonym it is offered for.
    let (att, subject) = if tamper == "owner" {
        // Somebody else's anchored success, claimed under our clean pseudonym.
        (&theirs, me.x_only_public_key().0.serialize())
    } else if subject_is_defaulter {
        (&theirs, defaulter.x_only_public_key().0.serialize())
    } else {
        (&mine, me.x_only_public_key().0.serialize())
    };

    let leaf = anchor_leaf(&att.body.anchor.txid, 0, &att.id());
    let proof = tree.prove(&leaf).expect("the offered attestation is anchored");
    let smt_proof = defaults.prove(&subject);

    let mut body_bytes = att.body.canonical_bytes();
    assert_eq!(body_bytes.len(), 152);
    let mut sig_bytes = att.sig_owner().expect("co-signed").as_ref().to_vec();
    sig_bytes.extend_from_slice(att.sig_counterparty().expect("co-signed").as_ref());
    assert_eq!(sig_bytes.len(), 128);

    println!("anchored_root = {}", q(&anchored_root));
    println!("defaults_root = {}", q(&defaults.root()));
    println!("min_successes = \"1\"");
    println!("used = \"1\"");
    println!("pseudonym = {}", bytes_toml(&subject));
    let bodies: Vec<String> = (0..MAX_SUCCESSES).map(|_| bytes_toml(&body_bytes)).collect();
    let sigs: Vec<String> = (0..MAX_SUCCESSES).map(|_| bytes_toml(&sig_bytes)).collect();
    println!("bodies = [{}]", bodies.join(", "));
    println!("sigs = [{}]", sigs.join(", "));
    let path = format!("[{}]", proof.siblings.iter().map(q).collect::<Vec<_>>().join(", "));
    println!("leaf_paths = [{}]", (0..MAX_SUCCESSES).map(|_| path.clone()).collect::<Vec<_>>().join(", "));
    println!(
        "leaf_indices = [{}]",
        (0..MAX_SUCCESSES).map(|s| format!("\"{}\"", if s == 0 { proof.leaf_index } else { 0 })).collect::<Vec<_>>().join(", ")
    );
    println!("defaults_path = [{}]", smt_proof.siblings.iter().map(q).collect::<Vec<_>>().join(", "));
    body_bytes.clear();
}
