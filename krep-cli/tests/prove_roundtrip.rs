//! End-to-end `krep prove` → `krep check-proof`, without a node.
//!
//! The accumulator here is built locally rather than scanned, which is the only
//! part this cannot exercise offline. Everything downstream of it is the real
//! path: real co-signed v2 attestations, the real Merkle and sparse trees, the
//! real circuit, and a real UltraHonk proof.
//!
//! Gated on `$KREP_TEST_PROVE` because proving needs `nargo` and `bb` installed
//! and takes a few seconds per case.
//!
//! What it is really for is the last test: a proof that verifies against the
//! roots it was built from must *fail* against roots someone else derived. If
//! that ever passes, the proof means nothing, and nothing else in this file
//! would notice.

use krep_core::chain::Chain;
use krep_core::{countersign, create_partial, derive_context_keypair, AttestationBody, Outcome, Outpoint, Role};
use krep_zk::hash::to_hex;
use krep_zk::merkle::MerkleTree;
use krep_zk::scan::anchor_leaf;
use krep_zk::smt::SparseMerkleTree;
use secp256k1::Keypair;
use std::path::{Path, PathBuf};
use std::process::Command;

const ANCHOR_DEPTH: usize = 20;

fn kp(tag: &str) -> Keypair {
    let mut seed = [0u8; 32];
    seed[..tag.len()].copy_from_slice(tag.as_bytes());
    derive_context_keypair(&seed, "prove-roundtrip")
}

fn chain_of(owner: &Keypair, cp: &Keypair, txids: &[[u8; 32]]) -> Chain {
    let mut chain = Chain::new(owner.x_only_public_key().0);
    for (i, txid) in txids.iter().enumerate() {
        let body = AttestationBody {
            v: 2,
            anchor: Outpoint { txid: *txid, index: 0 },
            role: Role::Provider,
            owner: owner.x_only_public_key().0,
            counterparty: cp.x_only_public_key().0,
            outcome: Outcome::Success,
            amount_bucket: 2,
            prev: chain.head(),
            index: i as u64,
            ts: 1_785_000_000 + i as u64,
        };
        chain.append(countersign(cp, create_partial(owner, body).unwrap()).unwrap()).unwrap();
    }
    chain
}

/// A saved scan, in the shape `krep roots --out` writes.
fn roots_json(chains: &[&Chain], defaulted: Vec<[u8; 32]>, noise: u8) -> String {
    let mut leaves: Vec<Vec<u8>> = Vec::new();
    for c in chains {
        for a in &c.attestations {
            leaves.push(anchor_leaf(&a.body.anchor.txid, a.body.anchor.index, &a.id()));
        }
    }
    // Other people's settlements. Without them the tree is the subject's chain
    // and membership would be a statement about a set of one.
    for i in 0..noise {
        leaves.push(anchor_leaf(&[i; 32], 0, &[i.wrapping_add(77); 32]));
    }
    let tree = MerkleTree::build_fixed_depth(leaves.clone(), ANCHOR_DEPTH);
    let smt = SparseMerkleTree::from_keys(defaulted.clone());
    serde_json::json!({
        "depth": ANCHOR_DEPTH,
        "complete": true,
        "anchored_root": to_hex(&tree.root().unwrap()),
        "defaults_root": to_hex(&smt.root()),
        "anchored_leaves": leaves.iter().map(hex::encode).collect::<Vec<_>>(),
        "defaulted": defaulted.iter().map(hex::encode).collect::<Vec<_>>(),
    })
    .to_string()
}

fn krep(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_krep")).args(args).output().expect("running krep")
}

fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, body).unwrap();
    p
}

#[test]
fn prove_then_check_against_independently_derived_roots() {
    if std::env::var("KREP_TEST_PROVE").is_err() {
        eprintln!("set KREP_TEST_PROVE=1 to run (needs nargo + bb, takes ~1 minute)");
        return;
    }
    let dir = std::env::temp_dir().join("krep-prove-roundtrip");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let (me, buyer, other) = (kp("subject"), kp("buyer"), kp("stranger"));
    let mine = chain_of(&me, &buyer, &[[0xa1; 32], [0xa2; 32]]);
    let theirs = chain_of(&other, &buyer, &[[0xb1; 32]]);

    let chain_path = write(&dir, "chain.json", &serde_json::to_string(&mine).unwrap());
    let roots_path = write(&dir, "roots.json", &roots_json(&[&mine, &theirs], vec![], 12));
    let proof_path = dir.join("proof.json");

    let out = krep(&[
        "prove",
        "--chain", chain_path.to_str().unwrap(),
        "--roots", roots_path.to_str().unwrap(),
        "--min-successes", "2",
        "--out", proof_path.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "prove failed: {}", String::from_utf8_lossy(&out.stderr));

    // The proof must not carry the pseudonym it exists to conceal.
    let bundle = std::fs::read_to_string(&proof_path).unwrap();
    let subject = hex::encode(me.x_only_public_key().0.serialize());
    assert!(!bundle.contains(&subject), "the bundle names the pseudonym");
    // A "successful" run that wrote nothing would still pass every assertion
    // above, and bb happily verifies an empty file against nothing.
    let parsed: serde_json::Value = serde_json::from_str(&bundle).unwrap();
    let proof_bytes = parsed["proof"].as_str().unwrap().len() / 2;
    assert!(proof_bytes > 8_000, "proof is only {proof_bytes} bytes");

    let out = krep(&[
        "check-proof",
        "--proof", proof_path.to_str().unwrap(),
        "--roots", roots_path.to_str().unwrap(),
        "--min-successes", "2",
    ]);
    assert!(out.status.success(), "check failed: {}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("VERIFIED"));

    // Now the test the rest of this file exists to set up. A verifier who
    // scanned a different range derives a different anchored root, and the same
    // proof must not satisfy them — otherwise "the verifier derives the roots
    // themselves" is decoration and a prover could have chosen any tree.
    let elsewhere = write(&dir, "other-roots.json", &roots_json(&[&mine, &theirs], vec![], 13));
    let out = krep(&[
        "check-proof",
        "--proof", proof_path.to_str().unwrap(),
        "--roots", elsewhere.to_str().unwrap(),
        "--min-successes", "2",
    ]);
    assert!(!out.status.success(), "a proof verified against roots it was not built for");

    // And a verifier demanding more than was proved is not satisfied either.
    let out = krep(&[
        "check-proof",
        "--proof", proof_path.to_str().unwrap(),
        "--roots", roots_path.to_str().unwrap(),
        "--min-successes", "4",
    ]);
    assert!(!out.status.success(), "a 2-success proof satisfied a demand for 4");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A verification key says *which circuit* was proved. A verifier that takes
/// one from the prover has therefore let the prover choose what was proved.
///
/// The attack needs nothing clever: write a circuit with the same three public
/// inputs and no assertions at all, set those inputs to the roots the verifier
/// will derive — they are public — and prove it. The proof is valid, the same
/// 14,656 bytes, and against its own vk it verifies. It establishes nothing.
#[test]
fn a_proof_of_a_circuit_that_asserts_nothing_is_rejected() {
    if std::env::var("KREP_TEST_PROVE").is_err() {
        eprintln!("set KREP_TEST_PROVE=1 to run (needs nargo + bb)");
        return;
    }
    let dir = std::env::temp_dir().join("krep-prove-permissive");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("circuit/src")).unwrap();

    let (me, buyer) = (kp("attacker"), kp("buyer"));
    let mine = chain_of(&me, &buyer, &[[0xd1; 32]]);
    let roots_body = roots_json(&[&mine], vec![], 10);
    let roots_path = write(&dir, "roots.json", &roots_body);
    let roots: serde_json::Value = serde_json::from_str(&roots_body).unwrap();

    let circuit = dir.join("circuit");
    std::fs::write(
        circuit.join("Nargo.toml"),
        "[package]\nname = \"circuit\"\ntype = \"bin\"\nauthors = [\"\"]\n",
    )
    .unwrap();
    std::fs::write(
        circuit.join("src/main.nr"),
        "fn main(anchored_root: pub Field, defaults_root: pub Field, min_successes: pub u32) {}\n",
    )
    .unwrap();
    std::fs::write(
        circuit.join("Prover.toml"),
        format!(
            "anchored_root = \"{}\"\ndefaults_root = \"{}\"\nmin_successes = \"1\"\n",
            roots["anchored_root"].as_str().unwrap(),
            roots["defaults_root"].as_str().unwrap()
        ),
    )
    .unwrap();

    let sh = |prog: &str, args: &[&str]| {
        let out = Command::new(prog).args(args).current_dir(&circuit).output().expect(prog);
        assert!(out.status.success(), "{prog}: {}", String::from_utf8_lossy(&out.stderr));
    };
    sh("nargo", &["execute", "-p", "Prover.toml"]);
    sh("bb", &["write_vk", "-b", "target/circuit.json", "-o", "target"]);
    sh("bb", &["prove", "-b", "target/circuit.json", "-w", "target/circuit.gz", "-o", "target"]);

    let bundle = serde_json::json!({
        "min_successes": 1,
        "proved_against_anchored_root": roots["anchored_root"],
        "proved_against_defaults_root": roots["defaults_root"],
        "proof": hex::encode(std::fs::read(circuit.join("target/proof")).unwrap()),
        "vk": hex::encode(std::fs::read(circuit.join("target/vk")).unwrap()),
    });
    let proof_path = write(&dir, "proof.json", &bundle.to_string());

    let out = krep(&[
        "check-proof",
        "--proof", proof_path.to_str().unwrap(),
        "--roots", roots_path.to_str().unwrap(),
        "--min-successes", "1",
    ]);
    assert!(
        !out.status.success(),
        "a proof of a circuit with no constraints was accepted:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_slashed_pseudonym_is_refused_before_any_proving_happens() {
    // No toolchain needed: this must fail while building the witness, so a
    // defaulter never reaches the prover at all.
    let dir = std::env::temp_dir().join("krep-prove-slashed");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let (me, buyer) = (kp("defaulted"), kp("buyer"));
    let mine = chain_of(&me, &buyer, &[[0xc1; 32]]);
    let chain_path = write(&dir, "chain.json", &serde_json::to_string(&mine).unwrap());
    let roots_path = write(
        &dir,
        "roots.json",
        &roots_json(&[&mine], vec![me.x_only_public_key().0.serialize()], 8),
    );

    let out = krep(&[
        "prove",
        "--chain", chain_path.to_str().unwrap(),
        "--roots", roots_path.to_str().unwrap(),
        "--out", dir.join("proof.json").to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("recorded as having defaulted"), "{err}");
    assert!(!dir.join("proof.json").exists(), "a proof was written for a defaulter");

    let _ = std::fs::remove_dir_all(&dir);
}
