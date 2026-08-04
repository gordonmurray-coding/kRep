//! Making the M6 proof something a person can actually produce and check.
//!
//! The circuit and the accumulators already existed; what did not was any path
//! from *a chain file on disk* to *a proof someone else can verify*. Building
//! one meant hand-editing `Prover.toml` against fixtures invented for the
//! purpose, which proves the circuit compiles and nothing about whether the
//! claim it encodes is reachable from real data.
//!
//! Two commands close that:
//!
//! - `krep prove` reads a chain, finds its successes in a rebuilt anchored set,
//!   takes the absence path for its pseudonym, and emits the witness.
//! - `krep check-proof` rebuilds both roots *itself* and verifies against those,
//!   never against the roots the prover supplied.
//!
//! The second point is the whole reason this is worth anything. A proof carries
//! its public inputs, and a prover who chose them could prove membership in a
//! tree they invented. So the verifier writes the public inputs from what it
//! derived, and hands the prover's proof to `bb` against those. A proof built on
//! a different set simply fails — no comparison of hex strings required, and no
//! opportunity to forget one.

use anyhow::{anyhow, bail, Context, Result};
use krep_core::chain::Chain;
use krep_core::Outcome;
use krep_zk::hash::{to_be_32, to_hex, Field};
use krep_zk::merkle::MerkleTree;
use krep_zk::scan::anchor_leaf;
use krep_zk::smt::SparseMerkleTree;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Must match `ANCHOR_DEPTH` in the circuit.
pub const ANCHOR_DEPTH: usize = 20;
/// Must match `MAX_SUCCESSES` in the circuit.
pub const MAX_SUCCESSES: usize = 4;
/// Three public inputs, one field each, big-endian.
pub const PUBLIC_INPUT_BYTES: usize = 96;

/// A scan, saved.
///
/// Rebuilding the accumulators from a node takes hours over a full pruning
/// window. Both trees are a pure function of these two lists, so saving them
/// turns every proof after the first into an operation on a local file.
///
/// It holds the *raw* leaf values rather than their hashes, because building a
/// path needs the value that goes in at the bottom. Order does not matter:
/// `build_fixed_depth` sorts, so two people who scanned the same range agree
/// even if their nodes returned blocks in a different order.
#[derive(Serialize, Deserialize)]
pub struct RootsFile {
    pub depth: usize,
    /// Whether the scan reached the tip. A partial set is not a smaller version
    /// of a complete one — it is one that fails honest provers.
    pub complete: bool,
    pub anchored_root: String,
    pub defaults_root: String,
    pub anchored_leaves: Vec<String>,
    pub defaulted: Vec<String>,
}

impl RootsFile {
    pub fn from_scan(r: &crate::roots::Roots, depth: usize) -> Self {
        RootsFile {
            depth,
            complete: r.reached_tip,
            anchored_root: r.anchored.root().as_ref().map(to_hex).unwrap_or_default(),
            defaults_root: to_hex(&r.defaults.root()),
            anchored_leaves: r.leaves.iter().map(hex::encode).collect(),
            defaulted: r.defaulted.iter().map(hex::encode).collect(),
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
    }

    /// Rebuild both accumulators, and check they still hash to what was saved.
    ///
    /// The recorded roots are not trusted here; they are a tripwire. If a saved
    /// scan is edited, or a change to the hashing makes an old file mean
    /// something different, this is where it surfaces rather than in a proof
    /// that mysteriously will not verify.
    pub fn trees(&self) -> Result<(MerkleTree, SparseMerkleTree)> {
        let leaves: Vec<Vec<u8>> = self
            .anchored_leaves
            .iter()
            .map(|h| hex::decode(h).map_err(|e| anyhow!("bad leaf hex: {e}")))
            .collect::<Result<_>>()?;
        let mut keys = Vec::with_capacity(self.defaulted.len());
        for h in &self.defaulted {
            let b = hex::decode(h).map_err(|e| anyhow!("bad pseudonym hex: {e}"))?;
            keys.push(<[u8; 32]>::try_from(&b[..]).map_err(|_| anyhow!("pseudonym must be 32 bytes"))?);
        }
        let anchored = MerkleTree::build_fixed_depth(leaves, self.depth);
        let defaults = SparseMerkleTree::from_keys(keys);

        let got = anchored.root().as_ref().map(to_hex).unwrap_or_default();
        if got != self.anchored_root {
            bail!("saved anchored root {} does not match the rebuilt {got}", self.anchored_root);
        }
        let got = to_hex(&defaults.root());
        if got != self.defaults_root {
            bail!("saved defaults root {} does not match the rebuilt {got}", self.defaults_root);
        }
        Ok((anchored, defaults))
    }
}

/// A proof, and nothing a verifier is expected to take on faith.
///
/// Note what is *not* here: no verification key. A vk says which circuit was
/// proved, so a verifier accepting one from the prover has let the prover choose
/// what was proved — and the attack is not subtle. Write a circuit with these
/// same three public inputs and no assertions at all, set them to the roots the
/// verifier will derive (they are public), prove it. That proof is valid, the
/// same 14,656 bytes, and against its own key it verifies. It establishes
/// nothing. `check-proof` therefore derives the key from its own embedded copy
/// of the circuit, and there is no field here for a prover to fill.
///
/// The roots recorded below are a courtesy for reading the file. Verification
/// never consumes them either.
#[derive(Serialize, Deserialize)]
pub struct ProofBundle {
    pub min_successes: u32,
    pub proved_against_anchored_root: String,
    pub proved_against_defaults_root: String,
    pub proof: String,
}

/// The 96 bytes `bb` expects: three field elements, big-endian.
pub fn public_inputs(anchored: &Field, defaults: &Field, min_successes: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(PUBLIC_INPUT_BYTES);
    for f in [to_be_32(anchored), to_be_32(defaults), to_be_32(&Field::from(min_successes as u128))] {
        out.extend_from_slice(&f);
    }
    out
}

fn toml_bytes(b: &[u8]) -> String {
    format!("[{}]", b.iter().map(|x| format!("\"{x}\"")).collect::<Vec<_>>().join(", "))
}

fn toml_fields(f: &[Field]) -> String {
    format!("[{}]", f.iter().map(|x| format!("\"{}\"", to_hex(x))).collect::<Vec<_>>().join(", "))
}

/// What went into a witness, for telling the user what was actually claimed.
#[derive(Debug)]
pub struct Witness {
    pub toml: String,
    pub used: usize,
    pub pseudonym: [u8; 32],
    pub anchored_root: Field,
    pub defaults_root: Field,
}

/// Build the circuit's witness from a real chain against a real accumulator.
///
/// Every failure here is a claim the prover cannot honestly make, so each one
/// says which claim rather than which array was the wrong length.
pub fn witness(
    chain: &Chain,
    anchored: &MerkleTree,
    defaults: &SparseMerkleTree,
    min_successes: u32,
) -> Result<Witness> {
    let subject = chain.owner.serialize();

    // Absence first: it is the claim most likely to be false, and the one whose
    // failure a prover most needs stated plainly.
    let smt_proof = defaults.prove(&subject);
    if !smt_proof.proves_absence() {
        bail!(
            "this pseudonym is recorded as having defaulted — the circuit will not prove otherwise.\n\
             That is the accumulator working, not a bug."
        );
    }

    let mut bodies = Vec::new();
    let mut sigs = Vec::new();
    let mut paths: Vec<Vec<Field>> = Vec::new();
    let mut indices = Vec::new();

    for att in &chain.attestations {
        if bodies.len() == MAX_SUCCESSES {
            break;
        }
        if att.body.outcome != Outcome::Success {
            continue;
        }
        // v1 ids are blake3; the circuit recomputes v2 Poseidon2 ids, because
        // rehashing blake3 in-circuit costs more than the whole rest of it.
        if att.body.v < 2 {
            continue;
        }
        let (Some(so), Some(sc)) = (att.sig_owner(), att.sig_counterparty()) else {
            // Covenant-witnessed entries carry no signatures, so there is
            // nothing for the circuit to rehash. They are also always defaults.
            continue;
        };

        let leaf = anchor_leaf(&att.body.anchor.txid, att.body.anchor.index, &att.id());
        let Some(proof) = anchored.prove(&leaf) else {
            bail!(
                "attestation {} is not in the anchored set that was rebuilt from the chain.\n\
                 Either its settlement is outside the scanned window, or it was never anchored.",
                hex::encode(att.id())
            );
        };
        if proof.siblings.len() != ANCHOR_DEPTH {
            bail!(
                "the accumulator is depth {} but the circuit walks {ANCHOR_DEPTH}",
                proof.siblings.len()
            );
        }

        let mut sig = so.as_ref().to_vec();
        sig.extend_from_slice(sc.as_ref());
        bodies.push(att.body.canonical_bytes());
        sigs.push(sig);
        paths.push(proof.siblings.clone());
        indices.push(proof.leaf_index);
    }

    let used = bodies.len();
    if used < min_successes as usize {
        bail!(
            "only {used} anchored success{} available, but the proof claims {min_successes}",
            if used == 1 { " is" } else { "es are" }
        );
    }
    if used == 0 {
        bail!("no anchored successes in this chain — there is nothing to prove");
    }

    // Unused slots repeat slot zero. The circuit ignores them past `used`, and
    // an honest prover with fewer successes should not have to invent inputs.
    let pad = |v: &Vec<Vec<u8>>| -> Vec<String> {
        (0..MAX_SUCCESSES).map(|i| toml_bytes(&v[i.min(used - 1)])).collect()
    };
    let anchored_root = anchored.root().ok_or_else(|| anyhow!("the anchored set is empty"))?;
    let defaults_root = defaults.root();

    let mut toml = String::new();
    toml.push_str(&format!("anchored_root = \"{}\"\n", to_hex(&anchored_root)));
    toml.push_str(&format!("defaults_root = \"{}\"\n", to_hex(&defaults_root)));
    toml.push_str(&format!("min_successes = \"{min_successes}\"\n"));
    toml.push_str(&format!("used = \"{used}\"\n"));
    toml.push_str(&format!("pseudonym = {}\n", toml_bytes(&subject)));
    toml.push_str(&format!("bodies = [{}]\n", pad(&bodies).join(", ")));
    toml.push_str(&format!("sigs = [{}]\n", pad(&sigs).join(", ")));
    let path_list: Vec<String> =
        (0..MAX_SUCCESSES).map(|i| toml_fields(&paths[i.min(used - 1)])).collect();
    toml.push_str(&format!("leaf_paths = [{}]\n", path_list.join(", ")));
    let idx_list: Vec<String> = (0..MAX_SUCCESSES)
        .map(|i| format!("\"{}\"", if i < used { indices[i] } else { 0 }))
        .collect();
    toml.push_str(&format!("leaf_indices = [{}]\n", idx_list.join(", ")));
    toml.push_str(&format!("defaults_path = {}\n", toml_fields(&smt_proof.siblings)));

    Ok(Witness { toml, used, pseudonym: subject, anchored_root, defaults_root })
}

/// Where the Noir toolchain lives.
///
/// `nargo` and `bb` are external programs, not crates, and are only needed by
/// these two commands. When they are missing the witness is still written and
/// the exact commands printed, so the milestone does not become unreachable for
/// want of an installer.
pub struct Toolchain {
    pub nargo: PathBuf,
    pub bb: PathBuf,
}

pub fn find_toolchain() -> Option<Toolchain> {
    let home = std::env::var("HOME").unwrap_or_default();
    let nargo = which("nargo", &[format!("{home}/.nargo/bin/nargo")])?;
    let bb = which("bb", &[format!("{home}/.bb/bb")])?;
    Some(Toolchain { nargo, bb })
}

fn which(name: &str, extra: &[String]) -> Option<PathBuf> {
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            let p = Path::new(dir).join(name);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    extra.iter().map(PathBuf::from).find(|p| p.is_file())
}

pub fn run(program: &Path, args: &[&str], cwd: &Path) -> Result<()> {
    let out = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .output()
        .with_context(|| format!("running {}", program.display()))?;
    if !out.status.success() {
        bail!(
            "{} {} failed:\n{}{}",
            program.display(),
            args.join(" "),
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout)
        );
    }
    Ok(())
}

/// The circuit, carried in the binary.
///
/// Proving used to run inside the repo's own circuit directory. That made
/// `krep prove` work from a checkout and nowhere else — and worse, it left
/// `Prover.toml` in the source tree, which holds the pseudonym and every
/// attestation body in full. A command whose purpose is to reveal none of that
/// should not write all of it to disk next to a `.git`.
///
/// Eleven kilobytes of Noir is a cheap thing for the binary to carry, and it
/// also pins what was proved: the circuit cannot be swapped underneath a proof
/// by editing files beside it.
const CIRCUIT_FILES: &[(&str, &str)] = &[
    ("Nargo.toml", include_str!("../../krep-zk/circuit/Nargo.toml")),
    ("src/main.nr", include_str!("../../krep-zk/circuit/src/main.nr")),
    ("src/attestation.nr", include_str!("../../krep-zk/circuit/src/attestation.nr")),
    ("src/hash.nr", include_str!("../../krep-zk/circuit/src/hash.nr")),
];

/// A scratch copy of the circuit, removed when it goes out of scope.
///
/// The witness lives in here, so leaving it behind on the failure paths would
/// undo the point of moving it out of the repo. `Drop` covers the `?` returns
/// that an explicit cleanup at the end of the happy path would miss.
pub struct Scratch(PathBuf);

impl Scratch {
    pub fn new(tag: &str) -> Result<Scratch> {
        let dir = std::env::temp_dir().join(format!("krep-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src"))?;
        for (name, body) in CIRCUIT_FILES {
            std::fs::write(dir.join(name), body)?;
        }
        Ok(Scratch(dir))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use krep_core::{countersign, create_partial, derive_context_keypair, AttestationBody, Outpoint, Role};
    use krep_core::chain::Chain;
    use secp256k1::Keypair;

    fn kp(tag: &str) -> Keypair {
        let mut seed = [0u8; 32];
        seed[..tag.len()].copy_from_slice(tag.as_bytes());
        derive_context_keypair(&seed, "test")
    }

    fn chain_with(owner: &Keypair, cp: &Keypair, outcome: Outcome, txid: [u8; 32]) -> Chain {
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
        let att = countersign(cp, create_partial(owner, body).unwrap()).unwrap();
        let mut chain = Chain::new(owner.x_only_public_key().0);
        chain.append(att).unwrap();
        chain
    }

    fn accumulators(chain: &Chain, defaulted: Vec<[u8; 32]>) -> (MerkleTree, SparseMerkleTree) {
        let mut leaves: Vec<Vec<u8>> = chain
            .attestations
            .iter()
            .map(|a| anchor_leaf(&a.body.anchor.txid, a.body.anchor.index, &a.id()))
            .collect();
        // Padding, so the subject is not the only thing in the tree.
        for i in 0..7u8 {
            leaves.push(anchor_leaf(&[i; 32], 0, &[i.wrapping_add(40); 32]));
        }
        (MerkleTree::build_fixed_depth(leaves, ANCHOR_DEPTH), SparseMerkleTree::from_keys(defaulted))
    }

    #[test]
    fn witness_carries_the_real_path_and_the_real_pseudonym() {
        let (me, buyer) = (kp("me"), kp("buyer"));
        let chain = chain_with(&me, &buyer, Outcome::Success, [0x31; 32]);
        let (anchored, defaults) = accumulators(&chain, vec![]);
        let w = witness(&chain, &anchored, &defaults, 1).unwrap();
        assert_eq!(w.used, 1);
        assert_eq!(w.pseudonym, me.x_only_public_key().0.serialize());
        assert!(w.toml.contains("min_successes = \"1\""));
        // A path for every level the circuit walks, and every one filled.
        assert!(w.toml.matches("0x").count() >= ANCHOR_DEPTH + krep_zk::smt::DEPTH);
    }

    #[test]
    fn a_defaulter_cannot_build_a_witness_at_all() {
        // The refusal belongs here, not only in the circuit: a prover should be
        // told what is false about their claim, not handed a proof that fails.
        let (me, buyer) = (kp("slashed"), kp("buyer"));
        let chain = chain_with(&me, &buyer, Outcome::Success, [0x41; 32]);
        let (anchored, defaults) =
            accumulators(&chain, vec![me.x_only_public_key().0.serialize()]);
        let err = witness(&chain, &anchored, &defaults, 1).unwrap_err().to_string();
        assert!(err.contains("recorded as having defaulted"), "{err}");
    }

    #[test]
    fn claiming_more_successes_than_exist_is_refused() {
        let (me, buyer) = (kp("thin"), kp("buyer"));
        let chain = chain_with(&me, &buyer, Outcome::Success, [0x51; 32]);
        let (anchored, defaults) = accumulators(&chain, vec![]);
        let err = witness(&chain, &anchored, &defaults, 3).unwrap_err().to_string();
        assert!(err.contains("only 1 anchored success"), "{err}");
    }

    #[test]
    fn an_unanchored_success_is_refused_rather_than_padded_around() {
        // The chain verifies and the signatures are real; the settlement simply
        // is not in the set. Silently skipping it would let a prover claim a
        // number of successes the accumulator does not support.
        let (me, buyer) = (kp("ghost"), kp("buyer"));
        let chain = chain_with(&me, &buyer, Outcome::Success, [0x61; 32]);
        let (_, defaults) = accumulators(&chain, vec![]);
        let elsewhere = MerkleTree::build_fixed_depth(
            (0..8u8).map(|i| anchor_leaf(&[i; 32], 0, &[i; 32])).collect::<Vec<_>>(),
            ANCHOR_DEPTH,
        );
        let err = witness(&chain, &elsewhere, &defaults, 1).unwrap_err().to_string();
        assert!(err.contains("not in the anchored set"), "{err}");
    }

    #[test]
    fn a_saved_scan_rebuilds_to_the_same_roots() {
        let (me, buyer) = (kp("saved"), kp("buyer"));
        let chain = chain_with(&me, &buyer, Outcome::Success, [0x71; 32]);
        let (anchored, defaults) = accumulators(&chain, vec![[9u8; 32]]);
        let file = RootsFile {
            depth: ANCHOR_DEPTH,
            complete: true,
            anchored_root: to_hex(&anchored.root().unwrap()),
            defaults_root: to_hex(&defaults.root()),
            anchored_leaves: chain
                .attestations
                .iter()
                .map(|a| hex::encode(anchor_leaf(&a.body.anchor.txid, a.body.anchor.index, &a.id())))
                .chain((0..7u8).map(|i| hex::encode(anchor_leaf(&[i; 32], 0, &[i.wrapping_add(40); 32]))))
                .collect(),
            defaulted: vec![hex::encode([9u8; 32])],
        };
        let (a2, d2) = file.trees().unwrap();
        assert_eq!(a2.root(), anchored.root());
        assert_eq!(d2.root(), defaults.root());
    }

    #[test]
    fn an_edited_scan_is_caught_when_rebuilt() {
        // Someone who could pass off an altered accumulator could prove
        // membership of anything they liked.
        let (me, buyer) = (kp("edited"), kp("buyer"));
        let chain = chain_with(&me, &buyer, Outcome::Success, [0x81; 32]);
        let (anchored, defaults) = accumulators(&chain, vec![]);
        let mut file = RootsFile {
            depth: ANCHOR_DEPTH,
            complete: true,
            anchored_root: to_hex(&anchored.root().unwrap()),
            defaults_root: to_hex(&defaults.root()),
            anchored_leaves: vec![hex::encode(anchor_leaf(&[1u8; 32], 0, &[2u8; 32]))],
            defaulted: vec![],
        };
        assert!(file.trees().unwrap_err().to_string().contains("anchored root"));

        // Repair the anchored side, then break only the defaults side: a
        // pseudonym quietly dropped from the list is how a defaulter would make
        // themselves absent, and it has to be caught by the root and not by
        // anything that trusts the list.
        file.anchored_root = to_hex(&MerkleTree::build_fixed_depth(
            vec![anchor_leaf(&[1u8; 32], 0, &[2u8; 32])],
            ANCHOR_DEPTH,
        )
        .root()
        .unwrap());
        file.defaults_root = to_hex(&SparseMerkleTree::from_keys([[7u8; 32]]).root());
        assert!(file.trees().unwrap_err().to_string().contains("defaults root"));
    }

    #[test]
    fn public_inputs_are_three_big_endian_fields() {
        let a = Field::from(1u128);
        let b = Field::from(2u128);
        let pi = public_inputs(&a, &b, 3);
        assert_eq!(pi.len(), PUBLIC_INPUT_BYTES);
        assert_eq!(pi[31], 1);
        assert_eq!(pi[63], 2);
        assert_eq!(pi[95], 3);
        assert!(pi[..31].iter().all(|&b| b == 0));
    }
}
