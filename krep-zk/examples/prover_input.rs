//! Emit a `Prover.toml` for the selective-disclosure circuit from real
//! accumulators, so the circuit is exercised against the same code a verifier
//! runs rather than against hand-written fixtures.

use krep_zk::hash::Field;
use krep_zk::merkle::MerkleTree;
use krep_zk::scan::anchor_leaf;
use krep_zk::smt::SparseMerkleTree;

const ANCHOR_DEPTH: usize = 20;
const MAX_SUCCESSES: usize = 4;

/// The field encoding of a leaf, matching what `hash_leaf` absorbs: 16-byte
/// chunks big-endian, then the byte length.
fn leaf_fields(leaf: &[u8]) -> Vec<Field> {
    let mut out = Vec::new();
    for chunk in leaf.chunks(16) {
        let mut buf = [0u8; 16];
        buf[16 - chunk.len()..].copy_from_slice(chunk);
        out.push(Field::from(u128::from_be_bytes(buf)));
    }
    out.push(Field::from(leaf.len() as u128));
    out
}

fn q(f: &Field) -> String {
    format!("\"{}\"", krep_zk::hash::to_hex(f))
}

fn h32(s: &str) -> [u8; 32] {
    hex::decode(s).expect("hex").try_into().expect("32 bytes")
}

fn main() {
    // A settlement that really anchored on testnet-10 during the M2-M4 runs.
    let escrow = h32("89495c52d44340a2b1dec34c82ce0c6f58ad1e2dbc6c80249fce2060d3f05af4");
    let maker_id = h32("edbf04bbcbbe2fe103a9b95aeb96ede5f266e42c5aa01cc1239e79fe4f13fb8c");
    let buyer_id = h32("4f06a2f06b98daae171d48d2fdc506f6fc0d4051cde8051b9238b6bc8f881041");

    let mine = anchor_leaf(&escrow, 0, &buyer_id);
    let mut all = vec![mine.clone(), anchor_leaf(&escrow, 0, &maker_id)];
    // Unrelated traffic, so the tree is not trivially small.
    for i in 0..30u8 {
        all.push(anchor_leaf(&[i; 32], 0, &[i.wrapping_add(9); 32]));
    }
    let tree = MerkleTree::build_fixed_depth(all, ANCHOR_DEPTH);
    let anchored_root = tree.root().expect("root");
    let proof = tree.prove(&mine).expect("our leaf is present");

    // The defaults tree, holding a pseudonym a real slash recorded.
    let defaults = SparseMerkleTree::from_keys([h32(
        "b36ede013b3204d71dfd3dd69636a3079a1a2b0796844f2678b99dbf5a247128",
    )]);
    // Whose reputation are we proving? The buyer never defaulted; the maker
    // did. Setting KREP_SUBJECT=defaulter emits the maker's case, which the
    // circuit must refuse to solve.
    let defaulter = h32("b36ede013b3204d71dfd3dd69636a3079a1a2b0796844f2678b99dbf5a247128");
    let clean = h32("c85c8b847594ad3573a72d36b0d645ef9de8ed591d46ad221d0a68e99e2b43e1");
    let subject =
        if std::env::var("KREP_SUBJECT").as_deref() == Ok("defaulter") { defaulter } else { clean };
    let smt_proof = defaults.prove(&subject);

    let fields = leaf_fields(&mine);
    let leaves: Vec<String> =
        (0..MAX_SUCCESSES).map(|_| format!("[{}]", fields.iter().map(q).collect::<Vec<_>>().join(", "))).collect();
    let path = format!("[{}]", proof.siblings.iter().map(q).collect::<Vec<_>>().join(", "));
    let paths: Vec<String> = (0..MAX_SUCCESSES).map(|_| path.clone()).collect();
    let indices: Vec<String> = (0..MAX_SUCCESSES)
        .map(|s| format!("\"{}\"", if s == 0 { proof.leaf_index } else { 0 }))
        .collect();

    let bits: Vec<String> = (0..256)
        .map(|level| {
            let idx = 255 - level;
            let set = subject[idx / 8] & (1 << (7 - (idx % 8))) != 0;
            format!("\"{}\"", u8::from(set))
        })
        .collect();

    println!("anchored_root = {}", q(&anchored_root));
    println!("defaults_root = {}", q(&defaults.root()));
    println!("min_successes = \"1\"");
    println!("used = \"1\"");
    println!("leaves = [{}]", leaves.join(", "));
    println!("leaf_paths = [{}]", paths.join(", "));
    println!("leaf_indices = [{}]", indices.join(", "));
    println!("pseudonym_bits = [{}]", bits.join(", "));
    println!("defaults_path = [{}]", smt_proof.siblings.iter().map(q).collect::<Vec<_>>().join(", "));
}
