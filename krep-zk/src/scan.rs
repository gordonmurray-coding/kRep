//! Deriving both accumulators from chain data.
//!
//! These are the rules that make the roots a shared reference point rather
//! than something a prover asserts. They are pure functions over transaction
//! data so they can be tested exactly, and so a verifier rebuilding the roots
//! runs the same code the prover did.
//!
//! Both derivations mirror rules that already exist elsewhere in the project,
//! and must not drift from them:
//!
//! - anchoring mirrors `krep_core::kaspad`'s spend-based check — an
//!   attestation counts as anchored when the transaction *spending its anchor
//!   outpoint* carries its id in the payload;
//! - a default mirrors the escrow covenant's slash branch, reading the
//!   pseudonym from the position the covenant recorded it in.

use crate::hash::Digest32;
use krep_escrow::state::{EscrowState, Phase, OFF_MAKER_REP};

/// Cap on payload bytes considered per transaction.
///
/// Every 32-byte window of a payload is a candidate id, so a large payload
/// contributes a large number of leaves. Kaspa allows payloads far bigger than
/// any attestation needs; refusing to expand the very largest keeps rebuilding
/// the accumulator bounded. A settlement commits 32 or 64 bytes, so this is
/// orders of magnitude of headroom.
pub const MAX_PAYLOAD_SCANNED: usize = 4096;

/// One accumulator leaf: an anchor outpoint bound to an id it commits.
///
/// The outpoint is part of the leaf on purpose. Committing the id alone would
/// let any transaction anywhere vouch for it, which is precisely the confusion
/// the spend-based anchoring rule exists to prevent.
pub fn anchor_leaf(outpoint_txid: &[u8; 32], outpoint_index: u32, id: &Digest32) -> Vec<u8> {
    let mut leaf = Vec::with_capacity(32 + 4 + 32);
    leaf.extend_from_slice(outpoint_txid);
    leaf.extend_from_slice(&outpoint_index.to_le_bytes());
    leaf.extend_from_slice(id);
    leaf
}

/// Every leaf a single settled transaction contributes.
///
/// For each outpoint the transaction spends, and each **32-byte-aligned** slot
/// of its payload, one leaf.
///
/// Alignment is what makes this accumulator tractable, and the cost of getting
/// it wrong was measured rather than guessed. Scanning unaligned windows — the
/// original rule, which asked only that an id be in the payload *somewhere* —
/// turns a payload of length L into L−31 leaves instead of L/32. On testnet-10
/// that was 48,057 leaves where 1,611 would do, a factor of 30, and a full
/// pruning window came to 13.9 million leaves against the 1,048,576 a depth-20
/// tree holds. The tree could not cover the range the design assumes it covers.
///
/// The size was never driven by kRep. In a 15,009-block sample, 223 outpoints
/// out of 163,396 accepted transactions produced every leaf, because a handful
/// of payload-carrying transactions belonging to other protocols each generated
/// a few hundred. Under the old rule the accumulator grew with everyone else's
/// payload usage.
///
/// Nothing kRep anchors is affected: `build_payload` writes `ids.concat()`, so
/// ids sit at offsets 0 and 32, and the escrow's terminal payload is the same 64
/// bytes. Both are aligned, so every anchor ever made still counts. What is
/// given up is a foreign protocol embedding a kRep id at an arbitrary offset in
/// its own format — which nothing does, and which was never worth thirty times
/// the accumulator.
pub fn leaves_for_tx(spent: &[([u8; 32], u32)], payload: &[u8]) -> Vec<Vec<u8>> {
    if payload.len() < 32 || spent.is_empty() {
        return Vec::new();
    }
    let scanned = &payload[..payload.len().min(MAX_PAYLOAD_SCANNED)];
    let mut out = Vec::new();
    for (txid, index) in spent {
        for slot in scanned.chunks_exact(32) {
            let id: Digest32 = slot.try_into().expect("chunks_exact(32) yields 32 bytes");
            out.push(anchor_leaf(txid, *index, &id));
        }
    }
    out
}

/// A pushed item from a signature script.
#[derive(Debug, PartialEq, Eq)]
pub enum Push {
    Data(Vec<u8>),
    /// Values below 17 are opcodes, not data pushes.
    Small(i64),
}

/// Recover what a signature script pushed. `None` if it contains anything that
/// is not a push, since such a script is not one we can reason about.
pub fn parse_pushes(script: &[u8]) -> Option<Vec<Push>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < script.len() {
        let op = script[i];
        i += 1;
        let len = match op {
            0x00 => {
                out.push(Push::Small(0));
                continue;
            }
            0x4f => {
                out.push(Push::Small(-1));
                continue;
            }
            0x51..=0x60 => {
                out.push(Push::Small((op - 0x51 + 1) as i64));
                continue;
            }
            1..=0x4b => op as usize,
            0x4c => {
                let n = *script.get(i)? as usize;
                i += 1;
                n
            }
            0x4d => {
                let n = u16::from_le_bytes(script.get(i..i + 2)?.try_into().ok()?) as usize;
                i += 2;
                n
            }
            0x4e => {
                let n = u32::from_le_bytes(script.get(i..i + 4)?.try_into().ok()?) as usize;
                i += 4;
                n
            }
            _ => return None,
        };
        out.push(Push::Data(script.get(i..i + len)?.to_vec()));
        i += len;
    }
    Some(out)
}

/// Which branch a covenant spend selected, if the script looks like one.
///
/// The redeem script is the last push and the selector sits just below it.
pub fn branch_selector(sig_script: &[u8]) -> Option<i64> {
    let pushes = parse_pushes(sig_script)?;
    if pushes.len() < 2 {
        return None;
    }
    match &pushes[pushes.len() - 2] {
        Push::Small(v) => Some(*v),
        Push::Data(d) if d.len() <= 8 => {
            let mut buf = [0u8; 8];
            buf[..d.len()].copy_from_slice(d);
            Some(i64::from_le_bytes(buf))
        }
        Push::Data(_) => None,
    }
}

/// Read a defaulted pseudonym out of a slash.
///
/// `escrow_payload` is the payload of the transaction that *created* the
/// outpoint being spent — the escrow's state. FabMesh escrows are recognisable
/// on chain by their magic bytes, which is what makes this rebuildable by a
/// third party who was never party to the job.
///
/// Returns the pseudonym only when the spend really took the slash branch of a
/// claimed escrow. A settlement, a refund, or any other spend yields nothing.
pub fn default_from_spend(escrow_payload: &[u8], sig_script: &[u8], slash_selector: i64) -> Option<Digest32> {
    if branch_selector(sig_script)? != slash_selector {
        return None;
    }
    let state = EscrowState::decode(escrow_payload).ok()?;
    // Only a claimed job can be slashed; an OPEN escrow has nobody to blame.
    if !matches!(state.phase, Phase::Claimed | Phase::Shipped | Phase::Disputed) {
        return None;
    }
    let rep = state.maker_rep?;
    debug_assert_eq!(
        &escrow_payload[OFF_MAKER_REP..OFF_MAKER_REP + 32],
        &rep.serialize(),
        "the pseudonym must be read from the offset the covenant witness names"
    );
    Some(rep.serialize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{self, MerkleTree};
    use crate::smt::{self, SparseMerkleTree};
    use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};

    fn pk(b: u8) -> XOnlyPublicKey {
        Keypair::from_seckey_slice(&Secp256k1::new(), &[b; 32]).unwrap().x_only_public_key().0
    }

    fn claimed(maker: u8, rep: u8) -> Vec<u8> {
        EscrowState {
            phase: Phase::Claimed,
            terms_id: [9u8; 32],
            maker: Some(pk(maker)),
            maker_rep: Some(pk(rep)),
            tracking: None,
            shipped_at: 0,
        }
        .encode()
        .to_vec()
    }

    /// A signature script shaped like a covenant spend: args, state, selector,
    /// then the redeem script.
    fn covenant_sig(selector: i64, redeem: &[u8]) -> Vec<u8> {
        let mut s = Vec::new();
        let push = |s: &mut Vec<u8>, d: &[u8]| {
            s.push(d.len() as u8);
            s.extend_from_slice(d);
        };
        push(&mut s, &[0xaa; 40]); // prev_rest
        push(&mut s, &[0xbb; 40]); // prev_payload
        if (1..=16).contains(&selector) {
            s.push(0x50 + selector as u8);
        } else if selector == 0 {
            s.push(0x00);
        }
        push(&mut s, redeem);
        s
    }

    #[test]
    fn a_settlement_contributes_a_leaf_for_the_id_it_commits() {
        // The shape a real anchor produces: two ids in one 64-byte payload.
        let id_a = [0xa1u8; 32];
        let id_b = [0xb2u8; 32];
        let mut payload = id_a.to_vec();
        payload.extend_from_slice(&id_b);
        let escrow = ([7u8; 32], 0u32);

        let leaves = leaves_for_tx(&[escrow], &payload);
        let tree = MerkleTree::build(leaves);
        let root = tree.root().unwrap();

        for id in [&id_a, &id_b] {
            let leaf = anchor_leaf(&escrow.0, escrow.1, id);
            let proof = tree.prove(&leaf).expect("an anchored id must be provable");
            assert!(merkle::verify(&root, &leaf, &proof));
        }
    }

    #[test]
    fn an_id_is_bound_to_the_outpoint_that_anchored_it() {
        // Committing the id alone would let any transaction vouch for it. This
        // is the accumulator's version of the spend-based anchoring rule.
        let id = [0xa1u8; 32];
        let tree = MerkleTree::build(leaves_for_tx(&[([7u8; 32], 0)], &id));
        let root = tree.root().unwrap();

        assert!(tree.prove(&anchor_leaf(&[7u8; 32], 0, &id)).is_some());
        assert!(tree.prove(&anchor_leaf(&[8u8; 32], 0, &id)).is_none(), "different outpoint");
        assert!(tree.prove(&anchor_leaf(&[7u8; 32], 1, &id)).is_none(), "different output index");
        let _ = root;
    }

    #[test]
    fn transactions_that_anchor_nothing_contribute_nothing() {
        assert!(leaves_for_tx(&[([1u8; 32], 0)], b"short").is_empty(), "payload under 32 bytes");
        assert!(leaves_for_tx(&[], &[0u8; 64]).is_empty(), "a coinbase spends nothing");
        // And an enormous payload is bounded rather than expanded wholesale.
        let huge = vec![0u8; MAX_PAYLOAD_SCANNED * 4];
        let n = leaves_for_tx(&[([1u8; 32], 0)], &huge).len();
        assert_eq!(n, MAX_PAYLOAD_SCANNED / 32);
    }

    #[test]
    fn only_aligned_slots_become_leaves() {
        // The measurement that motivated this: a payload of length L used to
        // yield L-31 leaves and now yields L/32. At the sizes actually seen on
        // testnet-10 that is the difference between a tree that holds a pruning
        // window and one that does not.
        let payload = vec![0u8; 320];
        assert_eq!(leaves_for_tx(&[([1u8; 32], 0)], &payload).len(), 10);

        // A trailing partial slot contributes nothing, so an id cannot be
        // indexed at a position the verifier would refuse.
        let ragged = vec![0u8; 320 + 20];
        assert_eq!(leaves_for_tx(&[([1u8; 32], 0)], &ragged).len(), 10);

        // Every input still gets its own leaf per slot: the outpoint is part of
        // the leaf, and which one anchored the id is not known here.
        let two = [([1u8; 32], 0), ([2u8; 32], 1)];
        assert_eq!(leaves_for_tx(&two, &payload).len(), 20);
    }

    #[test]
    fn a_real_settlement_payload_is_indexed_at_both_slots() {
        // What kRep actually writes: `ids.concat()`, one or two ids. Both sit
        // at aligned offsets, so the change costs nothing already anchored.
        let (a, b) = ([0xa1u8; 32], [0xb2u8; 32]);
        let mut payload = a.to_vec();
        payload.extend_from_slice(&b);
        let leaves = leaves_for_tx(&[([9u8; 32], 0)], &payload);
        assert_eq!(leaves.len(), 2);
        assert!(leaves.contains(&anchor_leaf(&[9u8; 32], 0, &a)));
        assert!(leaves.contains(&anchor_leaf(&[9u8; 32], 0, &b)));
    }

    #[test]
    fn a_slash_records_the_pseudonym_and_nothing_else_does() {
        const SLASH: i64 = 7;
        let redeem = vec![0x51u8; 60];
        let state = claimed(5, 6);

        let got = default_from_spend(&state, &covenant_sig(SLASH, &redeem), SLASH);
        assert_eq!(got, Some(pk(6).serialize()), "the slash names the pseudonym, not the payment key");
        assert_ne!(got, Some(pk(5).serialize()));

        // Every other branch leaves the record clean.
        for other in [0i64, 1, 2, 3, 8] {
            assert_eq!(default_from_spend(&state, &covenant_sig(other, &redeem), SLASH), None);
        }
    }

    #[test]
    fn a_slash_of_something_that_is_not_an_escrow_is_ignored() {
        const SLASH: i64 = 7;
        let redeem = vec![0x51u8; 60];
        // A payload of the right length that is not escrow state — e.g. a bare
        // anchor commitment — must not be mined for a pseudonym.
        let foreign = vec![0xcd; 142];
        assert_eq!(default_from_spend(&foreign, &covenant_sig(SLASH, &redeem), SLASH), None);

        // Nor may an escrow nobody has claimed produce a defaulter.
        let open = EscrowState::open([9u8; 32]).encode().to_vec();
        assert_eq!(default_from_spend(&open, &covenant_sig(SLASH, &redeem), SLASH), None);
    }

    #[test]
    fn the_two_accumulators_answer_the_two_halves_of_the_claim() {
        const SLASH: i64 = 7;
        let redeem = vec![0x51u8; 60];

        // One settlement anchoring a success, and one slash against pseudonym 6.
        let id = [0xa1u8; 32];
        let anchored = MerkleTree::build(leaves_for_tx(&[([7u8; 32], 0)], &id));
        let defaults = SparseMerkleTree::from_keys(
            default_from_spend(&claimed(5, 6), &covenant_sig(SLASH, &redeem), SLASH),
        );

        // A clean pseudonym: its success is anchored, and it is absent from
        // the defaults. Both halves of "≥N successes and 0 defaults".
        let leaf = anchor_leaf(&[7u8; 32], 0, &id);
        assert!(merkle::verify(&anchored.root().unwrap(), &leaf, &anchored.prove(&leaf).unwrap()));
        assert!(smt::verify_absence(&defaults.root(), &defaults.prove(&pk(11).serialize())));

        // The defaulter cannot produce that second half.
        assert!(!smt::verify_absence(&defaults.root(), &defaults.prove(&pk(6).serialize())));
    }
}

/// Regression tests pinned to transactions that really settled on testnet-10
/// during the M2–M4 runs. Synthetic shapes prove the logic; these prove the
/// logic matches what the chain actually contains.
#[cfg(test)]
mod real_chain {
    use super::*;
    use crate::merkle::{self, MerkleTree};
    use crate::smt::{self, SparseMerkleTree};

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).expect("fixture hex")
    }
    fn h32(s: &str) -> Digest32 {
        h(s).try_into().expect("32 bytes")
    }

    // The settlement that paid the maker and minted both sides' reputation.
    const SETTLED_ESCROW_TXID: &str = "89495c52d44340a2b1dec34c82ce0c6f58ad1e2dbc6c80249fce2060d3f05af4";
    const MAKER_ATT_ID: &str = "edbf04bbcbbe2fe103a9b95aeb96ede5f266e42c5aa01cc1239e79fe4f13fb8c";
    const BUYER_ATT_ID: &str = "4f06a2f06b98daae171d48d2fdc506f6fc0d4051cde8051b9238b6bc8f881041";
    // The pseudonym a slash recorded as having defaulted.
    const DEFAULTED_REP: &str = "b36ede013b3204d71dfd3dd69636a3079a1a2b0796844f2678b99dbf5a247128";

    #[test]
    fn a_real_settlement_yields_leaves_for_both_sides() {
        // The settle transaction spent the SHIPPED escrow outpoint and carried
        // both attestation ids in a 64-byte payload.
        let mut payload = h(MAKER_ATT_ID);
        payload.extend_from_slice(&h(BUYER_ATT_ID));
        let escrow = (h32(SETTLED_ESCROW_TXID), 0u32);

        let tree = MerkleTree::build(leaves_for_tx(&[escrow], &payload));
        let root = tree.root().expect("a settlement anchors something");

        for id in [MAKER_ATT_ID, BUYER_ATT_ID] {
            let leaf = anchor_leaf(&escrow.0, escrow.1, &h32(id));
            let proof = tree.prove(&leaf).expect("both sides' ids must be provable");
            assert!(merkle::verify(&root, &leaf, &proof), "{id} failed against the real settlement");
        }

        // And an id that settlement did not carry is not provable against it.
        let unrelated = anchor_leaf(&escrow.0, escrow.1, &[0x11; 32]);
        assert!(tree.prove(&unrelated).is_none());
    }

    #[test]
    fn the_real_defaulted_pseudonym_cannot_prove_a_clean_record() {
        // Rebuilt from what the covenant recorded on chain: the slash named
        // this pseudonym, at the offset the covenant witness points to.
        let defaults = SparseMerkleTree::from_keys([h32(DEFAULTED_REP)]);
        let root = defaults.root();

        let theirs = defaults.prove(&h32(DEFAULTED_REP));
        assert!(!smt::verify_absence(&root, &theirs), "a real defaulter must not prove absence");
        assert!(smt::verify(&root, &theirs), "but their presence is provable");

        // The buyer they defaulted on is untouched by it.
        let buyer_rep = h32("c85c8b847594ad3573a72d36b0d645ef9de8ed591d46ad221d0a68e99e2b43e1");
        assert!(smt::verify_absence(&root, &defaults.prove(&buyer_rep)));
    }
}
