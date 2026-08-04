//! Building the M6 accumulators from a live node.
//!
//! The selective-disclosure proof is only meaningful because both roots are
//! *reproducible*: the verifier rebuilds them from chain data rather than
//! accepting whatever the prover offers. Without this, "a global root anyone
//! can maintain" is an assertion. This is the code that makes it true.
//!
//! Both derivations reuse the pure rules in `krep_zk::scan`, so what a verifier
//! computes here and what a prover proved against cannot drift apart.

use anyhow::{anyhow, Result};
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_rpc_core::RpcHash;
use krep_zk::merkle::MerkleTree;
use krep_zk::scan::{branch_selector, default_from_spend, leaves_for_tx};
use krep_zk::smt::SparseMerkleTree;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Selector of the escrow covenant's slash branch.
pub const SLASH_SELECTOR: i64 = 7;

pub struct Roots {
    pub anchored: MerkleTree,
    pub defaults: SparseMerkleTree,
    pub blocks_scanned: usize,
    pub accepted_txs: usize,
    pub reached_tip: bool,
}

/// A chain block roughly `back` batches before the tip.
///
/// Walking the chain *without* acceptance data is cheap — the node returns
/// hashes only — so this finds a recent starting point in seconds, where
/// scanning bodies from the pruning point would take many minutes on a 10 BPS
/// chain. It is a convenience for inspecting recent settlements, not a
/// substitute for a full rebuild.
pub async fn recent_start(rpc: &Arc<dyn RpcApi>, back: usize) -> Result<RpcHash> {
    let dag = rpc.get_block_dag_info().await.map_err(|e| anyhow!("get_block_dag_info: {e}"))?;
    let mut marks = vec![dag.pruning_point_hash];
    let mut cursor = dag.pruning_point_hash;
    loop {
        let resp = rpc
            .get_virtual_chain_from_block(cursor, false, None)
            .await
            .map_err(|e| anyhow!("get_virtual_chain_from_block: {e}"))?;
        match resp.added_chain_block_hashes.last() {
            Some(&last) if last != cursor => {
                cursor = last;
                marks.push(cursor);
            }
            _ => break,
        }
    }
    Ok(marks[marks.len().saturating_sub(back.max(1))])
}

/// Scan forward from `start`, accumulating both sets.
///
/// Two bulk passes rather than one chatty one. Acceptance comes from the
/// virtual chain, which returns ids only; bodies come from `get_blocks`, which
/// returns a whole mergeset per call. Fetching blocks individually — the
/// obvious way to write this — cost about four minutes per batch on a 10 BPS
/// chain, which would put a full rebuild at over a day and make "anyone can
/// maintain this" untrue in practice.
///
/// Bounded by `max_batches` for the same reason the anchor verifier is: a scan
/// that runs out of budget must say so rather than quietly present a partial
/// accumulator as complete. A partial anchored root is worse than none —
/// proofs from honest provers whose settlement fell outside the window fail.
pub async fn build(
    rpc: &Arc<dyn RpcApi>,
    start: RpcHash,
    max_batches: usize,
    depth: usize,
) -> Result<Roots> {
    // Pass one: which transactions were accepted, and how far the window runs.
    let mut accepted: HashSet<RpcHash> = HashSet::new();
    let mut cursor = start;
    let mut reached_tip = false;
    for _ in 0..max_batches {
        let batch = rpc
            .get_virtual_chain_from_block(cursor, true, None)
            .await
            .map_err(|e| anyhow!("get_virtual_chain_from_block: {e}"))?;
        for entry in &batch.accepted_transaction_ids {
            accepted.extend(entry.accepted_transaction_ids.iter().copied());
        }
        match batch.added_chain_block_hashes.last() {
            Some(&last) if last != cursor => cursor = last,
            _ => {
                reached_tip = true;
                break;
            }
        }
    }
    let end = cursor;

    // Pass two: bodies in bulk, keeping only what was accepted.
    let mut leaves: Vec<Vec<u8>> = Vec::new();
    let mut defaulted: Vec<[u8; 32]> = Vec::new();
    let mut payloads: HashMap<RpcHash, Vec<u8>> = HashMap::new();
    let mut pending_slashes: Vec<(RpcHash, Vec<u8>)> = Vec::new();
    let mut blocks_scanned = 0usize;
    let mut accepted_txs = 0usize;
    let mut low = Some(start);

    loop {
        let resp = rpc.get_blocks(low, true, true).await.map_err(|e| anyhow!("get_blocks: {e}"))?;
        if resp.blocks.is_empty() {
            break;
        }
        blocks_scanned += resp.blocks.len();
        let mut past_end = false;
        for block in &resp.blocks {
            for tx in &block.transactions {
                let Some(vd) = tx.verbose_data.as_ref() else { continue };
                // Every transaction's payload is worth remembering: a slash
                // needs the payload of the escrow it spends, which was accepted
                // earlier in this same window.
                payloads.insert(vd.transaction_id, tx.payload.clone());
                if !accepted.contains(&vd.transaction_id) {
                    continue;
                }
                accepted_txs += 1;

                let spent: Vec<([u8; 32], u32)> = tx
                    .inputs
                    .iter()
                    .map(|i| (i.previous_outpoint.transaction_id.as_bytes(), i.previous_outpoint.index))
                    .collect();
                leaves.extend(leaves_for_tx(&spent, &tx.payload));

                for input in &tx.inputs {
                    if branch_selector(&input.signature_script) == Some(SLASH_SELECTOR) {
                        pending_slashes
                            .push((input.previous_outpoint.transaction_id, input.signature_script.clone()));
                    }
                }
            }
            if block.verbose_data.as_ref().map(|v| v.hash) == Some(end) {
                past_end = true;
            }
        }
        // `get_blocks` walks toward the tip regardless of where the acceptance
        // window ended, so without a bound the second pass ignores
        // --max-batches entirely and scans the whole remaining chain.
        if past_end {
            break;
        }
        match resp.block_hashes.last() {
            Some(&last) if Some(last) != low => low = Some(last),
            _ => break,
        }
    }

    // Resolve slashes once every payload in the window is known, since an
    // escrow is always created before it is slashed but may appear later in
    // block order.
    for (escrow_txid, sig_script) in pending_slashes {
        if let Some(escrow_payload) = payloads.get(&escrow_txid) {
            if let Some(rep) = default_from_spend(escrow_payload, &sig_script, SLASH_SELECTOR) {
                defaulted.push(rep);
            }
        }
    }

    Ok(Roots {
        anchored: MerkleTree::build_fixed_depth(leaves, depth),
        defaults: SparseMerkleTree::from_keys(defaulted),
        blocks_scanned,
        accepted_txs,
        reached_tip,
    })
}
