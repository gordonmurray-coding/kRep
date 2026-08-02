//! Live anchor verification against a kaspad node.
//!
//! # Why this is a chain scan and not a lookup
//!
//! kaspad has **no transaction index**. There is no `getTransaction(txid)` RPC
//! (confirmed against rusty-kaspa v2.0.1: the closest thing, `get_headers`, is
//! `NotImplemented`). What the node does expose is:
//!
//! - `get_virtual_chain_from_block` — for each chain block, the ids of the
//!   transactions that block *accepted*. This is exactly the acceptance
//!   predicate we need, and it is batched (10 x mergeset_size_limit per call).
//! - `get_block` — a block's transactions, including their payloads, and the
//!   verbose data listing a chain block's mergeset.
//!
//! So resolving `txid -> (accepted?, payload)` means walking the selected
//! parent chain forward, watching the accepted-id sets go by, and only when a
//! wanted id shows up, descending into that accepting block's mergeset to pull
//! the transaction body out.
//!
//! Two consequences worth stating plainly rather than hiding:
//!
//! 1. **The node's history is finite.** Kaspad prunes. Nothing before the
//!    pruning point can be verified by a pruning node at all — not "verified
//!    false", *unverifiable*. Old chains need an archival node, and this module
//!    reports that case as an error rather than silently reporting "unanchored".
//! 2. **Scanning costs round trips.** Verifying an N-attestation chain must not
//!    cost N scans, so [`KaspadAnchorVerifier::prefetch`] resolves every anchor
//!    in a chain in a single pass. Callers verifying a whole chain should use it.
//!
//! Nothing here relies on a third-party indexer or explorer API: the only
//! trusted party is the node operator, which for a self-hosted node is you.

use crate::{AnchorVerifier, Outpoint};
use kaspa_rpc_core::RpcHash;
use kaspa_rpc_core::api::rpc::RpcApi;
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::{Arc, Mutex};
use tokio::runtime::Handle;

/// Bounds on the selected-parent-chain scan.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Chain block to start scanning from. `None` means the node's pruning
    /// point — i.e. the whole history this node still has.
    pub scan_from: Option<RpcHash>,
    /// Maximum `get_virtual_chain_from_block` batches before giving up. Each
    /// batch covers up to 10 x mergeset_size_limit merged blocks.
    ///
    /// This is a runaway guard, not a tuning knob: the scan stops on its own
    /// when it reaches the virtual tip. Measured against a synced mainnet node
    /// (2026-08), a full pruning-point-to-tip scan *with* acceptance data took
    /// 471 batches in ~19s over LAN gRPC. (Without acceptance data the same
    /// history is only 76 batches — with it, each batch is bounded by merged
    /// blocks rather than chain blocks, so budget in the larger number.)
    ///
    /// The default sits far above the measurement because stopping early is the
    /// dangerous failure: the scan runs oldest-to-newest, so a premature cap
    /// blinds the verifier to exactly the recent anchors it is most often asked
    /// about. Exceeding the cap is reported as an explicit "ran out of budget"
    /// error, never as "not anchored".
    pub max_batches: usize,
    /// Acceptance depth required before an anchor counts. 0 accepts anything
    /// the virtual chain currently includes, which can still be reorged.
    /// At 10 BPS the default is on the order of ten seconds of chain.
    pub min_confirmations: u64,
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig { scan_from: None, max_batches: 4096, min_confirmations: 100 }
    }
}

/// What the node told us about one accepted anchor transaction.
#[derive(Debug, Clone)]
struct AnchorTx {
    payload: Vec<u8>,
    output_count: usize,
    accepting_block: RpcHash,
}

/// [`AnchorVerifier`] backed by a real kaspad node over wRPC (or gRPC — both
/// clients implement [`RpcApi`], and this type only needs the trait).
///
/// `is_anchored` is synchronous by trait contract while the RPC is async, so
/// this holds a tokio [`Handle`] and blocks on it. It must therefore be called
/// from a synchronous context — blocking on a handle from inside an async task
/// on the same runtime will panic.
pub struct KaspadAnchorVerifier {
    rpc: Arc<dyn RpcApi>,
    handle: Handle,
    cfg: ScanConfig,
    /// txid -> resolution. `None` means "scanned for and genuinely absent".
    resolved: Mutex<HashMap<RpcHash, Option<AnchorTx>>>,
    /// Outcome of the most recent scan, for accurate diagnostics.
    last_scan: Mutex<Option<ScanOutcome>>,
}

/// How far the last scan actually got. The difference between "I searched the
/// node's whole history" and "I ran out of budget" is the difference between a
/// meaningful absence and no information at all.
#[derive(Debug, Clone, Copy)]
struct ScanOutcome {
    batches: usize,
    reached_tip: bool,
}

impl KaspadAnchorVerifier {
    pub fn new(rpc: Arc<dyn RpcApi>, handle: Handle, cfg: ScanConfig) -> Self {
        KaspadAnchorVerifier {
            rpc,
            handle,
            cfg,
            resolved: Mutex::new(HashMap::new()),
            last_scan: Mutex::new(None),
        }
    }

    /// Resolve every anchor in one chain scan.
    ///
    /// Call this before [`crate::chain::Chain::verify_anchored`]; without it,
    /// each attestation triggers its own scan.
    pub fn prefetch<'a, I: IntoIterator<Item = &'a Outpoint>>(&self, anchors: I) -> io::Result<()> {
        let wanted: HashSet<RpcHash> = anchors.into_iter().map(|a| RpcHash::from_bytes(a.txid)).collect();
        self.resolve_all(wanted)
    }

    /// Number of anchors resolved so far (diagnostics).
    pub fn cached(&self) -> usize {
        self.resolved.lock().unwrap().len()
    }

    fn resolve_all(&self, wanted: HashSet<RpcHash>) -> io::Result<()> {
        let missing: HashSet<RpcHash> = {
            let cache = self.resolved.lock().unwrap();
            wanted.into_iter().filter(|t| !cache.contains_key(t)).collect()
        };
        if missing.is_empty() {
            return Ok(());
        }
        let (found, outcome) = self.handle.block_on(self.scan(&missing))?;
        *self.last_scan.lock().unwrap() = Some(outcome);
        let mut cache = self.resolved.lock().unwrap();
        for txid in missing {
            match found.get(&txid) {
                Some(tx) => {
                    cache.insert(txid, Some(tx.clone()));
                }
                // Only remember an absence if the scan actually ran out of
                // chain rather than out of budget. Caching "not found" after a
                // truncated scan would turn a temporary blind spot into a
                // permanent verdict.
                None if outcome.reached_tip => {
                    cache.insert(txid, None);
                }
                None => {}
            }
        }
        Ok(())
    }

    /// Walk the selected parent chain, collecting the wanted transactions.
    async fn scan(&self, wanted: &HashSet<RpcHash>) -> io::Result<(HashMap<RpcHash, AnchorTx>, ScanOutcome)> {
        let dag = self.rpc.get_block_dag_info().await.map_err(rpc_err("get_block_dag_info"))?;
        let mut start = self.cfg.scan_from.unwrap_or(dag.pruning_point_hash);

        let mut remaining: HashSet<RpcHash> = wanted.clone();
        let mut found: HashMap<RpcHash, AnchorTx> = HashMap::new();
        let min_conf = (self.cfg.min_confirmations > 0).then_some(self.cfg.min_confirmations);

        let mut batches = 0usize;
        let mut reached_tip = false;
        for _ in 0..self.cfg.max_batches {
            batches += 1;
            let batch = self
                .rpc
                .get_virtual_chain_from_block(start, true, min_conf)
                .await
                .map_err(rpc_err("get_virtual_chain_from_block"))?;

            for accepted in &batch.accepted_transaction_ids {
                let hits: Vec<RpcHash> = accepted
                    .accepted_transaction_ids
                    .iter()
                    .filter(|id| remaining.contains(*id))
                    .copied()
                    .collect();
                for txid in hits {
                    if let Some(tx) = self.fetch_from_mergeset(accepted.accepting_block_hash, txid).await? {
                        found.insert(txid, tx);
                        remaining.remove(&txid);
                    }
                }
            }

            if remaining.is_empty() {
                // Everything we came for is resolved; how much chain is left
                // is irrelevant.
                reached_tip = true;
                break;
            }
            // No further chain blocks: we have reached the node's virtual tip
            // (as trimmed by min_confirmations).
            match batch.added_chain_block_hashes.last() {
                Some(&last) if last != start => start = last,
                _ => {
                    reached_tip = true;
                    break;
                }
            }
        }

        Ok((found, ScanOutcome { batches, reached_tip }))
    }

    /// The transaction accepted by `accepting` lives in that chain block's
    /// mergeset, not in the chain block itself. Find it there.
    ///
    /// Two passes on purpose: block-without-transactions responses are small
    /// and already carry `transaction_ids`, so only the one block that actually
    /// holds the transaction is fetched with its (potentially large) body.
    async fn fetch_from_mergeset(&self, accepting: RpcHash, txid: RpcHash) -> io::Result<Option<AnchorTx>> {
        let head = self.rpc.get_block(accepting, false).await.map_err(rpc_err("get_block"))?;
        let Some(verbose) = head.verbose_data else {
            return Err(io::Error::other(format!("node returned no verbose data for block {accepting}")));
        };

        let mergeset = verbose.merge_set_blues_hashes.iter().chain(verbose.merge_set_reds_hashes.iter());
        for &block_hash in mergeset {
            let block = self.rpc.get_block(block_hash, false).await.map_err(rpc_err("get_block"))?;
            let holds_it = block
                .verbose_data
                .as_ref()
                .is_some_and(|v| v.transaction_ids.contains(&txid));
            if !holds_it {
                continue;
            }
            let full = self.rpc.get_block(block_hash, true).await.map_err(rpc_err("get_block"))?;
            if let Some(tx) = full
                .transactions
                .iter()
                .find(|tx| tx.verbose_data.as_ref().is_some_and(|v| v.transaction_id == txid))
            {
                return Ok(Some(AnchorTx {
                    payload: tx.payload.clone(),
                    output_count: tx.outputs.len(),
                    accepting_block: accepting,
                }));
            }
        }
        Ok(None)
    }

    fn lookup(&self, txid: RpcHash) -> io::Result<Option<AnchorTx>> {
        if let Some(hit) = self.resolved.lock().unwrap().get(&txid) {
            return Ok(hit.clone());
        }
        self.resolve_all(HashSet::from([txid]))?;
        Ok(self.resolved.lock().unwrap().get(&txid).cloned().flatten())
    }
}

/// Does `payload` commit `id`?
///
/// Any 32-byte-aligned-or-not occurrence counts. This is deliberately
/// permissive: the payload format belongs to whatever settlement protocol paid
/// for the transaction (a FabMesh escrow release, a kUSD liquidation, a plain
/// `krep anchor`), and kRep only asks that the id be in there. Mirror
/// attestations put two ids in one 64-byte payload; both verify against the
/// same transaction.
pub fn payload_commits(payload: &[u8], id: &[u8; 32]) -> bool {
    payload.windows(32).any(|w| w == id)
}

impl AnchorVerifier for KaspadAnchorVerifier {
    fn is_anchored(&self, id: &[u8; 32], anchor: &Outpoint) -> io::Result<bool> {
        let txid = RpcHash::from_bytes(anchor.txid);
        let Some(tx) = self.lookup(txid)? else {
            // Not a negative result — an unknown one. Saying "unanchored" here
            // would slander a chain whose anchors are simply older than this
            // node's pruning point, or newer than min_confirmations.
            let from = self
                .cfg
                .scan_from
                .map(|h| h.to_string())
                .unwrap_or_else(|| "the pruning point".into());
            let outcome = *self.last_scan.lock().unwrap();
            let detail = match outcome {
                Some(o) if o.reached_tip => format!(
                    "scanned {} batches from {from} to the virtual tip. The transaction is not in \
                     the history this node retains — either it does not exist, or it is older than \
                     the pruning point, or it is within the most recent {} chain blocks excluded by \
                     --min-confirmations",
                    o.batches, self.cfg.min_confirmations
                ),
                Some(o) => format!(
                    "gave up after {} batches from {from} WITHOUT reaching the tip — the scan ran \
                     out of budget, not out of chain. Raise --max-batches",
                    o.batches
                ),
                None => format!("no scan was performed from {from}"),
            };
            return Err(io::Error::other(format!(
                "anchor tx {txid} could not be resolved: {detail}. \
                 Options: --scan-from <recent chain block>, --min-confirmations, --max-batches, \
                 or point --rpc at an archival node."
            )));
        };

        // The anchor names an output of the settlement tx; if that output does
        // not exist, the anchor is fabricated. This is a real negative.
        if anchor.index as usize >= tx.output_count {
            return Ok(false);
        }
        let _ = tx.accepting_block; // acceptance already proven by the scan
        Ok(payload_commits(&tx.payload, id))
    }
}

fn rpc_err(call: &'static str) -> impl Fn(kaspa_rpc_core::RpcError) -> io::Error {
    move |e| io::Error::other(format!("{call}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::payload_commits;

    #[test]
    fn payload_commitment_matching() {
        let id = [7u8; 32];
        assert!(!payload_commits(&[], &id));
        assert!(!payload_commits(&[7u8; 31], &id), "short payload cannot commit");
        assert!(payload_commits(&[7u8; 32], &id));

        // Exactly the mirror-attestation case: two ids in one 64-byte payload.
        let other = [9u8; 32];
        let mut both = Vec::new();
        both.extend_from_slice(&other);
        both.extend_from_slice(&id);
        assert!(payload_commits(&both, &id));
        assert!(payload_commits(&both, &other));
        assert!(!payload_commits(&both, &[1u8; 32]));

        // Unaligned placement inside a larger protocol payload still counts.
        let mut embedded = vec![0xde, 0xad, 0xbe];
        embedded.extend_from_slice(&id);
        embedded.extend_from_slice(b"trailing");
        assert!(payload_commits(&embedded, &id));
    }
}
