//! Live anchor verification against a kaspad node.
//!
//! # What `anchor` means
//!
//! `anchor` is the outpoint the settlement transaction **spends** — SPEC 1.2's
//! `escrow_outpoint`, "txid:index of settled escrow". It is *not* the id of the
//! transaction that carries the commitment.
//!
//! That distinction is forced, not stylistic. If `anchor` named the
//! payload-carrying transaction itself, the protocol would be unbuildable: the
//! attestation id is `H(body ‖ signatures)` and `body` contains the anchor, so
//! committing the id in a transaction's payload would require knowing that
//! transaction's id before choosing its payload — and payload changes txid.
//! Naming the *spent* outpoint breaks the cycle, because the escrow output
//! exists before the settlement that consumes it:
//!
//! 1. an escrow (or any funded output) `O` exists
//! 2. both parties co-sign an attestation whose `anchor` is `O` → id
//! 3. the settlement transaction spends `O` and carries the id in its payload
//!
//! Verification runs that backwards: find the accepted transaction that spends
//! `O`, and check its payload commits the id.
//!
//! # Why this is a scan and not a lookup
//!
//! kaspad has **no transaction index**. There is no `getTransaction(txid)` RPC
//! (confirmed against rusty-kaspa v2.0.1: the closest thing, `get_headers`, is
//! `NotImplemented`), and there is certainly no "what spent this outpoint"
//! index. What the node does expose:
//!
//! - `get_virtual_chain_from_block` — per chain block, the ids of the
//!   transactions it *accepted*. Exactly the acceptance predicate we need, and
//!   cheap: ids only, batched.
//! - `get_blocks(low_hash, include_transactions)` — block bodies in bulk
//!   (~mergeset_size_limit per call), which is where inputs and payloads live.
//!
//! So resolving one anchor is two bounded phases:
//!
//! 1. **Locate the escrow.** Find `anchor.txid` in the accepted-id stream. This
//!    proves the outpoint's creating transaction was accepted, tells us it
//!    really has an output at `anchor.index`, and — crucially — gives a *start
//!    point*, since nothing can spend an output before it exists.
//! 2. **Find the spender.** Walk block bodies forward from there looking for a
//!    transaction whose input consumes `anchor`, then confirm that candidate
//!    was itself accepted (of two conflicting spends only one can be) and read
//!    its payload.
//!
//! Phase 2 is the expensive half, which is why phase 1's start point matters:
//! it turns "scan the chain" into "scan forward from the escrow".
//!
//! Two consequences worth stating plainly rather than hiding:
//!
//! 1. **The node's history is finite.** Kaspad prunes. Nothing before the
//!    pruning point can be verified by a pruning node at all — not "verified
//!    false", *unverifiable*. Old chains need an archival node, and this module
//!    reports that case as an error rather than silently reporting "unanchored".
//! 2. **Scanning costs round trips.** Verifying an N-attestation chain must not
//!    cost N chain scans, so [`KaspadAnchorVerifier::prefetch`] resolves every
//!    anchor's escrow in a single pass. Callers verifying a whole chain should
//!    use it.
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

/// Bounds on the scans.
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
    /// Budget, in blocks, for the body scan that hunts the spending
    /// transaction. Settlement normally follows its escrow closely, so this
    /// bounds the pathological case rather than the usual one.
    pub max_spend_scan_blocks: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig {
            scan_from: None,
            max_batches: 4096,
            min_confirmations: 100,
            max_spend_scan_blocks: 200_000,
        }
    }
}

/// What the node told us about an accepted transaction.
#[derive(Debug, Clone)]
struct AcceptedTx {
    payload: Vec<u8>,
    output_count: usize,
    /// Serialized script public keys, needed to prove an outpoint was locked by
    /// a particular covenant.
    output_spks: Vec<Vec<u8>>,
    /// Chain block that accepted it — the earliest point a spender can appear.
    accepting_block: RpcHash,
}

/// Result of hunting for the transaction that spends an anchor outpoint.
enum Spend {
    /// Found, accepted, and here are its payload and the signature script that
    /// unlocked the anchor outpoint.
    Settled { payload: Vec<u8>, signature_script: Vec<u8> },
    /// Scanned all the way to the tip; nothing ever spent this outpoint.
    Unspent,
    /// Ran out of block budget. Not a verdict.
    OutOfBudget { blocks: usize },
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
    resolved: Mutex<HashMap<RpcHash, Option<AcceptedTx>>>,
    /// Outcome of the most recent chain scan, for accurate diagnostics.
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

    /// Resolve every anchor's escrow transaction in one chain scan.
    ///
    /// Call this before [`crate::chain::Chain::verify_anchored`]; without it,
    /// each attestation triggers its own scan for phase 1.
    pub fn prefetch<'a, I: IntoIterator<Item = &'a Outpoint>>(&self, anchors: I) -> io::Result<()> {
        let wanted: HashSet<RpcHash> = anchors.into_iter().map(|a| RpcHash::from_bytes(a.txid)).collect();
        self.resolve_all(wanted, None)
    }

    /// Number of transactions resolved so far (diagnostics).
    pub fn cached(&self) -> usize {
        self.resolved.lock().unwrap().len()
    }

    /// Resolve `wanted` by scanning the virtual chain from `start` (defaulting
    /// to the configured start, i.e. the pruning point).
    ///
    /// Sync wrapper — only valid from outside the runtime. Code already running
    /// inside it must use [`Self::resolve_async`], since a nested `block_on`
    /// panics.
    fn resolve_all(&self, wanted: HashSet<RpcHash>, start: Option<RpcHash>) -> io::Result<()> {
        self.handle.block_on(self.resolve_async(wanted, start))
    }

    async fn resolve_async(&self, wanted: HashSet<RpcHash>, start: Option<RpcHash>) -> io::Result<()> {
        let missing: HashSet<RpcHash> = {
            let cache = self.resolved.lock().unwrap();
            wanted.into_iter().filter(|t| !cache.contains_key(t)).collect()
        };
        if missing.is_empty() {
            return Ok(());
        }
        let (found, outcome) = self.scan(&missing, start).await?;
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
    async fn scan(
        &self,
        wanted: &HashSet<RpcHash>,
        start: Option<RpcHash>,
    ) -> io::Result<(HashMap<RpcHash, AcceptedTx>, ScanOutcome)> {
        let mut start = match start.or(self.cfg.scan_from) {
            Some(h) => h,
            None => {
                self.rpc
                    .get_block_dag_info()
                    .await
                    .map_err(rpc_err("get_block_dag_info"))?
                    .pruning_point_hash
            }
        };

        let mut remaining: HashSet<RpcHash> = wanted.clone();
        let mut found: HashMap<RpcHash, AcceptedTx> = HashMap::new();
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
    async fn fetch_from_mergeset(&self, accepting: RpcHash, txid: RpcHash) -> io::Result<Option<AcceptedTx>> {
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
                return Ok(Some(AcceptedTx {
                    payload: tx.payload.clone(),
                    output_count: tx.outputs.len(),
                    output_spks: tx.outputs.iter().map(spk_bytes).collect(),
                    accepting_block: accepting,
                }));
            }
        }
        Ok(None)
    }

    /// Sync wrapper; see [`Self::resolve_all`] for the runtime caveat.
    fn lookup(&self, txid: RpcHash, start: Option<RpcHash>) -> io::Result<Option<AcceptedTx>> {
        self.handle.block_on(self.lookup_async(txid, start))
    }

    async fn lookup_async(&self, txid: RpcHash, start: Option<RpcHash>) -> io::Result<Option<AcceptedTx>> {
        // Bind and drop the guard before awaiting.
        let cached = self.resolved.lock().unwrap().get(&txid).cloned();
        if let Some(hit) = cached {
            return Ok(hit);
        }
        self.resolve_async(HashSet::from([txid]), start).await?;
        let hit = self.resolved.lock().unwrap().get(&txid).cloned();
        Ok(hit.flatten())
    }

    /// Hunt for the accepted transaction that spends `anchor`, starting from
    /// the chain block that accepted the outpoint's creating transaction.
    ///
    /// Bulk `get_blocks` is used rather than per-block `get_block` because this
    /// phase needs bodies (inputs and payloads), and one call returns a whole
    /// mergeset's worth.
    async fn find_spender(&self, anchor: &Outpoint, from: RpcHash) -> io::Result<Spend> {
        let escrow_txid = RpcHash::from_bytes(anchor.txid);

        // Start one chain block earlier where possible, so the accepting
        // block's own mergeset is inside the window: a transaction can spend an
        // output created in the same mergeset.
        let low = match self.rpc.get_block(from, false).await {
            Ok(b) => b.verbose_data.map(|v| v.selected_parent_hash).unwrap_or(from),
            Err(_) => from,
        };

        let mut low = Some(low);
        let mut scanned = 0usize;
        let mut seen: HashSet<RpcHash> = HashSet::new();

        while scanned < self.cfg.max_spend_scan_blocks {
            let resp = self.rpc.get_blocks(low, true, true).await.map_err(rpc_err("get_blocks"))?;
            if resp.blocks.is_empty() {
                return Ok(Spend::Unspent);
            }
            scanned += resp.blocks.len();

            for block in &resp.blocks {
                for tx in &block.transactions {
                    let spends_it = tx.inputs.iter().any(|input| {
                        input.previous_outpoint.transaction_id == escrow_txid
                            && input.previous_outpoint.index == anchor.index
                    });
                    if !spends_it {
                        continue;
                    }
                    let Some(txid) = tx.verbose_data.as_ref().map(|v| v.transaction_id) else { continue };
                    if !seen.insert(txid) {
                        continue; // same tx seen in another block
                    }
                    // A transaction sitting in a block is not necessarily
                    // accepted — of two conflicting spends only one can be, so
                    // acceptance is what decides which spend is real.
                    if let Some(accepted) = self.lookup_async(txid, Some(from)).await? {
                        let signature_script = tx
                            .inputs
                            .iter()
                            .find(|i| {
                                i.previous_outpoint.transaction_id == escrow_txid
                                    && i.previous_outpoint.index == anchor.index
                            })
                            .map(|i| i.signature_script.clone())
                            .unwrap_or_default();
                        return Ok(Spend::Settled { payload: accepted.payload, signature_script });
                    }
                }
            }

            match resp.block_hashes.last() {
                Some(&last) if Some(last) != low => low = Some(last),
                // No progress: we are at the tip and nothing spent it.
                _ => return Ok(Spend::Unspent),
            }
        }
        Ok(Spend::OutOfBudget { blocks: scanned })
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
    fn covenant_witnessed(
        &self,
        anchor: &Outpoint,
        witness: &crate::CovenantWitness,
        owner: &secp256k1::XOnlyPublicKey,
    ) -> io::Result<bool> {
        self.check_covenant(anchor, witness, owner)
    }

    fn is_anchored(&self, id: &[u8; 32], anchor: &Outpoint) -> io::Result<bool> {
        let escrow_txid = RpcHash::from_bytes(anchor.txid);

        // Phase 1: the outpoint's creating transaction must exist and be accepted.
        let Some(escrow) = self.lookup(escrow_txid, None)? else {
            // Not a negative result — an unknown one. Saying "unanchored" here
            // would slander a chain whose anchors are simply older than this
            // node's pruning point, or newer than min_confirmations.
            return Err(io::Error::other(format!(
                "anchor outpoint {escrow_txid}:{} could not be resolved: {}. \
                 Options: --scan-from <recent chain block>, --min-confirmations, --max-batches, \
                 or point --rpc at an archival node.",
                anchor.index,
                self.scan_diagnostic()
            )));
        };

        // An anchor naming an output the transaction does not have is fabricated.
        if anchor.index as usize >= escrow.output_count {
            return Ok(false);
        }

        // Phase 2: find the settlement that spent it.
        match self.handle.block_on(self.find_spender(anchor, escrow.accepting_block))? {
            Spend::Settled { payload, .. } => Ok(payload_commits(&payload, id)),
            // Genuinely never spent: the escrow was never settled, so there is
            // no settlement transaction and nothing anchors this attestation.
            Spend::Unspent => Ok(false),
            Spend::OutOfBudget { blocks } => Err(io::Error::other(format!(
                "could not determine what spent anchor outpoint {escrow_txid}:{}: scanned {blocks} \
                 blocks forward from its escrow without finding a spending transaction or reaching \
                 the tip. Raise --max-spend-scan-blocks.",
                anchor.index
            ))),
        }
    }
}

impl KaspadAnchorVerifier {
    /// Establish that a covenant, rather than a signature, authorized an
    /// attestation. See [`AnchorVerifier::covenant_witnessed`].
    fn check_covenant(
        &self,
        anchor: &Outpoint,
        witness: &crate::CovenantWitness,
        owner: &secp256k1::XOnlyPublicKey,
    ) -> io::Result<bool> {
        let escrow_txid = RpcHash::from_bytes(anchor.txid);
        let Some(escrow) = self.lookup(escrow_txid, None)? else {
            return Err(io::Error::other(format!(
                "covenant witness names outpoint {escrow_txid}:{} which could not be resolved: {}",
                anchor.index,
                self.scan_diagnostic()
            )));
        };

        // 1. The outpoint really was locked by this covenant.
        let expected = kaspa_txscript::pay_to_script_hash_script(&witness.redeem_script);
        let expected_bytes: Vec<u8> = expected
            .version()
            .to_be_bytes()
            .iter()
            .copied()
            .chain(expected.script().iter().copied())
            .collect();
        let Some(actual) = escrow.output_spks.get(anchor.index as usize) else {
            return Ok(false);
        };
        if *actual != expected_bytes {
            return Ok(false);
        }

        // 2. The covenant itself recorded this owner. Without this an attacker
        //    who can drive any covenant of their own could mint defaults
        //    against anybody they liked.
        let at = witness.owner_offset as usize;
        match escrow.payload.get(at..at + 32) {
            Some(bytes) if bytes == owner.serialize() => {}
            _ => return Ok(false),
        }

        // 3. Spending it really took the declared branch.
        let spend = self.handle.block_on(self.find_spender(anchor, escrow.accepting_block))?;
        let Spend::Settled { signature_script, .. } = spend else {
            return Ok(false);
        };
        let Some(items) = parse_pushes(&signature_script) else { return Ok(false) };
        // The redeem script is the last push; the selector sits just below it.
        let n = items.len();
        if n < 2 {
            return Ok(false);
        }
        if items[n - 1] != PushItem::Data(witness.redeem_script.clone()) {
            return Ok(false);
        }
        let selector = witness.branch as i64;
        let chosen = match &items[n - 2] {
            PushItem::Small(v) => *v,
            PushItem::Data(d) if d.len() <= 8 => {
                let mut buf = [0u8; 8];
                buf[..d.len()].copy_from_slice(d);
                i64::from_le_bytes(buf)
            }
            PushItem::Data(_) => return Ok(false),
        };
        Ok(chosen == selector)
    }

    fn scan_diagnostic(&self) -> String {
        let from = self
            .cfg
            .scan_from
            .map(|h| h.to_string())
            .unwrap_or_else(|| "the pruning point".into());
        match *self.last_scan.lock().unwrap() {
            Some(o) if o.reached_tip => format!(
                "scanned {} batches from {from} to the virtual tip. The transaction is not in the \
                 history this node retains — either it does not exist, or it is older than the \
                 pruning point, or it is within the most recent {} chain blocks excluded by \
                 --min-confirmations",
                o.batches, self.cfg.min_confirmations
            ),
            Some(o) => format!(
                "gave up after {} batches from {from} WITHOUT reaching the tip — the scan ran out \
                 of budget, not out of chain. Raise --max-batches",
                o.batches
            ),
            None => format!("no scan was performed from {from}"),
        }
    }
}

/// Serialized script public key, matching what the script engine sees:
/// the u16 version big-endian, then the script.
fn spk_bytes(output: &kaspa_rpc_core::RpcTransactionOutput) -> Vec<u8> {
    let spk = &output.script_public_key;
    spk.version().to_be_bytes().iter().copied().chain(spk.script().iter().copied()).collect()
}

/// One item pushed by a signature script.
#[derive(Debug, PartialEq, Eq)]
enum PushItem {
    Data(Vec<u8>),
    /// Small integers are encoded as opcodes rather than data pushes, so a
    /// branch selector below 17 never appears as bytes on the wire.
    Small(i64),
}

/// Walk a signature script and recover what it pushed.
///
/// Only the push forms are recognised — a signature script that contains
/// anything else is not one we can reason about, and the parse fails rather
/// than guessing.
fn parse_pushes(script: &[u8]) -> Option<Vec<PushItem>> {
    const OP_0: u8 = 0x00;
    const OP_PUSHDATA1: u8 = 0x4c;
    const OP_PUSHDATA2: u8 = 0x4d;
    const OP_PUSHDATA4: u8 = 0x4e;
    const OP_1NEGATE: u8 = 0x4f;
    const OP_1: u8 = 0x51;
    const OP_16: u8 = 0x60;

    let mut out = Vec::new();
    let mut i = 0usize;
    while i < script.len() {
        let op = script[i];
        i += 1;
        let len = match op {
            OP_0 => {
                out.push(PushItem::Small(0));
                continue;
            }
            OP_1NEGATE => {
                out.push(PushItem::Small(-1));
                continue;
            }
            OP_1..=OP_16 => {
                out.push(PushItem::Small((op - OP_1 + 1) as i64));
                continue;
            }
            1..=0x4b => op as usize,
            OP_PUSHDATA1 => {
                let n = *script.get(i)? as usize;
                i += 1;
                n
            }
            OP_PUSHDATA2 => {
                let n = u16::from_le_bytes(script.get(i..i + 2)?.try_into().ok()?) as usize;
                i += 2;
                n
            }
            OP_PUSHDATA4 => {
                let n = u32::from_le_bytes(script.get(i..i + 4)?.try_into().ok()?) as usize;
                i += 4;
                n
            }
            _ => return None,
        };
        out.push(PushItem::Data(script.get(i..i + len)?.to_vec()));
        i += len;
    }
    Some(out)
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
