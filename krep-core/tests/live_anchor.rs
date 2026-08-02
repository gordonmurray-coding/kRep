//! End-to-end anchor verification against a real kaspad node.
//!
//! Skipped unless `KREP_TEST_RPC` is set, e.g.
//!
//! ```sh
//! KREP_TEST_RPC=grpc://192.168.4.33:16110 \
//!   cargo test -p krep-core --features kaspad --test live_anchor -- --nocapture
//! ```
//!
//! This exercises what cannot be faked in a unit test: that the two-phase
//! resolution really works against live chain data — locating an outpoint's
//! creating transaction in the accepted-id stream, then finding the accepted
//! transaction that *spends* it and reading its payload.
//!
//! The sample is not hardcoded. The test discovers a real settlement from the
//! node itself: an accepted transaction carrying a payload, whose first input
//! becomes the `anchor` outpoint. That is exactly the shape kRep produces —
//! spend an escrow, commit the id in the payload — so the positive assertion is
//! made against a genuine on-chain commitment rather than a fixture.

#![cfg(feature = "kaspad")]

use kaspa_rpc_core::api::rpc::RpcApi;
use krep_core::kaspad::{KaspadAnchorVerifier, ScanConfig};
use krep_core::{AnchorVerifier, Outpoint};
use std::sync::Arc;
use std::time::Duration;

const ENV: &str = "KREP_TEST_RPC";

async fn connect(url: &str) -> Arc<dyn RpcApi> {
    if url.starts_with("grpc://") {
        use kaspa_grpc_client::GrpcClient;
        use kaspa_rpc_core::notify::mode::NotificationMode;
        Arc::new(
            GrpcClient::connect_with_args(
                NotificationMode::Direct,
                url.to_string(),
                None,
                false,
                None,
                false,
                Some(10_000),
                Default::default(),
            )
            .await
            .expect("grpc connect"),
        )
    } else {
        use kaspa_wrpc_client::prelude::*;
        let c = KaspaRpcClient::new(WrpcEncoding::Borsh, Some(url), None, None, None).expect("wrpc client");
        c.connect(Some(ConnectOptions {
            block_async_connect: true,
            strategy: ConnectStrategy::Fallback,
            connect_timeout: Some(Duration::from_secs(10)),
            ..Default::default()
        }))
        .await
        .expect("wrpc connect");
        Arc::new(c)
    }
}

/// A real settlement discovered from the node: an accepted, payload-carrying
/// transaction plus the outpoint it spends.
struct Sample {
    settlement: kaspa_rpc_core::RpcHash,
    /// The outpoint the settlement spends — an `anchor` in kRep terms.
    anchor: Outpoint,
    payload: Vec<u8>,
}

/// Cheaply walk the selected parent chain from the pruning point to the tip,
/// recording the batch boundaries. Without acceptance data this is fast, and it
/// gives us handles on *recent* chain positions — which matters, because a
/// settlement sampled from the oldest end of history necessarily spends
/// outputs created before the pruning point, i.e. outputs this node no longer
/// has. Those are legitimately unverifiable and prove nothing either way.
async fn chain_marks(rpc: &Arc<dyn RpcApi>) -> Vec<kaspa_rpc_core::RpcHash> {
    let dag = rpc.get_block_dag_info().await.expect("dag info");
    println!(
        "network={} sink={} pruning_point={} virtual_daa={}",
        dag.network, dag.sink, dag.pruning_point_hash, dag.virtual_daa_score
    );
    let mut start = dag.pruning_point_hash;
    let mut marks = vec![start];
    loop {
        let resp = rpc.get_virtual_chain_from_block(start, false, None).await.expect("virtual chain");
        match resp.added_chain_block_hashes.last() {
            Some(&last) if last != start => {
                start = last;
                marks.push(start);
            }
            _ => break,
        }
    }
    println!("chain walked to tip in {} marks", marks.len());
    marks
}

/// Walk the virtual chain collecting accepted transactions that both carry a
/// payload of at least 32 bytes and spend something.
async fn find_settlements(
    rpc: &Arc<dyn RpcApi>,
    from: kaspa_rpc_core::RpcHash,
    max_batches: usize,
    want: usize,
) -> Vec<Sample> {
    let mut start = from;
    let mut out: Vec<Sample> = Vec::new();

    for _ in 0..max_batches {
        let resp = rpc.get_virtual_chain_from_block(start, true, None).await.expect("virtual chain");

        for entry in &resp.accepted_transaction_ids {
            if entry.accepted_transaction_ids.is_empty() {
                continue;
            }
            let head = rpc.get_block(entry.accepting_block_hash, false).await.expect("accepting block");
            let verbose = head.verbose_data.expect("verbose data");
            let mergeset: Vec<_> = verbose
                .merge_set_blues_hashes
                .iter()
                .chain(verbose.merge_set_reds_hashes.iter())
                .copied()
                .collect();

            for block_hash in mergeset {
                let block = rpc.get_block(block_hash, true).await.expect("merged block");
                for tx in &block.transactions {
                    let Some(vd) = tx.verbose_data.as_ref() else { continue };
                    if !entry.accepted_transaction_ids.contains(&vd.transaction_id) {
                        continue;
                    }
                    if tx.payload.len() < 32 || tx.inputs.is_empty() {
                        continue;
                    }
                    let prev = &tx.inputs[0].previous_outpoint;
                    out.push(Sample {
                        settlement: vd.transaction_id,
                        anchor: Outpoint { txid: prev.transaction_id.as_bytes(), index: prev.index },
                        payload: tx.payload.clone(),
                    });
                    println!(
                        "candidate settlement {} ({} byte payload) spends {}:{}",
                        vd.transaction_id,
                        tx.payload.len(),
                        prev.transaction_id,
                        prev.index
                    );
                    if out.len() >= want {
                        return out;
                    }
                }
            }
        }

        match resp.added_chain_block_hashes.last() {
            Some(&last) if last != start => start = last,
            _ => break,
        }
    }
    out
}

#[test]
fn verifier_against_live_node() {
    let Ok(url) = std::env::var(ENV) else {
        eprintln!("skipping: set {ENV}=grpc://host:16110 (or ws://host:17110) to run");
        return;
    };

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().worker_threads(2).build().unwrap();
    let rpc = rt.block_on(connect(&url));

    let marks = rt.block_on(chain_marks(&rpc));
    assert!(marks.len() > 2, "node has almost no retained chain; cannot sample");
    // Sample near the tip so the outpoints being spent are themselves still
    // within retained history, and start the verifier a little further back so
    // phase 1 has margin to find them.
    let sample_from = marks[marks.len().saturating_sub(3)];
    let verify_from = marks[marks.len().saturating_sub(8)];
    println!("sampling from {sample_from}, verifying from {verify_from}");

    let samples = rt.block_on(find_settlements(&rpc, sample_from, 32, 6));
    assert!(!samples.is_empty(), "no payload-carrying accepted transaction found near the tip");

    let verifier = KaspadAnchorVerifier::new(
        rpc.clone(),
        rt.handle().clone(),
        // min_confirmations 0 so the tip trim does not interact with the
        // assertions; scan_from bounds the work to recent history.
        ScanConfig { scan_from: Some(verify_from), min_confirmations: 0, ..Default::default() },
    );

    // A candidate is usable only if its spent outpoint's creating transaction
    // is still within this node's retained history — otherwise phase 1 is
    // legitimately unresolvable and there is nothing to assert.
    let mut proven = 0usize;
    for s in &samples {
        let mut committed = [0u8; 32];
        committed.copy_from_slice(&s.payload[..32]);

        match verifier.is_anchored(&committed, &s.anchor) {
            Ok(true) => {
                println!(
                    "POSITIVE: {} spends {}:{} and its payload commits the id — spend-based \
                     verification confirmed against real chain data",
                    s.settlement,
                    hex::encode(s.anchor.txid),
                    s.anchor.index
                );

                // The same anchor must NOT vouch for an id the settlement does
                // not carry. This is a genuine negative: the settlement was
                // found and read, and it simply does not commit this id.
                let absent = [0x5au8; 32];
                assert!(
                    !verifier.is_anchored(&absent, &s.anchor).expect("resolvable"),
                    "an unrelated id must not verify against this settlement"
                );
                println!("negative verdict OK against the same real settlement");

                // An output index the escrow transaction does not have is a
                // fabricated anchor.
                let bogus = Outpoint { txid: s.anchor.txid, index: 100_000 };
                assert!(
                    !verifier.is_anchored(&committed, &bogus).expect("resolvable"),
                    "an anchor naming a nonexistent output must be rejected"
                );
                println!("fabricated output index rejected");

                proven += 1;
                break;
            }
            Ok(false) => println!(
                "candidate {} did not verify (its first input is not what carries the \
                 commitment); trying another",
                s.settlement
            ),
            Err(e) => println!("candidate {} unresolvable ({e}); trying another", s.settlement),
        }
    }
    assert!(
        proven > 0,
        "none of the {} sampled settlements could be verified — the spend-based path did not \
         confirm against live data",
        samples.len()
    );

    // An outpoint whose creating transaction does not exist must be an error,
    // never a false "unanchored" verdict.
    let unknown = Outpoint { txid: [0xab; 32], index: 0 };
    let err = verifier.is_anchored(&[0u8; 32], &unknown).unwrap_err();
    let msg = err.to_string();
    println!("unknown anchor correctly reported as unresolvable: {msg}");
    assert!(msg.contains("could not be resolved"), "unexpected error text: {msg}");
    assert!(msg.contains("to the virtual tip"), "expected a tip-reached diagnostic, got: {msg}");
}

/// How far does a full pruning-point-to-tip scan actually reach, and what does
/// it cost? This calibrates the `max_batches` default. Gated separately since
/// it walks the node's entire retained chain.
///
/// `KREP_TEST_FULL_SCAN=1 KREP_TEST_RPC=grpc://host:16110 cargo test -p krep-core \
///    --features kaspad --test live_anchor full_scan_cost -- --nocapture --ignored`
#[test]
#[ignore]
fn full_scan_cost() {
    let Ok(url) = std::env::var(ENV) else { return };
    if std::env::var("KREP_TEST_FULL_SCAN").is_err() {
        eprintln!("skipping: set KREP_TEST_FULL_SCAN=1");
        return;
    }
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().worker_threads(2).build().unwrap();
    let rpc = rt.block_on(connect(&url));

    rt.block_on(async {
        let dag = rpc.get_block_dag_info().await.unwrap();
        let mut start = dag.pruning_point_hash;
        let mut batches = 0usize;
        let mut chain_blocks = 0usize;
        let began = std::time::Instant::now();
        loop {
            let resp = rpc.get_virtual_chain_from_block(start, false, None).await.unwrap();
            batches += 1;
            chain_blocks += resp.added_chain_block_hashes.len();
            match resp.added_chain_block_hashes.last() {
                Some(&last) if last != start => start = last,
                _ => break,
            }
            if batches.is_multiple_of(200) {
                println!("  {batches} batches, {chain_blocks} chain blocks, {:?}", began.elapsed());
            }
            if began.elapsed() > Duration::from_secs(300) {
                println!("  aborting at 300s");
                break;
            }
        }
        println!(
            "full scan: {batches} batches, {chain_blocks} chain blocks, {:?}, reached {start}",
            began.elapsed()
        );
        println!("sink was {}", dag.sink);
    });
}
