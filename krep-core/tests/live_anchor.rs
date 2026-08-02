//! End-to-end anchor verification against a real kaspad node.
//!
//! Skipped unless `KREP_TEST_RPC` is set, e.g.
//!
//! ```sh
//! KREP_TEST_RPC=grpc://192.168.4.33:16110 \
//!   cargo test -p krep-core --features kaspad --test live_anchor -- --nocapture
//! ```
//!
//! The point of this test is to exercise the parts that cannot be faked in a
//! unit test: that the virtual-chain scan actually finds a transaction the node
//! really accepted, that descending into the accepting block's mergeset really
//! retrieves that transaction's payload, and that the three verdicts
//! (`Ok(true)` / `Ok(false)` / `Err`) come out where they should.

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

/// A real accepted transaction discovered from the node itself.
struct Sample {
    txid: kaspa_rpc_core::RpcHash,
    payload: Vec<u8>,
    outputs: usize,
}

/// Walk the virtual chain looking for accepted transactions, preferring one
/// that carries a payload of at least 32 bytes (which lets us assert the
/// positive path with a real on-chain commitment).
async fn find_sample(rpc: &Arc<dyn RpcApi>, max_batches: usize) -> (Option<Sample>, Option<Sample>) {
    let dag = rpc.get_block_dag_info().await.expect("dag info");
    println!(
        "network={} sink={} pruning_point={} virtual_daa={}",
        dag.network, dag.sink, dag.pruning_point_hash, dag.virtual_daa_score
    );

    let mut start = dag.pruning_point_hash;
    let mut any: Option<Sample> = None;
    let mut with_payload: Option<Sample> = None;
    let mut accepted_seen = 0usize;

    for batch in 0..max_batches {
        let resp = rpc.get_virtual_chain_from_block(start, true, None).await.expect("virtual chain");
        println!(
            "batch {batch}: {} chain blocks, {} acceptance entries",
            resp.added_chain_block_hashes.len(),
            resp.accepted_transaction_ids.len()
        );

        for entry in &resp.accepted_transaction_ids {
            if entry.accepted_transaction_ids.is_empty() {
                continue;
            }
            accepted_seen += entry.accepted_transaction_ids.len();

            // Pull the mergeset once and inspect every accepted tx in it.
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
                    let sample =
                        Sample { txid: vd.transaction_id, payload: tx.payload.clone(), outputs: tx.outputs.len() };
                    if sample.payload.len() >= 32 && with_payload.is_none() {
                        println!(
                            "found payload-bearing accepted tx {} ({} byte payload)",
                            sample.txid,
                            sample.payload.len()
                        );
                        with_payload = Some(sample);
                    } else if any.is_none() {
                        println!("found accepted tx {} ({} byte payload)", sample.txid, sample.payload.len());
                        any = Some(sample);
                    }
                }
                if with_payload.is_some() && any.is_some() {
                    break;
                }
            }
            if with_payload.is_some() && any.is_some() {
                break;
            }
        }

        if with_payload.is_some() && any.is_some() {
            break;
        }
        match resp.added_chain_block_hashes.last() {
            Some(&last) if last != start => start = last,
            _ => break,
        }
    }
    println!("saw {accepted_seen} accepted transaction ids while sampling");
    (any, with_payload)
}

#[test]
fn verifier_against_live_node() {
    let Ok(url) = std::env::var(ENV) else {
        eprintln!("skipping: set {ENV}=grpc://host:16110 (or ws://host:17110) to run");
        return;
    };

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().worker_threads(2).build().unwrap();
    let rpc = rt.block_on(connect(&url));

    let (any, with_payload) = rt.block_on(find_sample(&rpc, 32));
    let sample = with_payload.as_ref().or(any.as_ref()).expect(
        "no accepted transaction found on this node — cannot exercise the verifier against real data",
    );

    // Verify with min_confirmations 0: the samples come from deep history, but
    // we do not want the confirmation trim to interact with this assertion.
    // Exercise the shipped defaults, only relaxing the confirmation depth: the
    // samples come from deep history, but we do not want the tip trim to
    // interact with these assertions.
    let verifier = KaspadAnchorVerifier::new(
        rpc.clone(),
        rt.handle().clone(),
        ScanConfig { min_confirmations: 0, ..Default::default() },
    );

    let anchor = Outpoint { txid: sample.txid.as_bytes(), index: 0 };

    // 1. A random id is provably NOT committed by this real transaction.
    //    Reaching a verdict at all proves the scan found the tx and the
    //    mergeset descent retrieved its body.
    let absent = [0x5au8; 32];
    assert_eq!(
        verifier.is_anchored(&absent, &anchor).expect("resolvable"),
        false,
        "a random id must not be considered anchored by {}",
        sample.txid
    );
    println!("negative verdict OK against real tx {}", sample.txid);

    // 2. An output index the transaction does not have is a fabricated anchor.
    let bogus_index = Outpoint { txid: sample.txid.as_bytes(), index: sample.outputs as u32 + 500 };
    assert_eq!(verifier.is_anchored(&absent, &bogus_index).expect("resolvable"), false);
    println!("bogus output index rejected (tx has {} outputs)", sample.outputs);

    // 3. The positive path, using bytes that really are in a real payload.
    match with_payload.as_ref() {
        Some(s) => {
            let mut id = [0u8; 32];
            id.copy_from_slice(&s.payload[..32]);
            let a = Outpoint { txid: s.txid.as_bytes(), index: 0 };
            assert!(
                verifier.is_anchored(&id, &a).expect("resolvable"),
                "the first 32 payload bytes of {} must verify as committed",
                s.txid
            );
            println!("positive verdict OK: real payload commitment verified against {}", s.txid);
        }
        None => println!(
            "note: no accepted transaction with a >=32 byte payload in the sampled range, \
             so the positive path was exercised only by unit tests"
        ),
    }

    // 4. An unknown txid must be an error, never a false "unanchored" verdict.
    let unknown = Outpoint { txid: [0xab; 32], index: 0 };
    let err = verifier.is_anchored(&absent, &unknown).unwrap_err();
    println!("unknown txid correctly reported as unresolvable: {err}");
    let msg = err.to_string();
    assert!(msg.contains("could not be resolved"), "unexpected error text: {msg}");
    // Having scanned to the tip, the diagnostic must say so rather than blaming
    // a budget it never hit.
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
            if batches % 200 == 0 {
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
