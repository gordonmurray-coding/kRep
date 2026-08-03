//! Drives a real FabMesh escrow through a real Kaspa network.
//!
//! Gated on `KREP_TEST_RPC` and `KREP_TEST_WALLET`, e.g.
//!
//! ```sh
//! KREP_TEST_RPC=grpc://192.168.4.25:16110 \
//! KREP_TEST_WALLET=$HOME/.krep/wallet.key \
//!   cargo test -p krep-escrow --test live_escrow -- --nocapture --ignored
//! ```
//!
//! It exercises the path M2 exists for: a maker claims a job, never ships, and
//! the buyer slashes them after the deadline. The slash produces a *default
//! attestation that the maker never signed and cannot repudiate* — which is the
//! whole point of the covenant being the counter-signer of record.
//!
//! Real funds move, which is why it is `#[ignore]` by default.

use kaspa_consensus_core::hashing::sighash::{calc_schnorr_signature_hash, SigHashReusedValuesUnsync};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::hashing::tx::transaction_v0_id_preimage;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    ComputeCommit, PopulatedTransaction, Transaction, TransactionInput, TransactionOutpoint,
    TransactionOutput, UtxoEntry,
};
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::{pay_to_address_script, EngineFlags};
use krep_escrow::script::{covenant_script, escrow_address, escrow_spk, Branch};
use krep_escrow::state::{EscrowState, Phase, OFF_MAKER};
use krep_escrow::Terms;
use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};
use std::sync::Arc;

// A covenant spend carries the whole ~1 kB redeem script plus the previous
// state in its signature script, so these transactions are heavy: observed
// compute mass 4578 for the claim, against a 100 sompi/gram floor. Flat and
// generous beats clever here — the amounts at stake are tiny.
const FEE: u64 = 2_000_000;
const REWARD: u64 = 100_000_000; // 1 TKAS
const BOND: u64 = 50_000_000; // 0.5 TKAS

fn builder() -> ScriptBuilder {
    ScriptBuilder::with_flags(EngineFlags { covenants_enabled: true, ..Default::default() })
}

async fn connect(url: &str) -> Arc<dyn RpcApi> {
    use kaspa_grpc_client::GrpcClient;
    use kaspa_rpc_core::notify::mode::NotificationMode;
    Arc::new(
        GrpcClient::connect_with_args(NotificationMode::Direct, url.to_string(), None, false, None, false, Some(10_000), Default::default())
            .await
            .expect("grpc connect"),
    )
}

/// One input we are about to spend.
struct In {
    outpoint: TransactionOutpoint,
    entry: UtxoEntry,
    /// `None` means a plain P2PK input signed by the wallet key.
    covenant: Option<CovenantUnlock>,
}

struct CovenantUnlock {
    branch: Branch,
    prev_rest: Vec<u8>,
    prev_payload: Vec<u8>,
    /// Signature argument the branch expects, if any.
    needs_sig: bool,
    script: Vec<u8>,
}

/// Build, sign and return a transaction. Signatures cover the whole
/// transaction, so every signature script is filled in after the sighashes are
/// computed against a skeleton.
fn build_tx(key: &Keypair, ins: &[In], outs: Vec<TransactionOutput>, payload: Vec<u8>, lock_time: u64) -> Transaction {
    let skeleton = |scripts: Vec<Vec<u8>>| {
        Transaction::new(
            0,
            ins.iter()
                .zip(scripts)
                .map(|(i, sig)| TransactionInput {
                    previous_outpoint: i.outpoint,
                    signature_script: sig,
                    sequence: 0,
                    compute_commit: ComputeCommit::SigopCount(1.into()),
                })
                .collect(),
            outs.clone(),
            lock_time,
            SUBNETWORK_ID_NATIVE,
            0,
            payload.clone(),
        )
    };

    let empty = skeleton(ins.iter().map(|_| vec![]).collect());
    let entries: Vec<UtxoEntry> = ins.iter().map(|i| i.entry.clone()).collect();
    let populated = PopulatedTransaction::new(&empty, entries);
    let reused = SigHashReusedValuesUnsync::new();

    let sign_input = |idx: usize| {
        let hash = calc_schnorr_signature_hash(&populated, idx, SIG_HASH_ALL, &reused);
        let msg = secp256k1::Message::from_digest(hash.as_bytes());
        let mut sig = key.sign_schnorr(msg).as_ref().to_vec();
        sig.push(SIG_HASH_ALL.to_u8());
        sig
    };

    let scripts: Vec<Vec<u8>> = ins
        .iter()
        .enumerate()
        .map(|(idx, i)| match &i.covenant {
            None => builder().add_data(&sign_input(idx)).unwrap().drain(),
            Some(c) => {
                let mut b = builder();
                if c.needs_sig {
                    b.add_data(&sign_input(idx)).unwrap();
                }
                b.add_data(&c.prev_rest)
                    .unwrap()
                    .add_data(&c.prev_payload)
                    .unwrap()
                    .add_i64(c.branch.selector())
                    .unwrap()
                    .add_data(&c.script)
                    .unwrap()
                    .drain()
            }
        })
        .collect();

    let mut tx = skeleton(scripts);
    tx.finalize();
    tx
}

/// Split a transaction into the two halves a covenant spender must supply.
fn state_parts(tx: &Transaction) -> (Vec<u8>, Vec<u8>) {
    let preimage = transaction_v0_id_preimage(tx);
    let split = preimage.len() - tx.payload.len();
    let (rest, payload) = preimage.split_at(split);
    (rest.to_vec(), payload.to_vec())
}

async fn submit(rpc: &Arc<dyn RpcApi>, tx: &Transaction, what: &str) {
    let id = rpc.submit_transaction(tx.into(), false).await.unwrap_or_else(|e| panic!("submit {what}: {e}"));
    println!("  {what}: {id}");
    assert_eq!(id, tx.id(), "node accepted a different txid than we built");
}

/// Wait until `outpoint` is spendable from the node's point of view.
async fn wallet_utxos(rpc: &Arc<dyn RpcApi>, addr: &kaspa_addresses::Address) -> Vec<(TransactionOutpoint, UtxoEntry)> {
    let dag = rpc.get_block_dag_info().await.unwrap();
    rpc.get_utxos_by_addresses(vec![addr.clone()])
        .await
        .unwrap()
        .into_iter()
        .filter(|e| dag.virtual_daa_score >= e.utxo_entry.block_daa_score + 10)
        .map(|e| (TransactionOutpoint::from(e.outpoint), UtxoEntry::from(e.utxo_entry)))
        .collect()
}

#[test]
#[ignore]
fn escrow_slash_produces_an_unrepudiable_default() {
    let (Ok(url), Ok(wallet_path)) = (std::env::var("KREP_TEST_RPC"), std::env::var("KREP_TEST_WALLET")) else {
        eprintln!("skipping: set KREP_TEST_RPC and KREP_TEST_WALLET");
        return;
    };
    let seed = hex::decode(std::fs::read_to_string(&wallet_path).unwrap().trim()).unwrap();
    let key = Keypair::from_seckey_slice(&Secp256k1::new(), &seed).unwrap();

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().worker_threads(2).build().unwrap();
    let rpc = rt.block_on(connect(&url));

    rt.block_on(async {
        let network = rpc.get_current_network().await.unwrap();
        let prefix = kaspa_addresses::Prefix::from(network);
        let dag = rpc.get_block_dag_info().await.unwrap();
        println!("network={network} virtual_daa={}", dag.virtual_daa_score);
        // Everything this test creates comes after the current sink, so it is a
        // sound and cheap place to start the verifier's scan later.
        let scan_from = dag.sink;

        // The wallet plays buyer; the maker is a pseudonym that will default.
        let buyer = key.x_only_public_key().0;
        let maker: XOnlyPublicKey =
            Keypair::from_seckey_slice(&Secp256k1::new(), &[0x4d; 32]).unwrap().x_only_public_key().0;
        let wallet_addr = kaspa_addresses::Address::new(prefix, kaspa_addresses::Version::PubKey, &buyer.serialize());
        let wallet_spk = pay_to_address_script(&wallet_addr);

        // Deadline already in the past, so the slash path is open immediately.
        let terms = Terms {
            buyer,
            arbiter: None,
            reward: REWARD,
            maker_bond: BOND,
            deadline: dag.virtual_daa_score - 1_000,
            auto_release_delay: 100,
            file_hash: *blake3::hash(b"krep m2 live escrow").as_bytes(),
        };
        let script = covenant_script(&terms).unwrap();
        let esc_spk = escrow_spk(&terms).unwrap();
        println!("escrow {} ({} byte covenant)", escrow_address(&terms, prefix).unwrap(), script.len());

        let utxos = wallet_utxos(&rpc, &wallet_addr).await;
        let (op, entry) = utxos.into_iter().max_by_key(|(_, e)| e.amount).expect("fund the wallet first");
        println!("funding from {}:{} ({} sompi)", op.transaction_id, op.index, entry.amount);

        // 1. OPEN — buyer funds the escrow.
        let open = EscrowState::open(terms.id());
        let tx_open = build_tx(
            &key,
            &[In { outpoint: op, entry: entry.clone(), covenant: None }],
            vec![
                TransactionOutput { value: REWARD, script_public_key: esc_spk.clone(), covenant: None },
                TransactionOutput {
                    value: entry.amount - REWARD - FEE,
                    script_public_key: wallet_spk.clone(),
                    covenant: None,
                },
            ],
            open.encode().to_vec(),
            0,
        );
        submit(&rpc, &tx_open, "OPEN").await;

        // 2. CLAIMED — the maker bonds. Bond and fee come from the change output.
        let (rest, payload) = state_parts(&tx_open);
        let claimed = EscrowState {
            phase: Phase::Claimed,
            terms_id: terms.id(),
            maker: Some(maker),
            tracking: None,
            shipped_at: 0,
        };
        let change_value = entry.amount - REWARD - FEE;
        let tx_claim = build_tx(
            &key,
            &[
                In {
                    outpoint: TransactionOutpoint::new(tx_open.id(), 0),
                    entry: UtxoEntry::new(REWARD, esc_spk.clone(), 0, false, None),
                    covenant: Some(CovenantUnlock {
                        branch: Branch::Claim,
                        prev_rest: rest,
                        prev_payload: payload,
                        needs_sig: false,
                        script: script.clone(),
                    }),
                },
                In {
                    outpoint: TransactionOutpoint::new(tx_open.id(), 1),
                    entry: UtxoEntry::new(change_value, wallet_spk.clone(), 0, false, None),
                    covenant: None,
                },
            ],
            vec![
                TransactionOutput {
                    value: terms.claimed_value(),
                    script_public_key: esc_spk.clone(),
                    covenant: None,
                },
                TransactionOutput {
                    value: change_value - BOND - FEE,
                    script_public_key: wallet_spk.clone(),
                    covenant: None,
                },
            ],
            claimed.encode().to_vec(),
            0,
        );
        submit(&rpc, &tx_claim, "CLAIM").await;

        // 3. The default attestation the maker will never sign. Its anchor is
        //    the CLAIMED escrow outpoint that the slash consumes.
        let anchor = krep_core::Outpoint { txid: tx_claim.id().as_bytes(), index: 0 };
        let witness = krep_core::CovenantWitness {
            redeem_script: script.clone(),
            branch: Branch::Slash as u8,
            owner_offset: OFF_MAKER as u16,
        };
        let body = krep_core::AttestationBody {
            v: 1,
            anchor,
            role: krep_core::Role::Provider,
            owner: maker,
            counterparty: buyer,
            outcome: krep_core::Outcome::Default,
            amount_bucket: 1,
            prev: None,
            index: 0,
            ts: 1_785_720_000,
        };
        let att = krep_core::Attestation {
            body,
            auth: krep_core::Authorization::Covenant { covenant_witness: witness.clone() },
        };
        att.verify().expect("structurally valid");
        let att_id = att.id();
        println!("default attestation id {}", hex::encode(att_id));

        // 4. SLASH — buyer takes reward + bond, committing the attestation.
        let (rest2, payload2) = state_parts(&tx_claim);
        let mut slash_payload = att_id.to_vec();
        slash_payload.extend_from_slice(&[0u8; 32]); // buyer records nothing here
        let claim_change = change_value - BOND - FEE;
        let tx_slash = build_tx(
            &key,
            &[
                In {
                    outpoint: TransactionOutpoint::new(tx_claim.id(), 0),
                    entry: UtxoEntry::new(terms.claimed_value(), esc_spk.clone(), 0, false, None),
                    covenant: Some(CovenantUnlock {
                        branch: Branch::Slash,
                        prev_rest: rest2,
                        prev_payload: payload2,
                        needs_sig: true,
                        script: script.clone(),
                    }),
                },
                In {
                    outpoint: TransactionOutpoint::new(tx_claim.id(), 1),
                    entry: UtxoEntry::new(claim_change, wallet_spk.clone(), 0, false, None),
                    covenant: None,
                },
            ],
            vec![
                TransactionOutput {
                    value: terms.claimed_value(),
                    script_public_key: wallet_spk.clone(),
                    covenant: None,
                },
                TransactionOutput {
                    value: claim_change - FEE,
                    script_public_key: wallet_spk.clone(),
                    covenant: None,
                },
            ],
            slash_payload,
            terms.deadline,
        );
        submit(&rpc, &tx_slash, "SLASH").await;

        println!("\nescrow driven OPEN -> CLAIMED -> SLASH on {network}");

        // 5. The point of all of it: a third party with nothing but a node can
        //    confirm the default. The maker signed nothing and cannot repudiate
        //    it, and it is anchored by the very transaction that took their bond.
        let mut chain = krep_core::chain::Chain::new(maker);
        chain.append(att.clone()).expect("the default belongs to the maker's chain");

        let verifier = krep_core::kaspad::KaspadAnchorVerifier::new(
            rpc.clone(),
            tokio::runtime::Handle::current(),
            krep_core::kaspad::ScanConfig {
                scan_from: Some(scan_from),
                min_confirmations: 0,
                ..Default::default()
            },
        );

        // Give the slash a moment to be accepted, then verify. Blocking calls
        // must leave the async context, hence spawn_blocking.
        let mut verified = false;
        for attempt in 0..12 {
            let c = chain.clone();
            let v = &verifier;
            let outcome = tokio::task::block_in_place(|| c.verify_anchored(v));
            match outcome {
                Ok(()) => {
                    verified = true;
                    break;
                }
                Err(e) if attempt == 11 => panic!("default never verified: {e}"),
                Err(_) => tokio::time::sleep(std::time::Duration::from_secs(5)).await,
            }
        }
        assert!(verified);
        println!("VERIFIED: the maker carries a default they never signed");
        println!("  anchor  {}:0", tx_claim.id());
        println!("  slash   {}", tx_slash.id());
        println!("  score   {:?}", chain.score().defaults);

        // And the same witness must not vouch for a different pseudonym: the
        // covenant recorded who defaulted, and only they can be defamed by it.
        let mut impostor = att.clone();
        impostor.body.owner = buyer;
        let mut wrong = krep_core::chain::Chain::new(buyer);
        wrong.attestations.push(impostor);
        let v = &verifier;
        assert!(
            tokio::task::block_in_place(|| wrong.verify_anchored(v)).is_err(),
            "a covenant witness must not defame someone the covenant never named"
        );
        println!("  and it cannot be re-pointed at anyone else");
    });
}
