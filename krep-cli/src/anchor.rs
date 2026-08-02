//! Building the payload-carrying transaction that anchors attestation ids.
//!
//! The anchor does not have to be an escrow settlement — it just has to be a
//! real, accepted transaction that you paid for, whose payload commits the id.
//! That is the whole Sybil-cost model: `N` fake trades cost `N` real fees.
//!
//! Shape of the transaction: a self-send consolidation. All selected UTXOs go
//! back to the paying address as a single output, minus fee, with the 32- or
//! 64-byte payload attached.
//!
//! That shape keeps the KIP-9 storage mass term at zero *for realistic amounts*
//! — a single output worth nearly the sum of its inputs has a smaller harmonic
//! term than the inputs it replaces. It is not automatic, though: if the fee
//! eats most of the value (dust inputs), storage mass explodes and the node
//! would reject the transaction. So the fee is solved against the real
//! `calc_storage_mass` from consensus rather than assumed away, and a selection
//! that cannot pay for itself is refused rather than built.
//!
//! The payload is committed by the signature — `payload_hash` is mixed into the
//! sighash for any native transaction with a non-empty payload — so the anchor
//! commitment cannot be stripped or rewritten by a relay without invalidating
//! the transaction.

use anyhow::{Context, Result, anyhow, bail};
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::{
    constants::{STORAGE_MASS_PARAMETER, TX_VERSION},
    mass::{UtxoCell, calc_storage_mass, utxo_plurality},
    sign::{sign, verify as verify_signatures},
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{
        ComputeCommit, MutableTransaction, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint,
        TransactionOutput, UtxoEntry,
    },
};
use kaspa_rpc_core::RpcUtxoEntry;
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_txscript::pay_to_address_script;
use secp256k1::Keypair;
use std::sync::Arc;

/// Most inputs we will pull into one anchor transaction.
const MAX_INPUTS: usize = 8;
/// Conservative coinbase maturity. Mainnet needs 100, 10 BPS testnets 1000;
/// using the larger everywhere only ever makes us skip a young coinbase UTXO.
const COINBASE_MATURITY: u64 = 1000;
/// Confirmations required of a normal UTXO before we will spend it.
const UTXO_MIN_CONFIRMATIONS: u64 = 10;
/// Floor on the feerate (sompi per gram) if the node's estimate is unusable.
const MIN_FEERATE: f64 = 1.0;

#[derive(Debug)]
pub struct AnchorPlan {
    pub tx: Transaction,
    /// UTXO entries backing the inputs, kept so the signed transaction can be
    /// re-verified locally without going back to the node.
    pub entries: Vec<UtxoEntry>,
    pub address: Address,
    pub payload: Vec<u8>,
    pub input_count: usize,
    pub total_in: u64,
    pub out_value: u64,
    pub fee: u64,
    pub feerate: f64,
    pub mass: u64,
}

impl AnchorPlan {
    pub fn txid(&self) -> String {
        self.tx.id().to_string()
    }

    /// Re-verify our own signatures against the recomputed sighash before the
    /// transaction is shown to anyone or broadcast. Cheap, and it means a
    /// signing bug surfaces here rather than as a rejected submission or, worse,
    /// as a printed txid for a transaction that can never confirm.
    pub fn self_check(&self) -> Result<()> {
        let mutable = MutableTransaction::with_entries(self.tx.clone(), self.entries.clone());
        let verifiable = mutable.as_verifiable();
        verify_signatures(&verifiable).map_err(|e| anyhow!("built anchor tx failed self-verification: {e}"))
    }
}

/// Derive the paying address for a wallet key on whatever network the node runs.
pub async fn wallet_address(rpc: &Arc<dyn RpcApi>, key: &Keypair) -> Result<Address> {
    let network = rpc.get_current_network().await.map_err(|e| anyhow!("get_current_network: {e}"))?;
    Ok(address_for(network.into(), key))
}

pub fn address_for(prefix: Prefix, key: &Keypair) -> Address {
    Address::new(prefix, Version::PubKey, &key.x_only_public_key().0.serialize())
}

/// Concatenated attestation ids — 32 bytes each, one or two of them.
pub fn build_payload(ids: &[[u8; 32]]) -> Result<Vec<u8>> {
    match ids.len() {
        0 => bail!("anchor needs at least one attestation id"),
        1 | 2 => Ok(ids.concat()),
        n => bail!(
            "anchor commits at most two ids (one settlement, two mirrored chains); got {n}. \
             Anchor the rest in a separate transaction."
        ),
    }
}

/// Serialized size and compute mass of the transaction shape we build.
/// Mirrors rusty-kaspa's own `rothschild` estimator for v2.0.1 transactions.
fn estimate_mass(num_inputs: usize, num_outputs: u64, payload_len: usize) -> (u64, u64) {
    let serialized_bytes = 94 // version, counts, locktime, subnetwork id, gas, payload hash + len
        + 118 * (num_inputs as u64) // outpoint + sig script + sequence
        + 53 * num_outputs // value + spk
        + payload_len as u64;
    let compute_mass = serialized_bytes
        + 1000 * (num_inputs as u64) // one sigop per input
        + 370 * num_outputs;
    (compute_mass, serialized_bytes)
}

/// KIP-9 storage mass for this selection paying out a single output, using
/// consensus's own formula rather than an approximation of it.
fn storage_mass(selection: &[(TransactionOutpoint, UtxoEntry)], out_spk: &ScriptPublicKey, out_value: u64) -> u64 {
    if out_value == 0 {
        return u64::MAX;
    }
    let ins: Vec<UtxoCell> = selection.iter().map(|(_, e)| UtxoCell::from(e)).collect();
    let out = UtxoCell::new(utxo_plurality(out_spk, false), out_value);
    calc_storage_mass(false, ins.into_iter(), std::iter::once(out), STORAGE_MASS_PARAMETER)
        .unwrap_or(u64::MAX)
}

/// Fee and total mass for a selection, or `None` if it cannot pay for itself.
///
/// Storage mass depends on the change value, which depends on the fee, which
/// depends on the mass — so this iterates to a fixed point. For a consolidation
/// whose single output is worth roughly the sum of its inputs, the storage term
/// is zero and this settles on the first pass; it only does real work when the
/// inputs are small enough for KIP-9 to bite.
fn solve_fee(
    selection: &[(TransactionOutpoint, UtxoEntry)],
    total_in: u64,
    payload_len: usize,
    feerate: f64,
    out_spk: &ScriptPublicKey,
) -> Option<(u64, u64)> {
    let (compute_mass, serialized_bytes) = estimate_mass(selection.len(), 1, payload_len);
    // Transient (bandwidth) mass is normalized against compute mass; the
    // network charges whichever of the three binds.
    let non_storage = compute_mass.max(serialized_bytes * 2);
    let mut mass = non_storage;
    for _ in 0..4 {
        let fee = (mass as f64 * feerate).ceil() as u64;
        if total_in <= fee {
            return None;
        }
        let next = non_storage.max(storage_mass(selection, out_spk, total_in - fee));
        if next == mass {
            return Some((fee, mass));
        }
        mass = next;
    }
    None
}

fn is_spendable(entry: &RpcUtxoEntry, virtual_daa_score: u64) -> bool {
    let needed = if entry.is_coinbase { COINBASE_MATURITY } else { UTXO_MIN_CONFIRMATIONS };
    virtual_daa_score >= entry.block_daa_score.saturating_add(needed)
}

/// The wallet's spendable outpoints, and the address they belong to.
///
/// These are the outpoints eligible to be named as an attestation's `anchor`:
/// you pick one, both parties sign an attestation naming it, and the anchor
/// transaction then spends exactly that outpoint.
pub async fn spendable(
    rpc: &Arc<dyn RpcApi>,
    key: &Keypair,
) -> Result<(Address, Vec<(TransactionOutpoint, UtxoEntry)>)> {
    let address = wallet_address(rpc, key).await?;
    let dag = rpc.get_block_dag_info().await.map_err(|e| anyhow!("get_block_dag_info: {e}"))?;
    let entries = rpc
        .get_utxos_by_addresses(vec![address.clone()])
        .await
        .map_err(|e| {
            anyhow!(
                "get_utxos_by_addresses: {e}\n\
                 (this RPC needs the node started with --utxoindex)"
            )
        })?;
    let utxos = entries
        .into_iter()
        .filter(|e| is_spendable(&e.utxo_entry, dag.virtual_daa_score))
        .map(|e| (TransactionOutpoint::from(e.outpoint), UtxoEntry::from(e.utxo_entry)))
        .collect();
    Ok((address, utxos))
}

/// Fetch UTXOs, select enough to cover the fee, and build + sign the anchor tx.
///
/// `must_spend` is the outpoint the attestations name as their anchor. It is
/// pinned as an input, because that spend is precisely what verification looks
/// for — an anchor transaction that does not consume it proves nothing.
pub async fn build(
    rpc: &Arc<dyn RpcApi>,
    key: &Keypair,
    ids: &[[u8; 32]],
    feerate_override: Option<f64>,
    must_spend: TransactionOutpoint,
) -> Result<AnchorPlan> {
    // Fail on a malformed id set before doing any network work.
    build_payload(ids)?;
    let (address, utxos) = spendable(rpc, key).await?;
    if utxos.is_empty() {
        bail!(
            "no spendable UTXOs for {address}\n\
             Fund that address (and let coinbase outputs mature) before anchoring."
        );
    }

    let feerate = match feerate_override {
        Some(f) if f > 0.0 => f,
        _ => rpc
            .get_fee_estimate()
            .await
            .ok()
            .and_then(|est| est.normal_buckets.first().map(|b| b.feerate))
            .filter(|f| f.is_finite() && *f > 0.0)
            .unwrap_or(MIN_FEERATE)
            .max(MIN_FEERATE),
    };

    plan_tx(&address, key, utxos, ids, feerate, Some(must_spend))
}

/// The pure half of [`build`]: given a funded address's UTXOs, select inputs,
/// compute the fee, and produce a signed anchor transaction. No I/O, so this is
/// what the tests drive.
pub fn plan_tx(
    address: &Address,
    key: &Keypair,
    mut utxos: Vec<(TransactionOutpoint, UtxoEntry)>,
    ids: &[[u8; 32]],
    feerate: f64,
    must_spend: Option<TransactionOutpoint>,
) -> Result<AnchorPlan> {
    let payload = build_payload(ids)?;
    // Largest first: fewest inputs, smallest fee.
    utxos.sort_by_key(|(_, e)| std::cmp::Reverse(e.amount));

    // The pinned outpoint goes in first; everything else only tops up the fee.
    if let Some(pinned) = must_spend {
        let at = utxos.iter().position(|(op, _)| *op == pinned).ok_or_else(|| {
            anyhow!(
                "outpoint {}:{} is not a spendable UTXO of {address} — an anchor must spend the \
                 outpoint its attestations name, so it has to be yours, unspent and mature. \
                 Run `krep wallet-utxos` to see what is available.",
                pinned.transaction_id,
                pinned.index
            )
        })?;
        let pinned_utxo = utxos.remove(at);
        utxos.insert(0, pinned_utxo);
    }

    let script_public_key = pay_to_address_script(address);

    // Accumulate inputs until the selection covers its own fee with change left.
    let mut selected: Vec<(TransactionOutpoint, UtxoEntry)> = Vec::new();
    let mut total_in = 0u64;
    let mut solved: Option<(u64, u64)> = None;
    for utxo in utxos.into_iter().take(MAX_INPUTS) {
        total_in += utxo.1.amount;
        selected.push(utxo);
        if let Some(found) = solve_fee(&selected, total_in, payload.len(), feerate, &script_public_key) {
            solved = Some(found);
            break;
        }
    }
    let Some((fee, mass)) = solved else {
        bail!(
            "insufficient funds at {address}: {total_in} sompi across {} UTXO(s) cannot cover the \
             fee for a {}-byte-payload anchor at feerate {feerate}. Fund the address with more, \
             or fewer and larger, UTXOs.",
            selected.len(),
            payload.len()
        );
    };

    let out_value = total_in - fee;
    let inputs = selected
        .iter()
        .map(|(op, _)| TransactionInput {
            previous_outpoint: *op,
            signature_script: vec![],
            sequence: 0,
            compute_commit: ComputeCommit::SigopCount(1.into()),
        })
        .collect();
    let outputs = vec![TransactionOutput { value: out_value, script_public_key, covenant: None }];

    let unsigned = Transaction::new_non_finalized(
        TX_VERSION,
        inputs,
        outputs,
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        payload.clone(),
    );
    let entries: Vec<UtxoEntry> = selected.iter().map(|(_, e)| e.clone()).collect();
    let signable = MutableTransaction::with_entries(unsigned, entries.clone());
    let tx = sign(signable, *key).tx;

    Ok(AnchorPlan {
        tx,
        entries,
        address: address.clone(),
        payload,
        input_count: selected.len(),
        total_in,
        out_value,
        fee,
        feerate,
        mass,
    })
}

/// Broadcast. Deliberately separate from [`build`] so that constructing an
/// anchor is always a pure, reversible operation and spending is an explicit,
/// separate act.
pub async fn submit(rpc: &Arc<dyn RpcApi>, plan: &AnchorPlan) -> Result<String> {
    let txid = rpc
        .submit_transaction((&plan.tx).into(), false)
        .await
        .context("submit_transaction")?;
    Ok(txid.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionId};
    use secp256k1::Secp256k1;

    fn test_key() -> Keypair {
        Keypair::from_seckey_slice(&Secp256k1::new(), &[7u8; 32]).unwrap()
    }

    fn funded(address: &Address, amounts: &[u64]) -> Vec<(TransactionOutpoint, UtxoEntry)> {
        let spk: ScriptPublicKey = pay_to_address_script(address);
        amounts
            .iter()
            .enumerate()
            .map(|(i, &amount)| {
                (
                    TransactionOutpoint::new(TransactionId::from_bytes([i as u8 + 1; 32]), 0),
                    UtxoEntry::new(amount, spk.clone(), 0, false, None),
                )
            })
            .collect()
    }

    /// Re-verify every input signature against the recomputed sighash, using
    /// consensus's own verifier rather than a reimplementation.
    fn scripts_valid(plan: &AnchorPlan) -> bool {
        let mutable = MutableTransaction::with_entries(plan.tx.clone(), plan.entries.clone());
        let verifiable = mutable.as_verifiable();
        verify_signatures(&verifiable).is_ok()
    }

    #[test]
    fn payload_holds_one_or_two_ids_and_nothing_else() {
        assert!(build_payload(&[]).is_err(), "an anchor with no id is meaningless");
        assert_eq!(build_payload(&[[1u8; 32]]).unwrap().len(), 32);
        assert_eq!(build_payload(&[[1u8; 32], [2u8; 32]]).unwrap().len(), 64);
        assert!(build_payload(&[[1u8; 32], [2u8; 32], [3u8; 32]]).is_err(), "three ids must be refused");

        // The mirror case: both ids present, in order.
        let p = build_payload(&[[1u8; 32], [2u8; 32]]).unwrap();
        assert_eq!(&p[..32], &[1u8; 32]);
        assert_eq!(&p[32..], &[2u8; 32]);
    }

    #[test]
    fn planned_anchor_is_a_valid_signed_transaction() {
        let key = test_key();
        let address = address_for(Prefix::Testnet, &key);
        let id = [0xab; 32];
        let plan = plan_tx(&address, &key, funded(&address, &[500_000_000]), &[id], 1.0, None).unwrap();

        assert_eq!(plan.payload, id.to_vec(), "payload must be exactly the attestation id");
        assert_eq!(plan.input_count, 1);
        assert_eq!(plan.tx.outputs.len(), 1, "self-send consolidation keeps storage mass at zero");
        assert_eq!(plan.out_value, plan.total_in - plan.fee);
        assert!(plan.fee > 0, "an anchor that costs nothing proves nothing");
        assert!(plan.out_value < plan.total_in);

        // The real assertion: consensus script validation accepts our signature.
        assert!(scripts_valid(&plan), "the signed anchor tx must pass script validation");
    }

    #[test]
    fn rewriting_the_payload_invalidates_the_transaction() {
        let key = test_key();
        let address = address_for(Prefix::Testnet, &key);
        let plan = plan_tx(&address, &key, funded(&address, &[500_000_000]), &[[0xab; 32]], 1.0, None).unwrap();
        assert!(scripts_valid(&plan));

        // Strip the anchor commitment out of an otherwise untouched tx. If this
        // still validated, a relay could remove the attestation id for free and
        // the whole anchoring scheme would be worthless.
        let mut tampered = plan.tx.clone();
        tampered.payload = vec![0u8; 32];
        let stripped = AnchorPlan { tx: tampered, ..clone_meta(&plan) };
        assert!(
            !scripts_valid(&stripped),
            "payload must be committed by the signature (sighash includes payload_hash)"
        );
    }

    #[test]
    fn two_ids_share_one_anchor_transaction() {
        let key = test_key();
        let address = address_for(Prefix::Testnet, &key);
        let a = [0x11; 32];
        let b = [0x22; 32];
        let plan = plan_tx(&address, &key, funded(&address, &[500_000_000]), &[a, b], 1.0, None).unwrap();

        assert_eq!(plan.payload.len(), 64);
        assert!(scripts_valid(&plan));
        // Both mirrored attestations verify against this single transaction.
        assert!(krep_core::kaspad::payload_commits(&plan.payload, &a));
        assert!(krep_core::kaspad::payload_commits(&plan.payload, &b));
        assert!(!krep_core::kaspad::payload_commits(&plan.payload, &[0x33; 32]));
    }

    #[test]
    fn selection_pulls_more_inputs_and_refuses_dust() {
        let key = test_key();
        let address = address_for(Prefix::Testnet, &key);

        // One tiny UTXO cannot even cover its own fee.
        let err = plan_tx(&address, &key, funded(&address, &[10]), &[[1u8; 32]], 1.0, None).unwrap_err();
        assert!(err.to_string().contains("insufficient funds"), "got {err}");

        // Several mid-sized UTXOs, none of which covers a fee alone, are
        // consolidated until the selection pays for itself.
        let plan = plan_tx(&address, &key, funded(&address, &[1_500, 1_500, 1_500]), &[[1u8; 32]], 1.0, None).unwrap();
        assert!(plan.input_count > 1, "should have pulled several inputs, got {}", plan.input_count);
        assert!(scripts_valid(&plan));
        assert_eq!(plan.out_value, plan.total_in - plan.fee);
    }

    #[test]
    fn higher_feerate_costs_more() {
        let key = test_key();
        let address = address_for(Prefix::Testnet, &key);
        let cheap = plan_tx(&address, &key, funded(&address, &[500_000_000]), &[[1u8; 32]], 1.0, None).unwrap();
        let dear = plan_tx(&address, &key, funded(&address, &[500_000_000]), &[[1u8; 32]], 10.0, None).unwrap();
        assert!(dear.fee > cheap.fee, "{} vs {}", dear.fee, cheap.fee);
        assert_eq!(dear.mass, cheap.mass, "mass depends on shape, not on feerate");
    }

    #[test]
    fn pinned_outpoint_is_always_spent() {
        let key = test_key();
        let address = address_for(Prefix::Testnet, &key);
        let utxos = funded(&address, &[500_000_000, 400_000_000, 300_000_000]);
        // The smallest one: greedy largest-first selection would never pick it.
        let pinned = utxos[2].0;

        let plan =
            plan_tx(&address, &key, utxos.clone(), &[[1u8; 32]], 1.0, Some(pinned)).unwrap();
        assert!(
            plan.tx.inputs.iter().any(|i| i.previous_outpoint == pinned),
            "the anchor outpoint must be consumed, or verification finds nothing"
        );
        assert_eq!(plan.tx.inputs[0].previous_outpoint, pinned, "pinned input goes first");
        assert!(scripts_valid(&plan));

        // Without pinning, the largest UTXO alone covers the fee and the small
        // one is left untouched — which is exactly why pinning is required.
        let unpinned = plan_tx(&address, &key, utxos, &[[1u8; 32]], 1.0, None).unwrap();
        assert!(!unpinned.tx.inputs.iter().any(|i| i.previous_outpoint == pinned));
    }

    #[test]
    fn pinning_an_outpoint_we_do_not_own_is_refused() {
        let key = test_key();
        let address = address_for(Prefix::Testnet, &key);
        let stranger = TransactionOutpoint::new(TransactionId::from_bytes([0xee; 32]), 3);

        let err = plan_tx(
            &address,
            &key,
            funded(&address, &[500_000_000]),
            &[[1u8; 32]],
            1.0,
            Some(stranger),
        )
        .unwrap_err();
        assert!(err.to_string().contains("not a spendable UTXO"), "got {err}");
    }

    /// Clone everything but the transaction (which the caller replaces).
    fn clone_meta(p: &AnchorPlan) -> AnchorPlan {
        AnchorPlan {
            tx: p.tx.clone(),
            entries: p.entries.clone(),
            address: p.address.clone(),
            payload: p.payload.clone(),
            input_count: p.input_count,
            total_in: p.total_in,
            out_value: p.out_value,
            fee: p.fee,
            feerate: p.feerate,
            mass: p.mass,
        }
    }
}
