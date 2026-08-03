//! `krep escrow` — driving a FabMesh escrow covenant.
//!
//! # Why there is a state file
//!
//! A covenant spend has to prove which state it is spending from, and doing
//! that means supplying the previous transaction's bytes. kaspad has no
//! transaction index, so recovering those from the chain would mean a full
//! virtual-chain scan for every command — minutes per step. Every participant
//! already knows their own escrow's history, so the client keeps it: each
//! command reads the state file, submits the next transition, and writes the
//! result back. The chain remains the authority; the file is just a cache of
//! things we watched happen.

use anyhow::{anyhow, bail, Context, Result};
use kaspa_consensus_core::tx::{
    Transaction, TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_txscript::pay_to_address_script;
use krep_escrow::script::{covenant_script, escrow_address, escrow_spk, Branch, TERMINAL_PAYLOAD_BYTES};
use krep_escrow::state::{EscrowState, Phase};
use krep_escrow::tx::{build, state_parts, Input, Unlock};
use krep_escrow::Terms;
use secp256k1::Keypair;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

/// Everything the client needs to make the next move.
#[derive(Serialize, Deserialize)]
pub struct EscrowFile {
    pub terms: Terms,
    /// Present once the escrow has been opened.
    pub live: Option<Live>,
}

#[derive(Serialize, Deserialize)]
pub struct Live {
    /// The escrow output currently holding the funds.
    pub outpoint: String,
    pub value: u64,
    pub phase: String,
    /// The transaction that produced it, split for the covenant's state proof.
    pub prev_rest: String,
    pub prev_payload: String,
    /// A wallet output from the same transaction, used to pay the next fee.
    pub fee_outpoint: Option<String>,
    pub fee_value: u64,
}

pub fn load(path: &Path) -> Result<EscrowFile> {
    let s = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(serde_json::from_str(&s)?)
}

pub fn save(path: &Path, f: &EscrowFile) -> Result<()> {
    std::fs::write(path, serde_json::to_string_pretty(f)?)?;
    Ok(())
}

fn parse_outpoint(s: &str) -> Result<TransactionOutpoint> {
    let (id, idx) = s.split_once(':').ok_or_else(|| anyhow!("outpoint must be txid:index"))?;
    Ok(TransactionOutpoint::new(
        id.parse().map_err(|e| anyhow!("bad txid: {e}"))?,
        idx.parse().context("bad output index")?,
    ))
}

/// Fee to budget for a covenant spend. These transactions carry the whole
/// redeem script, so they are far heavier than an ordinary transfer.
pub async fn covenant_fee(rpc: &Arc<dyn RpcApi>) -> u64 {
    let feerate = rpc
        .get_fee_estimate()
        .await
        .ok()
        .and_then(|e| e.normal_buckets.first().map(|b| b.feerate))
        .filter(|f| f.is_finite() && *f > 0.0)
        .unwrap_or(100.0)
        .max(100.0);
    // A covenant spend carries the whole redeem script plus the previous state,
    // and commits several sigop units for script-unit budget, each worth 1000
    // grams. ~12000 mass covers that with room to spare.
    (feerate * 12000.0).ceil() as u64
}

pub async fn wallet_utxos(
    rpc: &Arc<dyn RpcApi>,
    key: &Keypair,
    prefix: kaspa_addresses::Prefix,
) -> Result<(kaspa_addresses::Address, Vec<(TransactionOutpoint, UtxoEntry)>)> {
    let addr = kaspa_addresses::Address::new(
        prefix,
        kaspa_addresses::Version::PubKey,
        &key.x_only_public_key().0.serialize(),
    );
    let dag = rpc.get_block_dag_info().await.map_err(|e| anyhow!("get_block_dag_info: {e}"))?;
    let utxos = rpc
        .get_utxos_by_addresses(vec![addr.clone()])
        .await
        .map_err(|e| anyhow!("get_utxos_by_addresses: {e} (node needs --utxoindex)"))?
        .into_iter()
        .filter(|e| dag.virtual_daa_score >= e.utxo_entry.block_daa_score + 10)
        .map(|e| (TransactionOutpoint::from(e.outpoint), UtxoEntry::from(e.utxo_entry)))
        .collect();
    Ok((addr, utxos))
}

/// Open the escrow: pay the reward in, with the OPEN state as payload.
pub async fn open(rpc: &Arc<dyn RpcApi>, key: &Keypair, terms: &Terms) -> Result<(Transaction, Live)> {
    let network = rpc.get_current_network().await.map_err(|e| anyhow!("get_current_network: {e}"))?;
    let prefix = kaspa_addresses::Prefix::from(network);
    let (addr, utxos) = wallet_utxos(rpc, key, prefix).await?;
    let wallet_spk = pay_to_address_script(&addr);
    let esc_spk = escrow_spk(terms).map_err(|e| anyhow!("building covenant: {e}"))?;
    let fee = covenant_fee(rpc).await;

    let (op, entry) = utxos
        .into_iter()
        .filter(|(_, e)| e.amount > terms.reward + fee * 3)
        .max_by_key(|(_, e)| e.amount)
        .ok_or_else(|| anyhow!("no wallet UTXO large enough to fund {} sompi + fees at {addr}", terms.reward))?;

    let change = entry.amount - terms.reward - fee;
    let tx = build(
        key,
        &[Input { outpoint: op, entry, unlock: Unlock::Wallet }],
        vec![
            TransactionOutput { value: terms.reward, script_public_key: esc_spk, covenant: None },
            TransactionOutput { value: change, script_public_key: wallet_spk, covenant: None },
        ],
        EscrowState::open(terms.id()).encode().to_vec(),
        0,
    );
    let (rest, payload) = state_parts(&tx);
    let live = Live {
        outpoint: format!("{}:0", tx.id()),
        value: terms.reward,
        phase: "open".into(),
        prev_rest: hex::encode(rest),
        prev_payload: hex::encode(payload),
        fee_outpoint: Some(format!("{}:1", tx.id())),
        fee_value: change,
    };
    Ok((tx, live))
}

/// Common shape of every covenant transition: spend the escrow plus a wallet
/// output for the fee, and produce whatever the branch requires.
#[allow(clippy::too_many_arguments)]
async fn transition(
    rpc: &Arc<dyn RpcApi>,
    key: &Keypair,
    terms: &Terms,
    live: &Live,
    branch: Branch,
    signers: Vec<Keypair>,
    extra_in: u64,
    outputs_for: impl Fn(u64, &kaspa_consensus_core::tx::ScriptPublicKey) -> Vec<TransactionOutput>,
    payload: Vec<u8>,
    lock_time: u64,
) -> Result<(Transaction, Live)> {
    let network = rpc.get_current_network().await.map_err(|e| anyhow!("get_current_network: {e}"))?;
    let prefix = kaspa_addresses::Prefix::from(network);
    let (addr, _) = wallet_utxos(rpc, key, prefix).await?;
    let wallet_spk = pay_to_address_script(&addr);
    let esc_spk = escrow_spk(terms).map_err(|e| anyhow!("building covenant: {e}"))?;
    let script = covenant_script(terms).map_err(|e| anyhow!("building covenant: {e}"))?;
    let fee = covenant_fee(rpc).await;

    let fee_op = live
        .fee_outpoint
        .as_deref()
        .ok_or_else(|| anyhow!("no wallet output recorded to pay the fee from"))?;
    if live.fee_value < fee + extra_in {
        bail!("recorded fee output holds {} sompi, need {}", live.fee_value, fee + extra_in);
    }
    let change = live.fee_value - fee - extra_in;

    let inputs = vec![
        Input {
            outpoint: parse_outpoint(&live.outpoint)?,
            entry: UtxoEntry::new(live.value, esc_spk, 0, false, None),
            unlock: Unlock::Covenant {
                branch,
                prev_rest: hex::decode(&live.prev_rest)?,
                prev_payload: hex::decode(&live.prev_payload)?,
                signers,
                script,
            },
        },
        Input {
            outpoint: parse_outpoint(fee_op)?,
            entry: UtxoEntry::new(live.fee_value, wallet_spk.clone(), 0, false, None),
            unlock: Unlock::Wallet,
        },
    ];

    let mut outputs = outputs_for(live.value + extra_in, &wallet_spk);
    outputs.push(TransactionOutput { value: change, script_public_key: wallet_spk, covenant: None });

    let tx = build(key, &inputs, outputs, payload, lock_time);
    let (rest, payload_part) = state_parts(&tx);
    let live_next = Live {
        outpoint: format!("{}:0", tx.id()),
        value: tx.outputs[0].value,
        phase: String::new(), // filled by the caller
        prev_rest: hex::encode(rest),
        prev_payload: hex::encode(payload_part),
        fee_outpoint: Some(format!("{}:{}", tx.id(), tx.outputs.len() - 1)),
        fee_value: change,
    };
    Ok((tx, live_next))
}

pub async fn claim(
    rpc: &Arc<dyn RpcApi>,
    key: &Keypair,
    terms: &Terms,
    live: &Live,
    maker: secp256k1::XOnlyPublicKey,
) -> Result<(Transaction, Live)> {
    let state = EscrowState {
        phase: Phase::Claimed,
        terms_id: terms.id(),
        maker: Some(maker),
        tracking: None,
        shipped_at: 0,
    };
    let esc = escrow_spk(terms).map_err(|e| anyhow!("{e}"))?;
    let claimed_value = terms.claimed_value();
    let (tx, mut next) = transition(
        rpc,
        key,
        terms,
        live,
        Branch::Claim,
        vec![],
        terms.maker_bond,
        move |_, _| vec![TransactionOutput { value: claimed_value, script_public_key: esc.clone(), covenant: None }],
        state.encode().to_vec(),
        0,
    )
    .await?;
    next.phase = "claimed".into();
    Ok((tx, next))
}

pub async fn ship(
    rpc: &Arc<dyn RpcApi>,
    key: &Keypair,
    terms: &Terms,
    live: &Live,
    maker: secp256k1::XOnlyPublicKey,
    tracking: [u8; 32],
) -> Result<(Transaction, Live)> {
    // `shipped_at` must equal the transaction's own lock time, and consensus
    // will not include a transaction before its lock time, so the value is a
    // lower bound on the real shipping moment rather than a claim we trust.
    //
    // It has to be strictly in the past: a transaction whose lock time has not
    // yet passed is "not finalized" and gets rejected, and lock_time equal to
    // the current DAA score counts as not yet passed. Backing off costs about a
    // second of the buyer's dispute window at 10 BPS and makes the transaction
    // acceptable immediately.
    let dag = rpc.get_block_dag_info().await.map_err(|e| anyhow!("{e}"))?;
    let now = dag.virtual_daa_score.saturating_sub(64);
    let state = EscrowState {
        phase: Phase::Shipped,
        terms_id: terms.id(),
        maker: Some(maker),
        tracking: Some(tracking),
        shipped_at: now,
    };
    let esc = escrow_spk(terms).map_err(|e| anyhow!("{e}"))?;
    let value = live.value;
    let (tx, mut next) = transition(
        rpc,
        key,
        terms,
        live,
        Branch::Ship,
        vec![*key],
        0,
        move |_, _| vec![TransactionOutput { value, script_public_key: esc.clone(), covenant: None }],
        state.encode().to_vec(),
        now,
    )
    .await?;
    next.phase = "shipped".into();
    Ok((tx, next))
}

/// Terminal payout: `ids` become the 64-byte attestation payload.
#[allow(clippy::too_many_arguments)]
pub async fn payout(
    rpc: &Arc<dyn RpcApi>,
    key: &Keypair,
    terms: &Terms,
    live: &Live,
    branch: Branch,
    beneficiary: secp256k1::XOnlyPublicKey,
    ids: &[[u8; 32]],
    lock_time: u64,
    signers: Vec<Keypair>,
) -> Result<(Transaction, Live)> {
    if ids.is_empty() || ids.len() > 2 {
        bail!("a settlement commits one or two attestation ids");
    }
    let mut payload = Vec::with_capacity(TERMINAL_PAYLOAD_BYTES);
    for id in ids {
        payload.extend_from_slice(id);
    }
    payload.resize(TERMINAL_PAYLOAD_BYTES, 0);

    let spk = kaspa_consensus_core::tx::ScriptPublicKey::new(
        0,
        std::iter::once(kaspa_txscript::opcodes::codes::OpData32)
            .chain(beneficiary.serialize())
            .chain(std::iter::once(kaspa_txscript::opcodes::codes::OpCheckSig))
            .collect(),
    );
    let value = terms.claimed_value();
    let (tx, mut next) = transition(
        rpc,
        key,
        terms,
        live,
        branch,
        signers,
        0,
        move |_, _| vec![TransactionOutput { value, script_public_key: spk.clone(), covenant: None }],
        payload,
        lock_time,
    )
    .await?;
    next.phase = "settled".into();
    Ok((tx, next))
}

/// Contest a delivery. Only the buyer may, and only on an arbitrated escrow —
/// with nobody to adjudicate, a dispute would strand the funds forever, so the
/// covenant simply has no such branch.
pub async fn dispute(
    rpc: &Arc<dyn RpcApi>,
    key: &Keypair,
    terms: &Terms,
    live: &Live,
) -> Result<(Transaction, Live)> {
    if !terms.arbitrated() {
        bail!("this escrow runs in pure-timeout mode and has no dispute path");
    }
    let prev = EscrowState::decode(&hex::decode(&live.prev_payload)?)
        .map_err(|e| anyhow!("cannot read escrow state: {e}"))?;
    // A dispute contests the delivery; it does not rewrite what was delivered.
    let state = EscrowState { phase: Phase::Disputed, ..prev };
    let esc = escrow_spk(terms).map_err(|e| anyhow!("{e}"))?;
    let value = live.value;
    let (tx, mut next) = transition(
        rpc,
        key,
        terms,
        live,
        Branch::Dispute,
        vec![*key],
        0,
        move |_, _| vec![TransactionOutput { value, script_public_key: esc.clone(), covenant: None }],
        state.encode().to_vec(),
        0,
    )
    .await?;
    next.phase = "disputed".into();
    Ok((tx, next))
}

/// Refund pays only the reward back and carries no payload — no trade happened.
pub async fn refund(
    rpc: &Arc<dyn RpcApi>,
    key: &Keypair,
    terms: &Terms,
    live: &Live,
) -> Result<(Transaction, Live)> {
    let spk = kaspa_consensus_core::tx::ScriptPublicKey::new(
        0,
        std::iter::once(kaspa_txscript::opcodes::codes::OpData32)
            .chain(terms.buyer.serialize())
            .chain(std::iter::once(kaspa_txscript::opcodes::codes::OpCheckSig))
            .collect(),
    );
    let value = terms.reward;
    let deadline = terms.deadline;
    let (tx, mut next) = transition(
        rpc,
        key,
        terms,
        live,
        Branch::Refund,
        vec![*key],
        0,
        move |_, _| vec![TransactionOutput { value, script_public_key: spk.clone(), covenant: None }],
        vec![],
        deadline,
    )
    .await?;
    next.phase = "refunded".into();
    Ok((tx, next))
}

pub fn describe(terms: &Terms, prefix: kaspa_addresses::Prefix) -> Result<String> {
    let addr = escrow_address(terms, prefix).map_err(|e| anyhow!("{e}"))?;
    let script = covenant_script(terms).map_err(|e| anyhow!("{e}"))?;
    Ok(format!(
        "escrow   {addr}\nterms id {}\ncovenant {} bytes, arbiter {}\nreward {} + bond {} = {} sompi\ndeadline DAA {}, auto-release +{}",
        hex::encode(terms.id()),
        script.len(),
        if terms.arbitrated() { "yes" } else { "none (pure timeout)" },
        terms.reward,
        terms.maker_bond,
        terms.claimed_value(),
        terms.deadline,
        terms.auto_release_delay,
    ))
}
