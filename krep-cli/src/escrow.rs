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
    /// A wallet output from the same transaction, available to pay the next
    /// fee — but only to the party it actually belongs to.
    pub fee_outpoint: Option<String>,
    pub fee_value: u64,
    /// Address that change was paid to, so the next mover can tell whether it
    /// is theirs to spend.
    #[serde(default)]
    pub fee_address: Option<String>,
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

/// A plain transfer. Escrow participants are separate parties with separate
/// funds — the maker signs their own shipment and pays for it — so standing one
/// up needs a way to move value to them.
pub async fn send(
    rpc: &Arc<dyn RpcApi>,
    key: &Keypair,
    to: &kaspa_addresses::Address,
    amount: u64,
) -> Result<Transaction> {
    let network = rpc.get_current_network().await.map_err(|e| anyhow!("get_current_network: {e}"))?;
    let prefix = kaspa_addresses::Prefix::from(network);
    let (addr, utxos) = wallet_utxos(rpc, key, prefix).await?;
    let fee = covenant_fee(rpc).await;
    let (op, entry) = utxos
        .into_iter()
        .filter(|(_, e)| e.amount > amount + fee)
        .max_by_key(|(_, e)| e.amount)
        .ok_or_else(|| anyhow!("no UTXO at {addr} large enough for {amount} sompi + fees"))?;
    let change = entry.amount - amount - fee;
    Ok(build(
        key,
        &[Input { outpoint: op, entry, unlock: Unlock::Wallet }],
        vec![
            TransactionOutput { value: amount, script_public_key: pay_to_address_script(to), covenant: None },
            TransactionOutput {
                value: change,
                script_public_key: pay_to_address_script(&addr),
                covenant: None,
            },
        ],
        vec![],
        0,
    ))
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
        fee_address: Some(addr.to_string()),
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

    // Whoever performs a transition pays for it out of their own funds.
    //
    // The escrow's own change output is preferred when it belongs to this
    // signer: it is the freshest thing they own and, crucially, is guaranteed
    // not to be double-spent by an in-flight transaction of their own. Picking
    // "largest confirmed UTXO" instead looks reasonable and is not — a party
    // moving twice in a row can select an output their previous, still
    // unconfirmed, transaction already spent.
    let mine = live.fee_address.as_deref() == Some(addr.to_string().as_str());
    let recorded = live.fee_outpoint.as_deref();
    let (fee_outpoint, fee_value) = match (mine, recorded) {
        (true, Some(op)) if live.fee_value >= fee + extra_in => (parse_outpoint(op)?, live.fee_value),
        _ => wallet_utxos(rpc, key, prefix)
            .await?
            .1
            .into_iter()
            .filter(|(_, e)| e.amount > fee + extra_in)
            .max_by_key(|(_, e)| e.amount)
            .map(|(op, e)| (op, e.amount))
            .ok_or_else(|| anyhow!("no spendable funds at {addr} to pay the {fee} sompi fee"))?,
    };
    let change = fee_value - fee - extra_in;

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
            outpoint: fee_outpoint,
            entry: UtxoEntry::new(fee_value, wallet_spk.clone(), 0, false, None),
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
        fee_address: Some(addr.to_string()),
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

// ---------------------------------------------------------------------------
// reputation: deriving attestations from the settlement itself
// ---------------------------------------------------------------------------

/// Coarse volume tier from the reward, in sompi.
///
/// SPEC 1.2 keeps buckets rather than amounts so a reputation chain does not
/// leak a ledger. The boundaries are round numbers of KAS; what matters is that
/// they are fixed and public, so two parties derive the same bucket without
/// negotiating it.
pub fn amount_bucket(reward: u64) -> u8 {
    const KAS: u64 = 100_000_000;
    match reward {
        r if r < 10 * KAS => 1,
        r if r < 100 * KAS => 2,
        r if r < 1_000 * KAS => 3,
        _ => 4,
    }
}

/// The escrow identities *are* the reputation identities here: the covenant
/// names a buyer in its terms and a maker in its state, and those are the
/// pubkeys whose chains the settlement feeds. Splitting payment identity from
/// reputation identity would need a separate binding, which the spec does not
/// yet define.
pub struct Parties {
    pub maker: secp256k1::XOnlyPublicKey,
    pub buyer: secp256k1::XOnlyPublicKey,
}

pub fn parties(terms: &Terms, live: &Live) -> Result<Parties> {
    let state = EscrowState::decode(&hex::decode(&live.prev_payload)?)
        .map_err(|e| anyhow!("cannot read escrow state: {e}"))?;
    Ok(Parties {
        maker: state.maker.ok_or_else(|| anyhow!("escrow names no maker yet"))?,
        buyer: terms.buyer,
    })
}

/// The attestation body a settlement produces for one side.
///
/// Every field is dictated by the escrow — the anchor is the outpoint the
/// settlement will spend, the roles come from who did what, the bucket from the
/// reward. Nothing here is a free choice, which is the point: two parties
/// settling the same escrow derive the same pair of bodies.
#[allow(clippy::too_many_arguments)]
pub fn settlement_body(
    terms: &Terms,
    live: &Live,
    owner: secp256k1::XOnlyPublicKey,
    counterparty: secp256k1::XOnlyPublicKey,
    role: krep_core::Role,
    outcome: krep_core::Outcome,
    prev: Option<[u8; 32]>,
    index: u64,
    ts: u64,
) -> Result<krep_core::AttestationBody> {
    let outpoint = parse_outpoint(&live.outpoint)?;
    Ok(krep_core::AttestationBody {
        v: 1,
        anchor: krep_core::Outpoint {
            txid: outpoint.transaction_id.as_bytes(),
            index: outpoint.index,
        },
        role,
        owner,
        counterparty,
        outcome,
        amount_bucket: amount_bucket(terms.reward),
        prev,
        index,
        ts,
    })
}

/// The default attestation a slash produces against the maker.
///
/// Unlike a settlement's, this one needs nobody's cooperation: it carries no
/// signatures, and its authority is that the slash branch of this covenant
/// executed against an escrow whose state named this maker. The buyer can build
/// it alone, which is exactly what makes "0 defaults" checkable.
pub fn default_attestation(
    terms: &Terms,
    live: &Live,
    prev: Option<[u8; 32]>,
    index: u64,
    ts: u64,
) -> Result<krep_core::Attestation> {
    let p = parties(terms, live)?;
    let body = settlement_body(
        terms,
        live,
        p.maker,
        p.buyer,
        krep_core::Role::Provider,
        krep_core::Outcome::Default,
        prev,
        index,
        ts,
    )?;
    let witness = krep_core::CovenantWitness {
        redeem_script: covenant_script(terms).map_err(|e| anyhow!("{e}"))?,
        branch: Branch::Slash as u8,
        owner_offset: krep_escrow::state::OFF_MAKER as u16,
    };
    let att = krep_core::Attestation {
        body,
        auth: krep_core::Authorization::Covenant { covenant_witness: witness },
    };
    att.verify().map_err(|e| anyhow!("derived default attestation is malformed: {e}"))?;
    Ok(att)
}
