//! Covenant script construction.
//!
//! # Status
//!
//! Incremental. The `OPEN -> CLAIMED` branch is implemented and exercised
//! against the real script VM; the remaining branches (ship, settle,
//! auto-release, dispute, slash, refund) are not yet built, so this must not be
//! used to hold real funds. `covenant_script` is deliberately *not* exposed as
//! a spendable address helper until every branch exists — a covenant with a
//! missing branch is a covenant with unspendable money in it.
//!
//! # Stack discipline
//!
//! The spending signature script supplies, bottom to top:
//!
//! ```text
//! [branch args…] <prev_tx_rest> <prev_tx_payload> <redeem script>
//! ```
//!
//! Branch arguments go *below* the state pair so that `verify_prev_state` can
//! work on the top two items regardless of how many arguments a branch takes.
//!
//! The redeem script first authenticates `prev_tx_payload` by recomputing
//! `blake2b("TransactionID", rest ‖ payload)` and checking it against the
//! outpoint being spent. Only then does it trust the previous state.

use crate::state::{OFF_MAKER, OFF_MAKER_REP, OFF_PHASE, OFF_SHIPPED_AT, OFF_TERMS, OFF_TRACKING, STATE_BYTES};
use crate::{state::Phase, Terms, TX_ID_KEY};
use kaspa_txscript::opcodes::codes::*;
use kaspa_txscript::script_builder::{ScriptBuilder, ScriptBuilderResult};
use kaspa_txscript::EngineFlags;
use secp256k1::XOnlyPublicKey;

/// A builder in covenant mode. The legacy limits (520-byte elements, 10 kB
/// scripts) predate Toccata; a multi-branch covenant and its redeem-script push
/// both exceed them, and these scripts are post-Toccata by construction.
fn builder() -> ScriptBuilder {
    ScriptBuilder::with_flags(EngineFlags { covenants_enabled: true, ..Default::default() })
}

/// Push the sequence that authenticates the supplied previous state.
///
/// Consumes `<rest> <payload>` from the stack and leaves `<payload>`, having
/// proven it is genuinely the payload of the transaction whose output we are
/// spending. Everything downstream may then treat it as fact.
fn verify_prev_state(b: &mut ScriptBuilder) -> ScriptBuilderResult<()> {
    b.add_op(OpDup)? // rest payload payload
        .add_op(OpRot)? // payload payload rest
        .add_op(OpRot)? // payload rest payload
        .add_op(OpCat)? // payload (rest‖payload)
        .add_data(TX_ID_KEY)?
        .add_op(OpBlake2bWithKey)? // payload txid
        .add_op(OpTxInputIndex)?
        .add_op(OpOutpointTxId)? // payload txid actual
        .add_op(OpEqualVerify)?;
    Ok(())
}

/// Require `payload[start..end]` of the *spending* transaction to equal `want`.
fn require_new_field(b: &mut ScriptBuilder, start: usize, end: usize, want: &[u8]) -> ScriptBuilderResult<()> {
    b.add_i64(start as i64)?
        .add_i64(end as i64)?
        .add_op(OpTxPayloadSubstr)?
        .add_data(want)?
        .add_op(OpEqualVerify)?;
    Ok(())
}

/// The `OPEN -> CLAIMED` transition.
///
/// Sig script: `<maker_rep_sig> <prev_rest> <prev_payload> <redeem>`.
///
/// Enforces, in order: the previous state is genuinely OPEN and belongs to this
/// job; the claimant controls the pseudonym they are binding to it; the new
/// state is a well-formed CLAIMED record for the same job with nothing shipped;
/// the escrow continues to the same covenant at output 0; and the escrow's
/// value grows by exactly the bond.
///
/// The *payment* key is not authenticated, and does not need to be: claiming
/// costs the bond, and whoever pays it names the key that gets paid. The
/// *pseudonym* is authenticated, and must be — it is the identity a default
/// lands on, so an unauthenticated one would let a maker name a rival's
/// pseudonym and then default on their behalf.
pub fn claim_branch(terms: &Terms) -> ScriptBuilderResult<Vec<u8>> {
    let terms_id = terms.id();
    let mut b = builder();

    verify_prev_state(&mut b)?; // [rep_sig, payload]
    require_prev_phase_and_job(&mut b, Phase::Open, &terms_id)?;
    b.add_op(OpDrop)?; // [rep_sig]

    // The claimant must control the pseudonym they are binding to this escrow.
    // The key is read out of the *new* state, so the signature proves whoever
    // wrote that field holds it.
    b.add_i64(OFF_MAKER_REP as i64)?
        .add_i64((OFF_MAKER_REP + 32) as i64)?
        .add_op(OpTxPayloadSubstr)?
        .add_op(OpCheckSigVerify)?; // []

    // New state: exact length, then field by field.
    b.add_op(OpTxPayloadLen)?.add_i64(STATE_BYTES as i64)?.add_op(OpNumEqualVerify)?;

    let mut header = Vec::new();
    header.extend_from_slice(&crate::state::MAGIC);
    header.push(crate::state::VERSION);
    header.push(Phase::Claimed.byte());
    require_new_field(&mut b, 0, OFF_TERMS, &header)?;
    require_new_field(&mut b, OFF_TERMS, OFF_TERMS + 32, &terms_id)?;

    // The payment key must not be all zeros, or the escrow would be CLAIMED by
    // nobody and the settlement would have no one to pay. (The pseudonym is
    // already pinned by the signature check above — a zero key cannot sign.)
    b.add_i64(OFF_MAKER as i64)?
        .add_i64((OFF_MAKER + 32) as i64)?
        .add_op(OpTxPayloadSubstr)?
        .add_data(&[0u8; 32])?
        .add_op(OpEqual)?
        .add_op(OpNot)?
        .add_op(OpVerify)?;

    // Nothing may be shipped yet: tracking hash and shipped_at both zero.
    require_new_field(&mut b, OFF_TRACKING, STATE_BYTES, &[0u8; STATE_BYTES - OFF_TRACKING])?;

    // The escrow stays in this same covenant, at output 0.
    b.add_op(OpTxInputIndex)?
        .add_op(OpTxInputSpk)?
        .add_i64(0)?
        .add_op(OpTxOutputSpk)?
        .add_op(OpEqualVerify)?;

    // And its value grows by exactly the bond — no more, no less. Less would
    // under-collateralize the job; more would let a maker park funds where only
    // the buyer can slash them.
    b.add_i64(0)?
        .add_op(OpTxOutputAmount)?
        .add_op(OpTxInputIndex)?
        .add_op(OpTxInputAmount)?
        .add_i64(terms.maker_bond as i64)?
        .add_op(OpAdd)?
        .add_op(OpNumEqual)?;

    Ok(b.drain())
}


/// Serialized `ScriptPublicKey` prefix for a pay-to-pubkey output: the u16
/// version big-endian, then the push opcode. `OpTxOutputSpk` pushes exactly
/// `version_be ‖ script`, so an expected P2PK output can be rebuilt in-script
/// from a pubkey that is only known at spend time.
fn p2pk_spk_prefix() -> Vec<u8> {
    vec![0x00, 0x00, OpData32]
}

/// Require output `idx` to be a P2PK output paying the pubkey currently on top
/// of the stack, for exactly `amount`. Consumes the pubkey.
fn require_p2pk_output(b: &mut ScriptBuilder, idx: i64, amount: u64) -> ScriptBuilderResult<()> {
    // Rebuild "0x0000 ‖ OpData32 ‖ <pubkey> ‖ OpCheckSig" and compare.
    b.add_data(&p2pk_spk_prefix())?
        .add_op(OpSwap)?
        .add_op(OpCat)?
        .add_data(&[OpCheckSig])?
        .add_op(OpCat)?
        .add_i64(idx)?
        .add_op(OpTxOutputSpk)?
        .add_op(OpEqualVerify)?;
    // The escrow pays out in full; whoever settles supplies a separate input
    // for the fee. Letting the covenant leak value into fees would make the
    // payout depend on the settler's fee choice.
    b.add_i64(idx)?.add_op(OpTxOutputAmount)?.add_i64(amount as i64)?.add_op(OpNumEqualVerify)?;
    Ok(())
}

/// Require the previous state (on top of stack, left in place) to be `phase`
/// and to belong to this job.
fn require_prev_phase_and_job(b: &mut ScriptBuilder, phase: Phase, terms_id: &[u8; 32]) -> ScriptBuilderResult<()> {
    b.add_op(OpDup)?
        .add_i64(OFF_PHASE as i64)?
        .add_i64((OFF_PHASE + 1) as i64)?
        .add_op(OpSubstr)?
        .add_data(&[phase.byte()])?
        .add_op(OpEqualVerify)?;
    b.add_op(OpDup)?
        .add_i64(OFF_TERMS as i64)?
        .add_i64((OFF_TERMS + 32) as i64)?
        .add_op(OpSubstr)?
        .add_data(terms_id)?
        .add_op(OpEqualVerify)?;
    Ok(())
}

/// Header bytes (`magic ‖ version ‖ phase`) that a new state must begin with.
fn header_for(phase: Phase) -> Vec<u8> {
    let mut header = Vec::new();
    header.extend_from_slice(&crate::state::MAGIC);
    header.push(crate::state::VERSION);
    header.push(phase.byte());
    header
}

/// Payload size of a terminal (SETTLED / SLASH / REFUND) transaction:
/// `owner_attestation_id ‖ counterparty_attestation_id`, zero-filled where a
/// side declines to record one. Fixing the size is what makes the covenant a
/// *rep-aware* escrow — settlement cannot quietly skip leaving room for the
/// attestation that the settlement is supposed to produce.
pub const TERMINAL_PAYLOAD_BYTES: usize = 64;

/// The `CLAIMED -> SHIPPED` transition: the maker attests a tracking hash.
///
/// Sig script: `<maker_sig> <prev_rest> <prev_payload> <redeem>`.
///
/// The escrow's value is untouched — shipping moves the job forward without
/// moving money, so the buyer's dispute window and the bond both survive it.
pub fn ship_branch(terms: &Terms) -> ScriptBuilderResult<Vec<u8>> {
    let terms_id = terms.id();
    let mut b = builder();
    verify_prev_state(&mut b)?; // [sig, payload]
    require_prev_phase_and_job(&mut b, Phase::Claimed, &terms_id)?;

    // The maker named in the previous state is the only one who may ship, and
    // the new state must keep naming them.
    b.add_op(OpDup)? // [sig, payload, payload]
        .add_i64(OFF_MAKER as i64)?
        .add_i64((OFF_MAKER + 32) as i64)?
        .add_op(OpSubstr)? // [sig, payload, maker]
        .add_op(OpDup)?
        .add_i64(OFF_MAKER as i64)?
        .add_i64((OFF_MAKER + 32) as i64)?
        .add_op(OpTxPayloadSubstr)?
        .add_op(OpEqualVerify)? // [sig, payload, maker]
        .add_op(OpRot)? // [payload, maker, sig]
        .add_op(OpSwap)? // [payload, sig, maker]
        .add_op(OpCheckSigVerify)? // [payload]
        .add_op(OpDrop)?; // []

    // New state: SHIPPED, same job, with a real tracking hash.
    b.add_op(OpTxPayloadLen)?.add_i64(STATE_BYTES as i64)?.add_op(OpNumEqualVerify)?;
    require_new_field(&mut b, 0, OFF_TERMS, &header_for(Phase::Shipped))?;
    require_new_field(&mut b, OFF_TERMS, OFF_TERMS + 32, &terms_id)?;
    b.add_i64(OFF_TRACKING as i64)?
        .add_i64((OFF_TRACKING + 32) as i64)?
        .add_op(OpTxPayloadSubstr)?
        .add_data(&[0u8; 32])?
        .add_op(OpEqual)?
        .add_op(OpNot)?
        .add_op(OpVerify)?;

    // `shipped_at` must be the transaction's own lock time. Consensus refuses
    // to include a transaction before its lock time, so the maker cannot claim
    // to have shipped in the future; and the auto-release clock is a relative
    // timelock on this output, so understating it buys nothing either.
    b.add_op(OpTxLockTime)?
        .add_i64(8)?
        .add_op(OpNum2Bin)?
        .add_i64(OFF_SHIPPED_AT as i64)?
        .add_i64((OFF_SHIPPED_AT + 8) as i64)?
        .add_op(OpTxPayloadSubstr)?
        .add_op(OpEqualVerify)?;

    // Same covenant, same value.
    b.add_op(OpTxInputIndex)?.add_op(OpTxInputSpk)?.add_i64(0)?.add_op(OpTxOutputSpk)?.add_op(OpEqualVerify)?;
    b.add_i64(0)?
        .add_op(OpTxOutputAmount)?
        .add_op(OpTxInputIndex)?
        .add_op(OpTxInputAmount)?
        .add_op(OpNumEqual)?;
    Ok(b.drain())
}

/// The `SHIPPED -> SETTLED` transition: the buyer releases.
///
/// Sig script: `<buyer_sig> <prev_rest> <prev_payload> <redeem>`.
///
/// Reward and bond both go to the maker, and the payload must carry the
/// attestation ids — this is where reputation becomes a settlement side effect
/// rather than a separate step someone can skip.
pub fn settle_branch(terms: &Terms) -> ScriptBuilderResult<Vec<u8>> {
    let terms_id = terms.id();
    let mut b = builder();
    verify_prev_state(&mut b)?; // [sig, payload]
    require_prev_phase_and_job(&mut b, Phase::Shipped, &terms_id)?;

    // Extract the maker, then check the buyer's release signature.
    b.add_i64(OFF_MAKER as i64)?
        .add_i64((OFF_MAKER + 32) as i64)?
        .add_op(OpSubstr)? // [sig, maker]
        .add_op(OpSwap)? // [maker, sig]
        .add_data(&terms.buyer.serialize())?
        .add_op(OpCheckSigVerify)?; // [maker]

    // Room for the attestations this settlement produces.
    b.add_op(OpTxPayloadLen)?.add_i64(TERMINAL_PAYLOAD_BYTES as i64)?.add_op(OpNumEqualVerify)?;

    require_p2pk_output(&mut b, 0, terms.claimed_value())?;
    b.add_op(OpTrue)?;
    Ok(b.drain())
}


/// The `OPEN -> REFUND` transition: nobody claimed the job before the deadline.
///
/// Sig script: `<buyer_sig> <prev_rest> <prev_payload> <redeem>`.
///
/// No trade happened, so no reputation is produced and the payload must be
/// empty — a refund is not a settlement and must not be able to masquerade as
/// one by carrying attestation-shaped bytes.
pub fn refund_branch(terms: &Terms) -> ScriptBuilderResult<Vec<u8>> {
    let terms_id = terms.id();
    let mut b = builder();
    verify_prev_state(&mut b)?; // [sig, payload]
    require_prev_phase_and_job(&mut b, Phase::Open, &terms_id)?;
    b.add_op(OpDrop)?; // [sig]

    b.add_i64(terms.deadline as i64)?.add_op(OpCheckLockTimeVerify)?;
    b.add_data(&terms.buyer.serialize())?.add_op(OpCheckSigVerify)?; // []

    b.add_op(OpTxPayloadLen)?.add_i64(0)?.add_op(OpNumEqualVerify)?;

    b.add_data(&terms.buyer.serialize())?;
    require_p2pk_output(&mut b, 0, terms.reward)?;
    b.add_op(OpTrue)?;
    Ok(b.drain())
}

/// The `CLAIMED -> SLASH` transition: the maker took the job and never shipped.
///
/// Sig script: `<buyer_sig> <prev_rest> <prev_payload> <redeem>`.
///
/// Reward *and* bond go to the buyer. This is the branch SPEC 1.5 calls the
/// unilateral default path: the payload must carry the attestation ids, and
/// because a defaulter will never co-sign their own default, the fact that this
/// branch executed is what stands in for their signature. The covenant is the
/// counter-signer of record.
pub fn slash_branch(terms: &Terms) -> ScriptBuilderResult<Vec<u8>> {
    let terms_id = terms.id();
    let mut b = builder();
    verify_prev_state(&mut b)?; // [sig, payload]
    require_prev_phase_and_job(&mut b, Phase::Claimed, &terms_id)?;
    b.add_op(OpDrop)?; // [sig]

    b.add_i64(terms.deadline as i64)?.add_op(OpCheckLockTimeVerify)?;
    b.add_data(&terms.buyer.serialize())?.add_op(OpCheckSigVerify)?; // []

    b.add_op(OpTxPayloadLen)?.add_i64(TERMINAL_PAYLOAD_BYTES as i64)?.add_op(OpNumEqualVerify)?;

    b.add_data(&terms.buyer.serialize())?;
    require_p2pk_output(&mut b, 0, terms.claimed_value())?;
    b.add_op(OpTrue)?;
    Ok(b.drain())
}

/// The `SHIPPED -> SETTLED` auto-release: the buyer went quiet.
///
/// Sig script: `<maker_sig> <prev_rest> <prev_payload> <redeem>`.
///
/// The wait is a *relative* timelock on the SHIPPED output, so the clock starts
/// when the job actually shipped and needs no arithmetic on the payload. Buyer
/// silence must not hold a maker's bond hostage indefinitely.
pub fn auto_release_branch(terms: &Terms) -> ScriptBuilderResult<Vec<u8>> {
    let terms_id = terms.id();
    let mut b = builder();
    verify_prev_state(&mut b)?; // [sig, payload]
    require_prev_phase_and_job(&mut b, Phase::Shipped, &terms_id)?;

    b.add_i64(terms.auto_release_delay as i64)?.add_op(OpCheckSequenceVerify)?;

    b.add_i64(OFF_MAKER as i64)?
        .add_i64((OFF_MAKER + 32) as i64)?
        .add_op(OpSubstr)? // [sig, maker]
        .add_op(OpDup)? // [sig, maker, maker]
        .add_op(OpRot)? // [maker, maker, sig]
        .add_op(OpSwap)? // [maker, sig, maker]
        .add_op(OpCheckSigVerify)?; // [maker]

    b.add_op(OpTxPayloadLen)?.add_i64(TERMINAL_PAYLOAD_BYTES as i64)?.add_op(OpNumEqualVerify)?;
    require_p2pk_output(&mut b, 0, terms.claimed_value())?;
    b.add_op(OpTrue)?;
    Ok(b.drain())
}

/// The `SHIPPED -> DISPUTED` transition: the buyer contests delivery.
///
/// Sig script: `<buyer_sig> <prev_rest> <prev_payload> <redeem>`.
///
/// Only available on an arbitrated job. In pure-timeout mode there is nobody to
/// resolve a dispute, so allowing one would strand the escrow forever — the
/// honest configuration is to have no dispute branch at all and let the
/// auto-release timer govern, which is exactly the "lower trust ceiling" the
/// spec attaches to running without an arbiter.
pub fn dispute_branch(terms: &Terms) -> Option<ScriptBuilderResult<Vec<u8>>> {
    terms.arbiter?;
    Some(build_dispute(terms))
}

fn build_dispute(terms: &Terms) -> ScriptBuilderResult<Vec<u8>> {
    let terms_id = terms.id();
    let mut b = builder();
    verify_prev_state(&mut b)?; // [sig, payload]
    require_prev_phase_and_job(&mut b, Phase::Shipped, &terms_id)?;

    // Everything except the phase byte carries over untouched: same maker, same
    // tracking hash, same ship time. A dispute contests the delivery, it does
    // not get to rewrite what was delivered.
    b.add_i64(OFF_MAKER as i64)?
        .add_i64(STATE_BYTES as i64)?
        .add_op(OpSubstr)? // [sig, tail]
        .add_i64(OFF_MAKER as i64)?
        .add_i64(STATE_BYTES as i64)?
        .add_op(OpTxPayloadSubstr)?
        .add_op(OpEqualVerify)?; // [sig]

    b.add_data(&terms.buyer.serialize())?.add_op(OpCheckSigVerify)?; // []

    b.add_op(OpTxPayloadLen)?.add_i64(STATE_BYTES as i64)?.add_op(OpNumEqualVerify)?;
    require_new_field(&mut b, 0, OFF_TERMS, &header_for(Phase::Disputed))?;
    require_new_field(&mut b, OFF_TERMS, OFF_TERMS + 32, &terms_id)?;

    // Money stays put while the dispute is live.
    b.add_op(OpTxInputIndex)?.add_op(OpTxInputSpk)?.add_i64(0)?.add_op(OpTxOutputSpk)?.add_op(OpEqualVerify)?;
    b.add_i64(0)?
        .add_op(OpTxOutputAmount)?
        .add_op(OpTxInputIndex)?
        .add_op(OpTxInputAmount)?
        .add_op(OpNumEqual)?;
    Ok(b.drain())
}

/// Who a resolved dispute pays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// Arbiter sides with the maker: reward + bond to the maker.
    ToMaker,
    /// Arbiter sides with the buyer: reward + bond to the buyer, and the maker
    /// takes the default.
    ToBuyer,
}

/// `DISPUTED -> SETTLED | SLASH`, requiring the arbiter plus the beneficiary.
///
/// Sig script: `<beneficiary_sig> <arbiter_sig> <prev_rest> <prev_payload> <redeem>`.
///
/// This is the 2-of-3 of SPEC 2.3 reduced to the combinations that can actually
/// move money: the arbiter alone cannot pay themselves, and neither party can
/// resolve their own dispute. Buyer-plus-maker agreement is deliberately not a
/// path here — two parties who agree never needed to dispute.
pub fn resolve_branch(terms: &Terms, resolution: Resolution) -> Option<ScriptBuilderResult<Vec<u8>>> {
    let arbiter = terms.arbiter?;
    Some(build_resolve(terms, arbiter, resolution))
}

fn build_resolve(terms: &Terms, arbiter: XOnlyPublicKey, resolution: Resolution) -> ScriptBuilderResult<Vec<u8>> {
    let terms_id = terms.id();
    let mut b = builder();
    verify_prev_state(&mut b)?; // [ben_sig, arb_sig, payload]
    require_prev_phase_and_job(&mut b, Phase::Disputed, &terms_id)?;

    b.add_i64(OFF_MAKER as i64)?
        .add_i64((OFF_MAKER + 32) as i64)?
        .add_op(OpSubstr)? // [ben_sig, arb_sig, maker]
        .add_op(OpSwap)? // [ben_sig, maker, arb_sig]
        .add_data(&arbiter.serialize())?
        .add_op(OpCheckSigVerify)?; // [ben_sig, maker]

    match resolution {
        Resolution::ToMaker => {
            // The maker is both the beneficiary and the second signer.
            b.add_op(OpDup)? // [ben_sig, maker, maker]
                .add_op(OpRot)? // [maker, maker, ben_sig]
                .add_op(OpSwap)? // [maker, ben_sig, maker]
                .add_op(OpCheckSigVerify)?; // [maker]
        }
        Resolution::ToBuyer => {
            b.add_op(OpDrop)? // [ben_sig]
                .add_data(&terms.buyer.serialize())?
                .add_op(OpCheckSigVerify)? // []
                .add_data(&terms.buyer.serialize())?; // [buyer]
        }
    }

    b.add_op(OpTxPayloadLen)?.add_i64(TERMINAL_PAYLOAD_BYTES as i64)?.add_op(OpNumEqualVerify)?;
    require_p2pk_output(&mut b, 0, terms.claimed_value())?;
    b.add_op(OpTrue)?;
    Ok(b.drain())
}


/// Branch selector, pushed as the topmost signature-script item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Branch {
    Claim = 0,
    Ship = 1,
    Settle = 2,
    AutoRelease = 3,
    Dispute = 4,
    ResolveToMaker = 5,
    ResolveToBuyer = 6,
    Slash = 7,
    Refund = 8,
}

impl Branch {
    pub fn selector(self) -> i64 {
        self as i64
    }
}

/// The complete escrow covenant: every branch under one script, and therefore
/// under one address.
///
/// This matters more than it looks. Each branch checks that the escrow stays in
/// "the same covenant" by comparing the spent output's script public key with
/// the one it creates. If branches lived at separate addresses those checks
/// would compare different scripts and the state machine would not actually
/// connect — a claim would produce an output that the ship branch could never
/// recognise. One script, one address, one escrow.
///
/// The signature script supplies `[branch args…] <prev_rest> <prev_payload>
/// <selector> <redeem>`; the dispatcher consumes the selector and hands the
/// rest to the chosen branch untouched.
pub fn covenant_script(terms: &Terms) -> ScriptBuilderResult<Vec<u8>> {
    let mut arms: Vec<(Branch, Vec<u8>)> = vec![
        (Branch::Claim, claim_branch(terms)?),
        (Branch::Ship, ship_branch(terms)?),
        (Branch::Settle, settle_branch(terms)?),
        (Branch::AutoRelease, auto_release_branch(terms)?),
        (Branch::Slash, slash_branch(terms)?),
        (Branch::Refund, refund_branch(terms)?),
    ];
    // Only offered when someone can actually adjudicate.
    if let Some(d) = dispute_branch(terms) {
        arms.push((Branch::Dispute, d?));
        arms.push((Branch::ResolveToMaker, resolve_branch(terms, Resolution::ToMaker).unwrap()?));
        arms.push((Branch::ResolveToBuyer, resolve_branch(terms, Resolution::ToBuyer).unwrap()?));
    }

    let mut b = builder();
    for (branch, code) in &arms {
        b.add_op(OpDup)?
            .add_i64(branch.selector())?
            .add_op(OpNumEqual)?
            .add_op(OpIf)?
            .add_op(OpDrop)?; // the selector itself
        for byte in code {
            b.add_op(*byte)?;
        }
        b.add_op(OpElse)?;
    }
    // Unrecognised selector: fail rather than fall through to anything.
    b.add_op(OpFalse)?;
    for _ in &arms {
        b.add_op(OpEndIf)?;
    }
    Ok(b.drain())
}

/// The escrow's script public key — what a buyer pays to open a job.
pub fn escrow_spk(terms: &Terms) -> ScriptBuilderResult<kaspa_consensus_core::tx::ScriptPublicKey> {
    Ok(kaspa_txscript::pay_to_script_hash_script(&covenant_script(terms)?))
}

/// The escrow's address on a given network — what a buyer sends the reward to.
pub fn escrow_address(terms: &Terms, prefix: kaspa_addresses::Prefix) -> ScriptBuilderResult<kaspa_addresses::Address> {
    let spk = escrow_spk(terms)?;
    Ok(kaspa_txscript::extract_script_pub_key_address(&spk, prefix)
        .expect("a p2sh script public key always yields an address"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::EscrowState;
    use crate::Terms;
    use kaspa_consensus_core::hashing::sighash::{calc_schnorr_signature_hash, SigHashReusedValuesUnsync};
    use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
    use kaspa_consensus_core::hashing::tx::transaction_v0_id_preimage;
    use kaspa_consensus_core::subnets::SubnetworkId;
    use kaspa_consensus_core::tx::{
        ComputeCommit, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint,
        TransactionOutput, UtxoEntry, VerifiableTransaction,
    };
    use kaspa_txscript::caches::Cache;
    use kaspa_txscript::{pay_to_script_hash_script, EngineFlags, TxScriptEngine};
    use kaspa_txscript_errors::TxScriptError;
    use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};

    fn kp(b: u8) -> Keypair {
        Keypair::from_seckey_slice(&Secp256k1::new(), &[b; 32]).unwrap()
    }
    fn key(b: u8) -> XOnlyPublicKey {
        kp(b).x_only_public_key().0
    }

    const BUYER: u8 = 1;
    const BUYER_REP: u8 = 8;
    const ARBITER: u8 = 2;
    const MAKER: u8 = 5;
    const MAKER_REP: u8 = 6;
    const STRANGER: u8 = 9;

    fn terms() -> Terms {
        Terms {
            buyer: key(BUYER),
            buyer_rep: key(BUYER_REP),
            arbiter: Some(key(ARBITER)),
            reward: 500_000_000,
            maker_bond: 100_000_000,
            deadline: 1_000_000,
            auto_release_delay: 50_000,
            file_hash: [7u8; 32],
        }
    }

    fn p2pk(k: u8) -> ScriptPublicKey {
        ScriptPublicKey::new(
            0,
            std::iter::once(OpData32)
                .chain(key(k).serialize())
                .chain(std::iter::once(OpCheckSig))
                .collect(),
        )
    }

    /// The transaction that put the escrow into `state`, plus the pieces a
    /// spender must supply to prove that state.
    fn prior(spk: &ScriptPublicKey, state: &EscrowState, value: u64) -> (Vec<u8>, Vec<u8>, TransactionOutpoint) {
        let tx = Transaction::new(
            0,
            vec![],
            vec![TransactionOutput { value, script_public_key: spk.clone(), covenant: None }],
            0,
            SubnetworkId::from_byte(0),
            0,
            state.encode().to_vec(),
        );
        let preimage = transaction_v0_id_preimage(&tx);
        let split = preimage.len() - tx.payload.len();
        let (rest, payload) = preimage.split_at(split);
        (rest.to_vec(), payload.to_vec(), TransactionOutpoint::new(tx.id(), 0))
    }

    /// A spend attempt, described declaratively so tests can perturb one thing
    /// at a time.
    struct Spend {
        script: Vec<u8>,
        branch: Branch,
        prev_state: EscrowState,
        prev_value: u64,
        new_payload: Vec<u8>,
        outputs: Vec<TransactionOutput>,
        lock_time: u64,
        sequence: u64,
        /// Signed by, if the branch expects a signature argument.
        signer: Option<Keypair>,
        /// Second signature, pushed *below* `signer` (arbiter paths).
        cosigner: Option<Keypair>,
    }

    impl Spend {
        fn new(branch: Branch, terms: &Terms, prev_state: EscrowState, prev_value: u64) -> Self {
            Spend {
                script: covenant_script(terms).unwrap(),
                branch,
                prev_state,
                prev_value,
                new_payload: vec![],
                outputs: vec![],
                lock_time: 0,
                sequence: 0,
                signer: None,
                cosigner: None,
            }
        }
    }

    /// Execute a spend against the real script VM.
    fn run(spend: Spend) -> Result<(), TxScriptError> {
        let selector = spend.branch.selector();
        run_with_raw_selector(spend, selector)
    }

    fn run_with_raw_selector(spend: Spend, selector: i64) -> Result<(), TxScriptError> {
        let spk = pay_to_script_hash_script(&spend.script);
        let (rest, payload, outpoint) = prior(&spk, &spend.prev_state, spend.prev_value);

        // Args are pushed bottom-up: beneficiary sig, then arbiter sig, then
        // the state pair, matching each branch's documented stack.
        let build_sig_script = |sigs: Option<(Vec<u8>, Option<Vec<u8>>)>| {
            let mut b = builder();
            if let Some((primary, second)) = &sigs {
                b.add_data(primary).unwrap();
                if let Some(s2) = second {
                    b.add_data(s2).unwrap();
                }
            }
            b.add_data(&rest)
                .unwrap()
                .add_data(&payload)
                .unwrap()
                .add_i64(selector)
                .unwrap()
                .add_data(&spend.script)
                .unwrap()
                .drain()
        };

        let make_tx = |sig_script: Vec<u8>| {
            Transaction::new(
                0,
                vec![TransactionInput {
                    previous_outpoint: outpoint,
                    signature_script: sig_script,
                    sequence: spend.sequence,
                    compute_commit: ComputeCommit::SigopCount(1.into()),
                }],
                spend.outputs.clone(),
                spend.lock_time,
                SubnetworkId::from_byte(0),
                0,
                spend.new_payload.clone(),
            )
        };
        let entry = UtxoEntry::new(spend.prev_value, spk.clone(), 0, false, None);

        // The signature covers the transaction, so build once unsigned to get
        // the sighash, then rebuild with the signature in place.
        let sig_script = match &spend.signer {
            None => build_sig_script(None),
            Some(k) => {
                let unsigned = make_tx(build_sig_script(None));
                let populated = PopulatedTransaction::new(&unsigned, vec![entry.clone()]);
                let reused = SigHashReusedValuesUnsync::new();
                let hash = calc_schnorr_signature_hash(&populated, 0, SIG_HASH_ALL, &reused);
                let msg = secp256k1::Message::from_digest(hash.as_bytes());
                let sign = |kp: &Keypair| {
                    let mut sig = kp.sign_schnorr(msg).as_ref().to_vec();
                    sig.push(SIG_HASH_ALL.to_u8());
                    sig
                };
                build_sig_script(Some((sign(k), spend.cosigner.as_ref().map(sign))))
            }
        };

        let tx = make_tx(sig_script);
        let populated = PopulatedTransaction::new(&tx, vec![entry]);
        let cache = Cache::new(10_000);
        let reused = SigHashReusedValuesUnsync::new();
        let flags = EngineFlags { covenants_enabled: true, ..Default::default() };
        let ctx = kaspa_txscript::EngineCtx::new(&cache).with_reused(&reused);
        let (input, utxo) = populated.populated_inputs().next().unwrap();
        TxScriptEngine::from_transaction_input(&populated, input, 0, utxo, ctx, flags).execute()
    }

    // ---------------------------------------------------------------- claim

    fn open_state(t: &Terms) -> EscrowState {
        EscrowState::open(t.id())
    }
    fn claimed_state(t: &Terms) -> EscrowState {
        EscrowState {
            phase: Phase::Claimed,
            terms_id: t.id(),
            maker: Some(key(MAKER)),
            maker_rep: Some(key(MAKER_REP)),
            tracking: None,
            shipped_at: 0,
        }
    }
    fn shipped_state(t: &Terms, at: u64) -> EscrowState {
        EscrowState {
            phase: Phase::Shipped,
            terms_id: t.id(),
            maker: Some(key(MAKER)),
            maker_rep: Some(key(MAKER_REP)),
            tracking: Some([0xcc; 32]),
            shipped_at: at,
        }
    }

    fn claim_spend(t: &Terms, new_state: EscrowState, out_value: u64, out_spk: Option<ScriptPublicKey>) -> Spend {
        let spk = out_spk.unwrap_or_else(|| escrow_spk(t).unwrap());
        let mut s = Spend::new(Branch::Claim, t, open_state(t), t.reward);
        s.signer = Some(kp(MAKER_REP));
        s.new_payload = new_state.encode().to_vec();
        s.outputs = vec![TransactionOutput { value: out_value, script_public_key: spk, covenant: None }];
        s
    }

    #[test]
    fn a_well_formed_claim_is_accepted() {
        let t = terms();
        run(claim_spend(&t, claimed_state(&t), t.claimed_value(), None)).expect("an honest claim must succeed");
    }

    #[test]
    fn the_bond_must_actually_be_paid() {
        let t = terms();
        assert!(run(claim_spend(&t, claimed_state(&t), t.claimed_value() - 1, None)).is_err(), "under-funded bond");
        assert!(run(claim_spend(&t, claimed_state(&t), t.claimed_value() + 1, None)).is_err(), "over-funded claim");
        assert!(run(claim_spend(&t, claimed_state(&t), t.reward, None)).is_err(), "no bond at all");
    }

    #[test]
    fn the_escrow_cannot_be_diverted_out_of_the_covenant() {
        let t = terms();
        assert!(
            run(claim_spend(&t, claimed_state(&t), t.claimed_value(), Some(p2pk(MAKER)))).is_err(),
            "escrow must remain in the covenant"
        );
    }

    #[test]
    fn a_claim_must_name_a_maker() {
        let t = terms();
        let mut nobody = claimed_state(&t);
        nobody.maker = None;
        assert!(run(claim_spend(&t, nobody, t.claimed_value(), None)).is_err(), "CLAIMED by nobody");
    }

    #[test]
    fn a_claim_cannot_pretend_the_job_already_shipped() {
        let t = terms();
        let mut sneak = claimed_state(&t);
        sneak.tracking = Some([9u8; 32]);
        sneak.shipped_at = 1;
        assert!(run(claim_spend(&t, sneak, t.claimed_value(), None)).is_err());
    }

    #[test]
    fn a_claim_cannot_retarget_the_escrow_at_another_job() {
        let t = terms();
        let mut swapped = claimed_state(&t);
        swapped.terms_id = Terms { reward: 1, ..terms() }.id();
        assert!(run(claim_spend(&t, swapped, t.claimed_value(), None)).is_err());
    }

    #[test]
    fn a_claim_must_prove_it_controls_the_pseudonym_it_binds() {
        let t = terms();
        // The pseudonym is the identity a default lands on. If naming one did
        // not require holding it, a maker could bind a rival's pseudonym, walk
        // away, and have the default recorded against them instead.
        let mut impostor = claim_spend(&t, claimed_state(&t), t.claimed_value(), None);
        impostor.signer = Some(kp(STRANGER));
        assert!(run(impostor).is_err(), "claiming under someone else's pseudonym must fail");

        // Signing with the *payment* key is not enough either — they are
        // deliberately different identities.
        let mut wrong_key = claim_spend(&t, claimed_state(&t), t.claimed_value(), None);
        wrong_key.signer = Some(kp(MAKER));
        assert!(run(wrong_key).is_err(), "the payment key cannot stand in for the pseudonym");
    }

    #[test]
    fn a_claim_must_name_a_pseudonym() {
        let t = terms();
        let mut anonymous = claimed_state(&t);
        anonymous.maker_rep = None; // encodes as 32 zero bytes
        // A zero key cannot sign, so this fails at the signature check — which
        // is exactly the property that stops a maker opting out of defaults.
        assert!(run(claim_spend(&t, anonymous, t.claimed_value(), None)).is_err());
    }

    #[test]
    fn the_new_state_must_be_the_claimed_phase() {
        let t = terms();
        for phase in [Phase::Open, Phase::Shipped, Phase::Disputed] {
            let mut wrong = claimed_state(&t);
            wrong.phase = phase;
            assert!(run(claim_spend(&t, wrong, t.claimed_value(), None)).is_err(), "claim produced {phase:?}");
        }
    }

    // ----------------------------------------------------------------- ship

    fn ship_spend(t: &Terms, new_state: EscrowState, lock_time: u64, signer: u8) -> Spend {
        let spk = escrow_spk(t).unwrap();
        let mut s = Spend::new(Branch::Ship, t, claimed_state(t), t.claimed_value());
        s.new_payload = new_state.encode().to_vec();
        s.outputs = vec![TransactionOutput { value: t.claimed_value(), script_public_key: spk, covenant: None }];
        s.lock_time = lock_time;
        s.signer = Some(kp(signer));
        s
    }

    #[test]
    fn the_maker_can_ship() {
        let t = terms();
        run(ship_spend(&t, shipped_state(&t, 900), 900, MAKER)).expect("the maker must be able to ship");
    }

    #[test]
    fn only_the_maker_can_ship() {
        let t = terms();
        // The buyer marking the job shipped would start the auto-release clock
        // without anything having been sent.
        assert!(run(ship_spend(&t, shipped_state(&t, 900), 900, BUYER)).is_err(), "buyer must not ship");
        assert!(run(ship_spend(&t, shipped_state(&t, 900), 900, STRANGER)).is_err(), "stranger must not ship");
    }

    #[test]
    fn shipping_requires_a_real_tracking_hash() {
        let t = terms();
        let mut untracked = shipped_state(&t, 900);
        untracked.tracking = Some([0u8; 32]);
        assert!(run(ship_spend(&t, untracked, 900, MAKER)).is_err(), "empty tracking hash");
    }

    #[test]
    fn shipped_at_must_be_the_transactions_own_lock_time() {
        let t = terms();
        // Backdating would shorten the buyer's window before auto-release.
        assert!(run(ship_spend(&t, shipped_state(&t, 100), 900, MAKER)).is_err(), "backdated ship");
        assert!(run(ship_spend(&t, shipped_state(&t, 5_000), 900, MAKER)).is_err(), "postdated ship");
    }

    #[test]
    fn shipping_cannot_move_money_or_change_the_maker() {
        let t = terms();
        let script = ship_branch(&t).unwrap();
        let spk = pay_to_script_hash_script(&script);

        let mut skim = ship_spend(&t, shipped_state(&t, 900), 900, MAKER);
        skim.outputs = vec![TransactionOutput { value: t.claimed_value() - 1, script_public_key: spk, covenant: None }];
        assert!(run(skim).is_err(), "shipping must not skim the escrow");

        let mut divert = ship_spend(&t, shipped_state(&t, 900), 900, MAKER);
        divert.outputs = vec![TransactionOutput {
            value: t.claimed_value(),
            script_public_key: p2pk(MAKER),
            covenant: None,
        }];
        assert!(run(divert).is_err(), "shipping must not pay the escrow out");

        let mut swap_maker = shipped_state(&t, 900);
        swap_maker.maker = Some(key(STRANGER));
        assert!(run(ship_spend(&t, swap_maker, 900, MAKER)).is_err(), "shipping must not re-assign the job");
    }

    #[test]
    fn ship_only_applies_to_a_claimed_escrow() {
        let t = terms();
        let mut from_open = ship_spend(&t, shipped_state(&t, 900), 900, MAKER);
        from_open.prev_state = open_state(&t);
        from_open.prev_value = t.reward;
        assert!(run(from_open).is_err(), "cannot ship a job nobody claimed");
    }

    // --------------------------------------------------------------- settle

    fn settle_spend(t: &Terms, payload: Vec<u8>, out_value: u64, out_spk: ScriptPublicKey, signer: u8) -> Spend {
        let mut s = Spend::new(Branch::Settle, t, shipped_state(t, 900), t.claimed_value());
        s.new_payload = payload;
        s.outputs = vec![TransactionOutput { value: out_value, script_public_key: out_spk, covenant: None }];
        s.signer = Some(kp(signer));
        s
    }

    fn attestation_payload() -> Vec<u8> {
        let mut p = vec![0xa1; 32];
        p.extend_from_slice(&[0xb2; 32]);
        p
    }

    #[test]
    fn the_buyer_can_release_to_the_maker() {
        let t = terms();
        run(settle_spend(&t, attestation_payload(), t.claimed_value(), p2pk(MAKER), BUYER))
            .expect("buyer release must pay the maker reward + bond");
    }

    #[test]
    fn only_the_buyer_can_release() {
        let t = terms();
        // A maker who could release unilaterally would simply take the money.
        assert!(
            run(settle_spend(&t, attestation_payload(), t.claimed_value(), p2pk(MAKER), MAKER)).is_err(),
            "maker must not release"
        );
        assert!(
            run(settle_spend(&t, attestation_payload(), t.claimed_value(), p2pk(MAKER), STRANGER)).is_err(),
            "stranger must not release"
        );
    }

    #[test]
    fn release_must_pay_the_maker_named_in_the_escrow() {
        let t = terms();
        assert!(
            run(settle_spend(&t, attestation_payload(), t.claimed_value(), p2pk(STRANGER), BUYER)).is_err(),
            "payout must go to the maker who did the work"
        );
        assert!(
            run(settle_spend(&t, attestation_payload(), t.claimed_value(), p2pk(BUYER), BUYER)).is_err(),
            "buyer must not redirect the payout to themselves"
        );
    }

    #[test]
    fn release_must_pay_reward_and_bond_in_full() {
        let t = terms();
        assert!(
            run(settle_spend(&t, attestation_payload(), t.reward, p2pk(MAKER), BUYER)).is_err(),
            "the bond must be returned along with the reward"
        );
        assert!(
            run(settle_spend(&t, attestation_payload(), t.claimed_value() - 1, p2pk(MAKER), BUYER)).is_err(),
            "no skimming on the way out"
        );
    }

    #[test]
    fn settlement_must_leave_room_for_the_attestations() {
        let t = terms();
        // This is what makes the escrow rep-aware: you cannot settle without
        // carrying the attestation ids the settlement is supposed to produce.
        for payload in [vec![], vec![0xa1; 32], vec![0xa1; 63], vec![0xa1; 65]] {
            assert!(
                run(settle_spend(&t, payload.clone(), t.claimed_value(), p2pk(MAKER), BUYER)).is_err(),
                "settlement with a {}-byte payload must be rejected",
                payload.len()
            );
        }
    }

    #[test]
    fn settle_only_applies_to_a_shipped_escrow() {
        let t = terms();
        let mut from_claimed = settle_spend(&t, attestation_payload(), t.claimed_value(), p2pk(MAKER), BUYER);
        from_claimed.prev_state = claimed_state(&t);
        assert!(run(from_claimed).is_err(), "cannot release a job that never shipped");
    }

    // --------------------------------------------------------------- refund

    fn disputed_state(t: &Terms) -> EscrowState {
        EscrowState { phase: Phase::Disputed, ..shipped_state(t, 900) }
    }

    fn refund_spend(t: &Terms, lock_time: u64, out_value: u64, out_spk: ScriptPublicKey, signer: u8) -> Spend {
        let mut s = Spend::new(Branch::Refund, t, open_state(t), t.reward);
        s.outputs = vec![TransactionOutput { value: out_value, script_public_key: out_spk, covenant: None }];
        s.lock_time = lock_time;
        s.signer = Some(kp(signer));
        s
    }

    #[test]
    fn an_unclaimed_job_refunds_after_the_deadline() {
        let t = terms();
        run(refund_spend(&t, t.deadline, t.reward, p2pk(BUYER), BUYER)).expect("buyer must get their money back");
    }

    #[test]
    fn refund_is_not_available_before_the_deadline() {
        let t = terms();
        assert!(
            run(refund_spend(&t, t.deadline - 1, t.reward, p2pk(BUYER), BUYER)).is_err(),
            "refunding early would let a buyer pull funding out from under a pending claim"
        );
    }

    #[test]
    fn only_the_buyer_can_refund_and_only_to_themselves() {
        let t = terms();
        assert!(run(refund_spend(&t, t.deadline, t.reward, p2pk(BUYER), STRANGER)).is_err(), "stranger refund");
        assert!(run(refund_spend(&t, t.deadline, t.reward, p2pk(STRANGER), BUYER)).is_err(), "refund elsewhere");
    }

    #[test]
    fn a_refund_cannot_masquerade_as_a_settlement() {
        let t = terms();
        // No trade happened, so a refund must not be able to carry attestation
        // bytes that a naive verifier might read as reputation.
        let mut with_payload = refund_spend(&t, t.deadline, t.reward, p2pk(BUYER), BUYER);
        with_payload.new_payload = attestation_payload();
        assert!(run(with_payload).is_err(), "refund payload must be empty");
    }

    // ---------------------------------------------------------------- slash

    fn slash_spend(t: &Terms, lock_time: u64, out_value: u64, out_spk: ScriptPublicKey, signer: u8) -> Spend {
        let mut s = Spend::new(Branch::Slash, t, claimed_state(t), t.claimed_value());
        s.new_payload = attestation_payload();
        s.outputs = vec![TransactionOutput { value: out_value, script_public_key: out_spk, covenant: None }];
        s.lock_time = lock_time;
        s.signer = Some(kp(signer));
        s
    }

    #[test]
    fn a_maker_who_never_ships_is_slashed_after_the_deadline() {
        let t = terms();
        run(slash_spend(&t, t.deadline, t.claimed_value(), p2pk(BUYER), BUYER))
            .expect("reward and bond must both go to the buyer");
    }

    #[test]
    fn slashing_is_not_available_before_the_deadline() {
        let t = terms();
        assert!(
            run(slash_spend(&t, t.deadline - 1, t.claimed_value(), p2pk(BUYER), BUYER)).is_err(),
            "a buyer must not be able to slash a maker who still has time to ship"
        );
    }

    #[test]
    fn only_the_buyer_can_slash_and_only_to_themselves() {
        let t = terms();
        assert!(run(slash_spend(&t, t.deadline, t.claimed_value(), p2pk(BUYER), MAKER)).is_err());
        assert!(run(slash_spend(&t, t.deadline, t.claimed_value(), p2pk(MAKER), BUYER)).is_err());
        assert!(run(slash_spend(&t, t.deadline, t.claimed_value(), p2pk(STRANGER), BUYER)).is_err());
    }

    #[test]
    fn a_slash_must_carry_the_default_attestation() {
        let t = terms();
        // The unilateral default path: the defaulter will never co-sign, so the
        // execution of this branch is what stands in for their signature. A
        // slash that carried no attestation would destroy the maker's bond
        // without recording why.
        let mut bare = slash_spend(&t, t.deadline, t.claimed_value(), p2pk(BUYER), BUYER);
        bare.new_payload = vec![];
        assert!(run(bare).is_err(), "slash payload must carry the attestation ids");
    }

    #[test]
    fn a_shipped_job_cannot_be_slashed() {
        let t = terms();
        let mut after_ship = slash_spend(&t, t.deadline, t.claimed_value(), p2pk(BUYER), BUYER);
        after_ship.prev_state = shipped_state(&t, 900);
        assert!(run(after_ship).is_err(), "shipping must protect the maker from the slash path");
    }

    // --------------------------------------------------------- auto-release

    fn auto_spend(t: &Terms, sequence: u64, out_value: u64, out_spk: ScriptPublicKey, signer: u8) -> Spend {
        let mut s = Spend::new(Branch::AutoRelease, t, shipped_state(t, 900), t.claimed_value());
        s.new_payload = attestation_payload();
        s.outputs = vec![TransactionOutput { value: out_value, script_public_key: out_spk, covenant: None }];
        s.sequence = sequence;
        s.signer = Some(kp(signer));
        s
    }

    #[test]
    fn the_maker_can_auto_release_after_the_delay() {
        let t = terms();
        run(auto_spend(&t, t.auto_release_delay, t.claimed_value(), p2pk(MAKER), MAKER))
            .expect("buyer silence must not hold the bond hostage forever");
    }

    #[test]
    fn auto_release_waits_for_the_full_delay() {
        let t = terms();
        assert!(
            run(auto_spend(&t, t.auto_release_delay - 1, t.claimed_value(), p2pk(MAKER), MAKER)).is_err(),
            "the buyer's dispute window must not be cut short"
        );
        assert!(run(auto_spend(&t, 0, t.claimed_value(), p2pk(MAKER), MAKER)).is_err(), "no wait at all");
    }

    #[test]
    fn only_the_maker_can_auto_release_and_only_to_themselves() {
        let t = terms();
        assert!(run(auto_spend(&t, t.auto_release_delay, t.claimed_value(), p2pk(MAKER), STRANGER)).is_err());
        assert!(run(auto_spend(&t, t.auto_release_delay, t.claimed_value(), p2pk(STRANGER), MAKER)).is_err());
    }

    // -------------------------------------------------------------- dispute

    fn dispute_spend(t: &Terms, new_state: EscrowState, signer: u8) -> Spend {
        let spk = escrow_spk(t).unwrap();
        let mut s = Spend::new(Branch::Dispute, t, shipped_state(t, 900), t.claimed_value());
        s.new_payload = new_state.encode().to_vec();
        s.outputs = vec![TransactionOutput { value: t.claimed_value(), script_public_key: spk, covenant: None }];
        s.signer = Some(kp(signer));
        s
    }

    #[test]
    fn the_buyer_can_dispute_a_shipment() {
        let t = terms();
        run(dispute_spend(&t, disputed_state(&t), BUYER)).expect("buyer must be able to contest delivery");
    }

    #[test]
    fn only_the_buyer_can_dispute() {
        let t = terms();
        assert!(run(dispute_spend(&t, disputed_state(&t), MAKER)).is_err(), "maker must not dispute themselves");
        assert!(run(dispute_spend(&t, disputed_state(&t), STRANGER)).is_err());
    }

    #[test]
    fn disputing_cannot_rewrite_what_was_delivered() {
        let t = terms();
        // A dispute contests the delivery; it does not get to change who
        // shipped, what they shipped, or when.
        let mut swap_maker = disputed_state(&t);
        swap_maker.maker = Some(key(STRANGER));
        assert!(run(dispute_spend(&t, swap_maker, BUYER)).is_err(), "maker rewritten");

        let mut swap_tracking = disputed_state(&t);
        swap_tracking.tracking = Some([0xee; 32]);
        assert!(run(dispute_spend(&t, swap_tracking, BUYER)).is_err(), "tracking hash rewritten");

        let mut swap_time = disputed_state(&t);
        swap_time.shipped_at = 1;
        assert!(run(dispute_spend(&t, swap_time, BUYER)).is_err(), "ship time rewritten");
    }

    #[test]
    fn pure_timeout_escrows_have_no_dispute_path() {
        // With no arbiter there is nobody to resolve a dispute, so offering one
        // would strand the escrow forever.
        let t = Terms { arbiter: None, ..terms() };
        assert!(dispute_branch(&t).is_none());
        assert!(resolve_branch(&t, Resolution::ToMaker).is_none());
        assert!(resolve_branch(&t, Resolution::ToBuyer).is_none());
    }

    // -------------------------------------------------------------- resolve

    fn resolve_spend(t: &Terms, res: Resolution, out_spk: ScriptPublicKey, beneficiary: u8, arbiter: u8) -> Spend {
        let branch = match res {
            Resolution::ToMaker => Branch::ResolveToMaker,
            Resolution::ToBuyer => Branch::ResolveToBuyer,
        };
        let mut s = Spend::new(branch, t, disputed_state(t), t.claimed_value());
        s.new_payload = attestation_payload();
        s.outputs =
            vec![TransactionOutput { value: t.claimed_value(), script_public_key: out_spk, covenant: None }];
        s.signer = Some(kp(beneficiary));
        s.cosigner = Some(kp(arbiter));
        s
    }

    #[test]
    fn an_arbiter_can_resolve_a_dispute_either_way() {
        let t = terms();
        run(resolve_spend(&t, Resolution::ToMaker, p2pk(MAKER), MAKER, ARBITER))
            .expect("arbiter siding with the maker must pay the maker");
        run(resolve_spend(&t, Resolution::ToBuyer, p2pk(BUYER), BUYER, ARBITER))
            .expect("arbiter siding with the buyer must pay the buyer");
    }

    #[test]
    fn resolution_needs_both_the_arbiter_and_the_beneficiary() {
        let t = terms();
        // Neither party can resolve their own dispute unilaterally...
        assert!(
            run(resolve_spend(&t, Resolution::ToMaker, p2pk(MAKER), MAKER, MAKER)).is_err(),
            "maker must not stand in for the arbiter"
        );
        assert!(
            run(resolve_spend(&t, Resolution::ToBuyer, p2pk(BUYER), BUYER, BUYER)).is_err(),
            "buyer must not stand in for the arbiter"
        );
        // ...and the arbiter alone cannot move the money either.
        assert!(
            run(resolve_spend(&t, Resolution::ToMaker, p2pk(MAKER), ARBITER, ARBITER)).is_err(),
            "arbiter alone must not resolve"
        );
    }

    #[test]
    fn a_resolution_cannot_pay_a_third_party() {
        let t = terms();
        assert!(run(resolve_spend(&t, Resolution::ToMaker, p2pk(STRANGER), MAKER, ARBITER)).is_err());
        assert!(run(resolve_spend(&t, Resolution::ToBuyer, p2pk(STRANGER), BUYER, ARBITER)).is_err());
        // And the arbiter cannot pay themselves.
        assert!(run(resolve_spend(&t, Resolution::ToMaker, p2pk(ARBITER), MAKER, ARBITER)).is_err());
    }

    #[test]
    fn resolution_only_applies_to_a_disputed_escrow() {
        let t = terms();
        let mut not_disputed = resolve_spend(&t, Resolution::ToMaker, p2pk(MAKER), MAKER, ARBITER);
        not_disputed.prev_state = shipped_state(&t, 900);
        assert!(run(not_disputed).is_err(), "cannot resolve a dispute that was never raised");
    }

    // ----------------------------------------------------------- dispatcher

    #[test]
    fn every_branch_lives_at_one_address() {
        let t = terms();
        // The whole state machine has to share a single script public key, or
        // the covenant-continuity checks would be comparing different scripts
        // and a claim would produce an output the ship branch cannot recognise.
        let spk = escrow_spk(&t).unwrap();
        let addr = escrow_address(&t, kaspa_addresses::Prefix::Testnet).unwrap();
        assert!(addr.to_string().starts_with("kaspatest:"));
        assert_eq!(spk, kaspa_txscript::pay_to_address_script(&addr));

        // And the address commits to the terms.
        let other = Terms { reward: t.reward + 1, ..terms() };
        assert_ne!(escrow_address(&other, kaspa_addresses::Prefix::Testnet).unwrap(), addr);

        // Dropping the arbiter changes both the branch set and the address.
        let timeout_only = Terms { arbiter: None, ..terms() };
        assert_ne!(escrow_address(&timeout_only, kaspa_addresses::Prefix::Testnet).unwrap(), addr);
        assert!(covenant_script(&timeout_only).unwrap().len() < covenant_script(&t).unwrap().len());
    }

    #[test]
    fn an_unknown_selector_is_rejected() {
        let t = terms();
        // Selector 99 matches no arm; the dispatcher must fail rather than fall
        // through into whichever branch happens to be last.
        let otherwise_valid = claim_spend(&t, claimed_state(&t), t.claimed_value(), None);
        assert!(
            run_with_raw_selector(otherwise_valid, 99).is_err(),
            "unknown selector must not execute anything"
        );
    }

    #[test]
    fn a_branch_cannot_be_run_under_another_branchs_selector() {
        let t = terms();
        // A perfectly valid claim, mislabelled as a settle: the settle arm runs
        // and rejects it. Selector and intent must agree.
        let mut mislabelled = claim_spend(&t, claimed_state(&t), t.claimed_value(), None);
        mislabelled.branch = Branch::Settle;
        assert!(run(mislabelled).is_err(), "claim executed under the settle selector must fail");

        // And a settle mislabelled as a claim.
        let mut wrong_way = settle_spend(&t, attestation_payload(), t.claimed_value(), p2pk(MAKER), BUYER);
        wrong_way.branch = Branch::Claim;
        assert!(run(wrong_way).is_err(), "settle executed under the claim selector must fail");
    }

    #[test]
    fn pure_timeout_escrows_reject_dispute_selectors_outright() {
        let t = Terms { arbiter: None, ..terms() };
        // The arms simply are not in the script, so the selector matches nothing.
        let mut s = Spend::new(Branch::Dispute, &t, shipped_state(&t, 900), t.claimed_value());
        s.new_payload = disputed_state(&t).encode().to_vec();
        s.outputs = vec![TransactionOutput {
            value: t.claimed_value(),
            script_public_key: escrow_spk(&t).unwrap(),
            covenant: None,
        }];
        s.signer = Some(kp(BUYER));
        assert!(run(s).is_err(), "no arbiter means no dispute path at all");
    }
}
