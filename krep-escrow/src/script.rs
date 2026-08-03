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

use crate::state::{OFF_MAKER, OFF_PHASE, OFF_SHIPPED_AT, OFF_TERMS, OFF_TRACKING, STATE_BYTES};
use crate::{state::Phase, Terms, TX_ID_KEY};
use kaspa_txscript::opcodes::codes::*;
use kaspa_txscript::script_builder::{ScriptBuilder, ScriptBuilderResult};

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
/// Enforces, in order: the previous state is genuinely OPEN and belongs to this
/// job; the new state is a well-formed CLAIMED record for the same job with a
/// non-zero maker and nothing shipped; the escrow continues to the same
/// covenant at output 0; and the escrow's value grows by exactly the bond.
///
/// The maker is not authenticated. It does not need to be: claiming costs the
/// bond, and whoever pays it names the pubkey that will be paid on settlement
/// and slashed on default. Claiming "as" someone else means funding their job.
pub fn claim_branch(terms: &Terms) -> ScriptBuilderResult<Vec<u8>> {
    let terms_id = terms.id();
    let mut b = ScriptBuilder::new();

    verify_prev_state(&mut b)?;

    // Previous phase must be OPEN.
    b.add_op(OpDup)?
        .add_i64(OFF_PHASE as i64)?
        .add_i64((OFF_PHASE + 1) as i64)?
        .add_op(OpSubstr)?
        .add_data(&[Phase::Open.byte()])?
        .add_op(OpEqualVerify)?;

    // Previous state must belong to this job. Without this an attacker could
    // splice in the OPEN state of a different, cheaper escrow.
    b.add_i64(OFF_TERMS as i64)?
        .add_i64((OFF_TERMS + 32) as i64)?
        .add_op(OpSubstr)?
        .add_data(&terms_id)?
        .add_op(OpEqualVerify)?;

    // New state: exact length, then field by field.
    b.add_op(OpTxPayloadLen)?.add_i64(STATE_BYTES as i64)?.add_op(OpNumEqualVerify)?;

    let mut header = Vec::new();
    header.extend_from_slice(&crate::state::MAGIC);
    header.push(crate::state::VERSION);
    header.push(Phase::Claimed.byte());
    require_new_field(&mut b, 0, OFF_TERMS, &header)?;
    require_new_field(&mut b, OFF_TERMS, OFF_TERMS + 32, &terms_id)?;

    // The maker field must not be all zeros, or the escrow would be CLAIMED by
    // nobody — the bond would be unattributable and the slash path would have
    // no one to blame.
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
    let mut b = ScriptBuilder::new();
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
    let mut b = ScriptBuilder::new();
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
    const ARBITER: u8 = 2;
    const MAKER: u8 = 5;
    const STRANGER: u8 = 9;

    fn terms() -> Terms {
        Terms {
            buyer: key(BUYER),
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
        prev_state: EscrowState,
        prev_value: u64,
        new_payload: Vec<u8>,
        outputs: Vec<TransactionOutput>,
        lock_time: u64,
        sequence: u64,
        /// Signed by, if the branch expects a signature argument.
        signer: Option<Keypair>,
    }

    impl Spend {
        fn new(script: Vec<u8>, prev_state: EscrowState, prev_value: u64) -> Self {
            Spend {
                script,
                prev_state,
                prev_value,
                new_payload: vec![],
                outputs: vec![],
                lock_time: 0,
                sequence: 0,
                signer: None,
            }
        }
    }

    /// Execute a spend against the real script VM.
    fn run(spend: Spend) -> Result<(), TxScriptError> {
        let spk = pay_to_script_hash_script(&spend.script);
        let (rest, payload, outpoint) = prior(&spk, &spend.prev_state, spend.prev_value);

        let build_sig_script = |signature: Option<Vec<u8>>| {
            let mut b = ScriptBuilder::new();
            if let Some(sig) = &signature {
                b.add_data(sig).unwrap();
            }
            b.add_data(&rest).unwrap().add_data(&payload).unwrap().add_data(&spend.script).unwrap().drain()
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
                let mut sig = k.sign_schnorr(msg).as_ref().to_vec();
                sig.push(SIG_HASH_ALL.to_u8());
                build_sig_script(Some(sig))
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
        EscrowState { phase: Phase::Claimed, terms_id: t.id(), maker: Some(key(MAKER)), tracking: None, shipped_at: 0 }
    }
    fn shipped_state(t: &Terms, at: u64) -> EscrowState {
        EscrowState {
            phase: Phase::Shipped,
            terms_id: t.id(),
            maker: Some(key(MAKER)),
            tracking: Some([0xcc; 32]),
            shipped_at: at,
        }
    }

    fn claim_spend(t: &Terms, new_state: EscrowState, out_value: u64, out_spk: Option<ScriptPublicKey>) -> Spend {
        let script = claim_branch(t).unwrap();
        let spk = out_spk.unwrap_or_else(|| pay_to_script_hash_script(&script));
        let mut s = Spend::new(script, open_state(t), t.reward);
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
        let script = ship_branch(t).unwrap();
        let spk = pay_to_script_hash_script(&script);
        let mut s = Spend::new(script, claimed_state(t), t.claimed_value());
        s.new_payload = new_state.encode().to_vec();
        s.outputs = vec![TransactionOutput {
            value: t.claimed_value(),
            script_public_key: spk,
            covenant: None,
        }];
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
        let script = settle_branch(t).unwrap();
        let mut s = Spend::new(script, shipped_state(t, 900), t.claimed_value());
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
}
