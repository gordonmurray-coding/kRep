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
//! <prev_tx_rest> <prev_tx_payload> [branch args…] <redeem script>
//! ```
//!
//! The redeem script first authenticates `prev_tx_payload` by recomputing
//! `blake2b("TransactionID", rest ‖ payload)` and checking it against the
//! outpoint being spent. Only then does it trust the previous state.

use crate::state::{OFF_MAKER, OFF_PHASE, OFF_TERMS, OFF_TRACKING, STATE_BYTES};
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::EscrowState;
    use crate::Terms;
    use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
    use kaspa_consensus_core::hashing::tx::transaction_v0_id_preimage;
    use kaspa_consensus_core::subnets::SubnetworkId;
    use kaspa_consensus_core::tx::{
        PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput,
        UtxoEntry, VerifiableTransaction,
    };
    use kaspa_txscript::caches::Cache;
    use kaspa_txscript::{pay_to_script_hash_script, EngineFlags, TxScriptEngine};
    use kaspa_txscript_errors::TxScriptError;
    use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};

    fn key(b: u8) -> XOnlyPublicKey {
        Keypair::from_seckey_slice(&Secp256k1::new(), &[b; 32]).unwrap().x_only_public_key().0
    }

    fn terms() -> Terms {
        Terms {
            buyer: key(1),
            arbiter: Some(key(2)),
            reward: 500_000_000,
            maker_bond: 100_000_000,
            deadline: 1_000_000,
            auto_release_delay: 50_000,
            file_hash: [7u8; 32],
        }
    }

    /// Build the transaction that funds the escrow, and return the pieces a
    /// spender must supply to prove its state.
    fn open_escrow(spk: &ScriptPublicKey, terms: &Terms) -> (Vec<u8>, Vec<u8>, TransactionOutpoint) {
        let state = EscrowState::open(terms.id());
        let tx = Transaction::new(
            0,
            vec![],
            vec![TransactionOutput { value: terms.reward, script_public_key: spk.clone(), covenant: None }],
            0,
            SubnetworkId::from_byte(0),
            0,
            state.encode().to_vec(),
        );
        let preimage = transaction_v0_id_preimage(&tx);
        let payload_len = tx.payload.len();
        let (rest, payload) = preimage.split_at(preimage.len() - payload_len);
        (rest.to_vec(), payload.to_vec(), TransactionOutpoint::new(tx.id(), 0))
    }

    struct Claim {
        new_state: EscrowState,
        out_value: u64,
        out_spk: Option<ScriptPublicKey>,
    }

    /// Run the claim branch against the real script VM.
    fn run(terms: &Terms, claim: Claim) -> Result<(), TxScriptError> {
        let script = claim_branch(terms).unwrap();
        let spk = pay_to_script_hash_script(&script);
        let (rest, payload, outpoint) = open_escrow(&spk, terms);

        let sig_script = ScriptBuilder::new()
            .add_data(&rest)
            .unwrap()
            .add_data(&payload)
            .unwrap()
            .add_data(&script)
            .unwrap()
            .drain();

        let tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: outpoint,
                signature_script: sig_script,
                sequence: 0,
                compute_commit: kaspa_consensus_core::tx::ComputeCommit::SigopCount(1.into()),
            }],
            vec![TransactionOutput {
                value: claim.out_value,
                script_public_key: claim.out_spk.unwrap_or(spk.clone()),
                covenant: None,
            }],
            0,
            SubnetworkId::from_byte(0),
            0,
            claim.new_state.encode().to_vec(),
        );
        let entry = UtxoEntry::new(terms.reward, spk, 0, false, None);
        let populated = PopulatedTransaction::new(&tx, vec![entry]);

        let cache = Cache::new(10_000);
        let reused = SigHashReusedValuesUnsync::new();
        let flags = EngineFlags { covenants_enabled: true, ..Default::default() };
        let ctx = kaspa_txscript::EngineCtx::new(&cache).with_reused(&reused);
        let (input, utxo) = populated.populated_inputs().next().unwrap();
        TxScriptEngine::from_transaction_input(&populated, input, 0, utxo, ctx, flags).execute()
    }

    fn claimed(terms: &Terms) -> EscrowState {
        EscrowState {
            phase: Phase::Claimed,
            terms_id: terms.id(),
            maker: Some(key(5)),
            tracking: None,
            shipped_at: 0,
        }
    }

    #[test]
    fn a_well_formed_claim_is_accepted() {
        let t = terms();
        run(&t, Claim { new_state: claimed(&t), out_value: t.claimed_value(), out_spk: None })
            .expect("an honest claim must succeed");
    }

    #[test]
    fn the_bond_must_actually_be_paid() {
        let t = terms();
        // Short by one sompi.
        assert!(
            run(&t, Claim { new_state: claimed(&t), out_value: t.claimed_value() - 1, out_spk: None }).is_err(),
            "an under-funded bond must be rejected"
        );
        // Paying more is also refused: it would park extra funds behind a
        // slash path controlled by the buyer.
        assert!(
            run(&t, Claim { new_state: claimed(&t), out_value: t.claimed_value() + 1, out_spk: None }).is_err(),
            "an over-funded claim must be rejected"
        );
        // Keeping the reward and posting nothing.
        assert!(run(&t, Claim { new_state: claimed(&t), out_value: t.reward, out_spk: None }).is_err());
    }

    #[test]
    fn the_escrow_cannot_be_diverted_out_of_the_covenant() {
        let t = terms();
        // A claim that pays the escrow to an ordinary key instead of back into
        // the covenant would simply steal the buyer's reward.
        let thief = pay_to_script_hash_script(&[OpTrue]);
        assert!(
            run(&t, Claim { new_state: claimed(&t), out_value: t.claimed_value(), out_spk: Some(thief) }).is_err(),
            "escrow must remain in the covenant"
        );
    }

    #[test]
    fn a_claim_must_name_a_maker() {
        let t = terms();
        let mut nobody = claimed(&t);
        nobody.maker = None; // encodes as 32 zero bytes
        assert!(
            run(&t, Claim { new_state: nobody, out_value: t.claimed_value(), out_spk: None }).is_err(),
            "CLAIMED with no maker must be rejected"
        );
    }

    #[test]
    fn a_claim_cannot_pretend_the_job_already_shipped() {
        let t = terms();
        let mut shipped = claimed(&t);
        shipped.tracking = Some([9u8; 32]);
        shipped.shipped_at = 1;
        assert!(
            run(&t, Claim { new_state: shipped, out_value: t.claimed_value(), out_spk: None }).is_err(),
            "claiming straight into a shipped state must be rejected"
        );
    }

    #[test]
    fn a_claim_cannot_retarget_the_escrow_at_another_job() {
        let t = terms();
        let other = Terms { reward: 1, ..terms() };
        let mut swapped = claimed(&t);
        swapped.terms_id = other.id();
        assert!(
            run(&t, Claim { new_state: swapped, out_value: t.claimed_value(), out_spk: None }).is_err(),
            "the new state must stay bound to this job"
        );
    }

    #[test]
    fn the_new_state_must_be_the_claimed_phase() {
        let t = terms();
        for phase in [Phase::Open, Phase::Shipped, Phase::Disputed] {
            let mut wrong = claimed(&t);
            wrong.phase = phase;
            assert!(
                run(&t, Claim { new_state: wrong, out_value: t.claimed_value(), out_spk: None }).is_err(),
                "claim branch must only produce CLAIMED, not {phase:?}"
            );
        }
    }
}
