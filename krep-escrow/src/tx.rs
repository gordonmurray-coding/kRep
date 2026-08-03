//! Building the transactions that move an escrow between phases.
//!
//! Every covenant spend has the same shape: a signature script carrying the
//! branch's arguments, the previous state, the branch selector and the redeem
//! script — plus, usually, an ordinary input to pay the fee, because the
//! covenant pays out its exact value and leaves nothing for one.

use crate::script::Branch;
use kaspa_consensus_core::hashing::sighash::{calc_schnorr_signature_hash, SigHashReusedValuesUnsync};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::hashing::tx::transaction_v0_id_preimage;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    ComputeCommit, PopulatedTransaction, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput,
    UtxoEntry,
};
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::EngineFlags;
use secp256k1::Keypair;

/// Script-unit budget an input commits to, expressed in sigop units — one unit
/// buys 100,000 script units.
///
/// A plain wallet input needs one. A covenant input needs far more: the
/// dispatcher has to scan past every earlier arm to reach the one being taken,
/// so cost grows with the whole script, not just the branch. The arbitrated
/// covenant's last arms measured ~205,000 units, which is why 1 is not enough
/// and why this is generous rather than tight — running out is a rejected
/// transaction, while over-committing only costs a little mass.
const COVENANT_SIGOPS: u8 = 4;
const WALLET_SIGOPS: u8 = 1;

/// A covenant spend carries the whole redeem script and the previous state in
/// its signature script, so these transactions are heavy — a claim measures
/// around 4600 compute mass against a 100 sompi/gram floor. Callers should
/// budget fees from the node's estimate rather than assuming a small transfer.
pub fn builder() -> ScriptBuilder {
    ScriptBuilder::with_flags(EngineFlags { covenants_enabled: true, ..Default::default() })
}

/// How an input is unlocked.
pub enum Unlock {
    /// An ordinary pay-to-pubkey input belonging to the signing wallet.
    Wallet,
    /// A covenant branch.
    Covenant {
        branch: Branch,
        prev_rest: Vec<u8>,
        prev_payload: Vec<u8>,
        /// Keys whose signatures the branch expects beneath the state, in
        /// bottom-to-top push order. Empty for branches that take none (claim);
        /// one for the single-signer branches; two for arbiter resolution,
        /// which needs the beneficiary *and* the arbiter.
        signers: Vec<Keypair>,
        script: Vec<u8>,
    },
}

pub struct Input {
    pub outpoint: TransactionOutpoint,
    pub entry: UtxoEntry,
    pub unlock: Unlock,
}

/// Assemble and sign. Signatures cover the whole transaction, so the sighashes
/// are computed against a skeleton with empty signature scripts and filled in
/// afterwards — signature scripts are not themselves part of the sighash.
///
/// `wallet` signs the ordinary inputs; covenant inputs are signed by whichever
/// keys their branch names, which need not be the same party.
pub fn build(
    wallet: &Keypair,
    inputs: &[Input],
    outputs: Vec<TransactionOutput>,
    payload: Vec<u8>,
    lock_time: u64,
) -> Transaction {
    let skeleton = |scripts: Vec<Vec<u8>>| {
        Transaction::new(
            0,
            inputs
                .iter()
                .zip(scripts)
                .map(|(i, sig)| TransactionInput {
                    previous_outpoint: i.outpoint,
                    signature_script: sig,
                    sequence: 0,
                    compute_commit: ComputeCommit::SigopCount(
                        match i.unlock {
                            Unlock::Wallet => WALLET_SIGOPS,
                            Unlock::Covenant { .. } => COVENANT_SIGOPS,
                        }
                        .into(),
                    ),
                })
                .collect(),
            outputs.clone(),
            lock_time,
            SUBNETWORK_ID_NATIVE,
            0,
            payload.clone(),
        )
    };

    let empty = skeleton(inputs.iter().map(|_| vec![]).collect());
    let entries: Vec<UtxoEntry> = inputs.iter().map(|i| i.entry.clone()).collect();
    let populated = PopulatedTransaction::new(&empty, entries);
    let reused = SigHashReusedValuesUnsync::new();

    let sign = |idx: usize, k: &Keypair| {
        let hash = calc_schnorr_signature_hash(&populated, idx, SIG_HASH_ALL, &reused);
        let msg = secp256k1::Message::from_digest(hash.as_bytes());
        let mut sig = k.sign_schnorr(msg).as_ref().to_vec();
        sig.push(SIG_HASH_ALL.to_u8());
        sig
    };

    let scripts = inputs
        .iter()
        .enumerate()
        .map(|(idx, i)| match &i.unlock {
            Unlock::Wallet => builder().add_data(&sign(idx, wallet)).unwrap().drain(),
            Unlock::Covenant { branch, prev_rest, prev_payload, signers, script } => {
                let mut b = builder();
                for k in signers {
                    b.add_data(&sign(idx, k)).unwrap();
                }
                b.add_data(prev_rest)
                    .unwrap()
                    .add_data(prev_payload)
                    .unwrap()
                    .add_i64(branch.selector())
                    .unwrap()
                    .add_data(script)
                    .unwrap()
                    .drain()
            }
        })
        .collect();

    let mut tx = skeleton(scripts);
    tx.finalize();
    tx
}

/// Split a transaction into the two halves a covenant spender must supply to
/// prove the state it is spending from.
pub fn state_parts(tx: &Transaction) -> (Vec<u8>, Vec<u8>) {
    let preimage = transaction_v0_id_preimage(tx);
    let split = preimage.len() - tx.payload.len();
    let (rest, payload) = preimage.split_at(split);
    (rest.to_vec(), payload.to_vec())
}
