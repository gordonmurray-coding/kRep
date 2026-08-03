//! krep — CLI for kRep attestation chains.
//!
//! Typical flow (two parties, one settled trade):
//!   krep keygen --out seed.hex
//!   krep pubkey --seed seed.hex --context fabmesh
//!   krep create --seed seed.hex --context fabmesh --chain mychain.json \
//!        --anchor <txid>:<n> --role provider --counterparty <hex> \
//!        --outcome success --bucket 2 > partial.json
//!   # counterparty runs:
//!   krep countersign --seed their_seed.hex --context fabmesh < partial.json > att.json
//!   # owner appends and anchors:
//!   krep append --chain mychain.json < att.json
//!   krep anchor --wallet wallet.key --id <attestation id> --rpc grpc://node:16110
//!   krep verify --chain mychain.json --rpc grpc://node:16110
//!   krep score  --chain mychain.json --rpc grpc://node:16110

mod anchor;
mod board;
mod escrow;
mod rpc;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use kaspa_consensus_core::network::NetworkType;
use kaspa_rpc_core::RpcHash;
use kaspa_rpc_core::api::rpc::RpcApi;
use krep_core::chain::Chain;
use krep_core::kaspad::{KaspadAnchorVerifier, ScanConfig};
use krep_core::{
    Attestation, AttestationBody, Outcome, Outpoint, PartialAttestation, Role, countersign,
    create_partial, derive_context_keypair,
};
use rand::RngCore;
use secp256k1::{Keypair, Secp256k1};
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(name = "krep", about = "Pseudonymous reputation chains anchored on Kaspa")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum RoleArg {
    Provider,
    Client,
}

#[derive(Clone, Copy, ValueEnum)]
enum OutcomeArg {
    Success,
    Default,
    DisputedResolved,
}

/// Anchor-verification options shared by `verify` and `score`.
#[derive(Args, Clone)]
struct RpcOpts {
    /// kaspad endpoint: grpc://host:16110 or ws://host:17110. Falls back to $KREP_RPC.
    #[arg(long)]
    rpc: Option<String>,
    /// Skip anchor verification entirely. Proves nothing about Sybil cost.
    #[arg(long)]
    offline: bool,
    /// Chain block hash to start the anchor scan from. Default: the node's pruning point.
    #[arg(long)]
    scan_from: Option<String>,
    /// Acceptance depth required before an anchor counts.
    #[arg(long, default_value_t = 100)]
    min_confirmations: u64,
    /// Runaway guard on the virtual-chain scan. The scan stops at the tip by
    /// itself; a full mainnet history measured ~471 batches / ~19s.
    #[arg(long, default_value_t = 4096)]
    max_batches: usize,
    /// Budget, in blocks, for the forward scan that looks for the transaction
    /// spending each anchor outpoint.
    #[arg(long, default_value_t = 200_000)]
    max_spend_scan_blocks: usize,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a new 32-byte master seed (hex file). Guard it like a wallet seed.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the x-only pubkey (pseudonym) for a seed + context.
    Pubkey {
        #[arg(long)]
        seed: PathBuf,
        #[arg(long)]
        context: String,
    },
    /// Create an owner-signed partial attestation (stdout JSON).
    Create {
        #[arg(long)]
        seed: PathBuf,
        #[arg(long)]
        context: String,
        /// Existing chain file — used to fill prev/index automatically.
        #[arg(long)]
        chain: Option<PathBuf>,
        /// Anchor outpoint: <txid_hex>:<output_index>. This is the outpoint the
        /// settlement transaction will SPEND, not the settlement's own txid —
        /// see `krep wallet-utxos`.
        #[arg(long)]
        anchor: String,
        #[arg(long, value_enum)]
        role: RoleArg,
        /// Counterparty x-only pubkey, hex.
        #[arg(long)]
        counterparty: String,
        #[arg(long, value_enum)]
        outcome: OutcomeArg,
        /// Volume bucket 1..=4.
        #[arg(long)]
        bucket: u8,
        /// Unix seconds; defaults to now.
        #[arg(long)]
        ts: Option<u64>,
    },
    /// Countersign a partial attestation from stdin (stdout: full attestation).
    Countersign {
        /// Master seed; derives the pseudonym with --context.
        #[arg(long, requires = "context")]
        seed: Option<PathBuf>,
        #[arg(long)]
        context: Option<String>,
        /// A raw key file instead — for escrow participants, whose reputation
        /// identity is the pubkey the covenant names.
        #[arg(long, conflicts_with = "seed")]
        wallet: Option<PathBuf>,
        /// Also emit the role-flipped mirror attestation for the countersigner's
        /// own chain, to <path>. Both ids can share one anchor transaction.
        #[arg(long)]
        mirror_out: Option<PathBuf>,
        /// Chain file of the countersigner, used to fill the mirror's prev/index.
        #[arg(long)]
        mirror_chain: Option<PathBuf>,
    },
    /// Append a full attestation (stdin) to a chain file, creating it if missing.
    Append {
        #[arg(long)]
        chain: PathBuf,
    },
    /// Verify a chain: structure, signatures, and on-chain anchoring.
    Verify {
        #[arg(long)]
        chain: PathBuf,
        #[command(flatten)]
        rpc: RpcOpts,
    },
    /// Print the default score breakdown for a chain (anchored attestations only).
    Score {
        #[arg(long)]
        chain: PathBuf,
        #[command(flatten)]
        rpc: RpcOpts,
    },
    /// Print an attestation's id (the value the settlement tx payload must commit).
    Id,
    /// Generate a 32-byte wallet key for paying anchor fees. Not a krep seed.
    WalletNew {
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the Kaspa address for a wallet key.
    WalletAddress {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    /// Print a wallet key's x-only pubkey — what escrow terms name.
    WalletPubkey {
        #[arg(long)]
        wallet: PathBuf,
    },
    /// Send funds to an address. Enough to stand up counterparties for testing.
    Send {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        rpc: Option<String>,
        #[arg(long)]
        submit: bool,
    },
    /// List the wallet's spendable outpoints — candidates to name as an anchor.
    WalletUtxos {
        #[arg(long)]
        wallet: PathBuf,
        /// kaspad endpoint. Falls back to $KREP_RPC.
        #[arg(long)]
        rpc: Option<String>,
    },
    /// Build a payload-carrying transaction committing one or two attestation
    /// ids. Prints the signed transaction; broadcasts only with --submit.
    Anchor {
        /// Wallet key file (64 hex chars) that pays the fee.
        #[arg(long)]
        wallet: PathBuf,
        /// Attestation id to commit, hex. Repeat for a second (mirror) id.
        #[arg(long = "id", required = true)]
        ids: Vec<String>,
        /// The outpoint to spend — must equal the `anchor` those attestations
        /// name. Verification looks for the transaction that consumes it.
        #[arg(long)]
        spend: String,
        /// kaspad endpoint. Falls back to $KREP_RPC.
        #[arg(long)]
        rpc: Option<String>,
        /// Broadcast immediately. What is built is what is sent.
        #[arg(long)]
        submit: bool,
        /// Write the signed transaction here for review, then send it verbatim
        /// with `krep submit`. Rebuilding would pay a different (live) fee and
        /// so produce a different txid.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Override feerate in sompi per gram. Pins the fee, making the build
        /// reproducible.
        #[arg(long)]
        fee_rate: Option<f64>,
    },
    /// The FabMesh job board, over Nostr.
    Job {
        #[command(subcommand)]
        cmd: JobCmd,
    },
    /// Drive a FabMesh escrow covenant.
    Escrow {
        #[command(subcommand)]
        cmd: EscrowCmd,
    },
    /// Broadcast a signed transaction written by `krep anchor --out`.
    Submit {
        #[arg(long)]
        tx: PathBuf,
        /// kaspad endpoint. Falls back to $KREP_RPC.
        #[arg(long)]
        rpc: Option<String>,
    },
}

#[derive(clap::Args, Clone)]
struct RelayOpts {
    /// Relay to use. Repeatable; falls back to $KREP_RELAYS (comma separated).
    /// Several is the point — one relay dropping a job only censors whoever
    /// asked it alone.
    #[arg(long = "relay")]
    relays: Vec<String>,
}

#[derive(Subcommand)]
enum JobCmd {
    /// Publish a job, deriving its terms from the escrow that backs it.
    Post {
        /// The escrow this job is backed by. Reward, bond, deadline and file
        /// hash all come from it, so the posting cannot advertise terms the
        /// escrow will not honour.
        #[arg(long)]
        escrow: PathBuf,
        /// The buyer's pseudonym — also their Nostr identity.
        #[arg(long, requires = "context")]
        seed: PathBuf,
        #[arg(long)]
        context: Option<String>,
        /// Stable identifier for this posting; editing it replaces the job.
        #[arg(long)]
        job_id: String,
        #[arg(long)]
        process: String,
        #[arg(long)]
        material: String,
        #[arg(long, default_value = "standard")]
        tolerance: String,
        #[arg(long, default_value_t = 1)]
        qty: u32,
        /// Coarse only — continent or country. Never a street address.
        #[arg(long)]
        region: String,
        /// Where the *encrypted* design file lives.
        #[arg(long)]
        file_ptr: String,
        /// The buyer's chain head, if they publish one.
        #[arg(long)]
        rep_head: Option<String>,
        #[command(flatten)]
        relay: RelayOpts,
    },
    /// List open jobs.
    List {
        #[arg(long)]
        process: Option<String>,
        #[arg(long)]
        region: Option<String>,
        #[command(flatten)]
        relay: RelayOpts,
    },
    /// Claim a job, advertising reputation and a funded bond.
    Claim {
        #[arg(long)]
        job_addr: String,
        /// The maker's pseudonym — the identity the escrow will bind.
        #[arg(long, requires = "context")]
        seed: PathBuf,
        #[arg(long)]
        context: Option<String>,
        /// The maker's chain, to advertise its head.
        #[arg(long)]
        chain: Option<PathBuf>,
        /// Payment key the escrow should pay on settlement.
        #[arg(long)]
        payment: String,
        /// Transaction that funded the bond, so the buyer can check it.
        #[arg(long)]
        bond_txid: String,
        #[arg(long)]
        note: Option<String>,
        #[command(flatten)]
        relay: RelayOpts,
    },
    /// Show the claims on a job.
    Claims {
        #[arg(long)]
        job_addr: String,
        #[command(flatten)]
        relay: RelayOpts,
    },
    /// Designate a winning claim and point it at the funded escrow.
    Accept {
        #[arg(long)]
        job_addr: String,
        #[arg(long, requires = "context")]
        seed: PathBuf,
        #[arg(long)]
        context: Option<String>,
        #[arg(long)]
        claim_id: String,
        /// The opened escrow the winner should claim against.
        #[arg(long)]
        escrow: PathBuf,
        #[arg(long, default_value = "mainnet")]
        network: String,
        #[command(flatten)]
        relay: RelayOpts,
    },
    /// Has this job been awarded, and to whom? What a maker polls after claiming.
    Awarded {
        #[arg(long)]
        job_addr: String,
        #[command(flatten)]
        relay: RelayOpts,
    },
    /// Send a private message — the shipping address, or the file's key.
    ///
    /// The relay sees a message addressed to the recipient from a throwaway
    /// key, and learns nothing about who sent it or what it says.
    Dm {
        /// Sender's pseudonym.
        #[arg(long, requires = "context")]
        seed: PathBuf,
        #[arg(long)]
        context: Option<String>,
        /// Recipient's x-only pubkey, hex.
        #[arg(long)]
        to: String,
        #[arg(long)]
        message: String,
        #[command(flatten)]
        relay: RelayOpts,
    },
    /// Read private messages addressed to a pseudonym.
    Inbox {
        #[arg(long, requires = "context")]
        seed: PathBuf,
        #[arg(long)]
        context: Option<String>,
        #[command(flatten)]
        relay: RelayOpts,
    },
    /// Check a posting against the escrow it claims to be backed by.
    Verify {
        #[arg(long)]
        job_addr: String,
        #[arg(long)]
        escrow: PathBuf,
        #[command(flatten)]
        relay: RelayOpts,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum ResolveTo {
    Maker,
    Buyer,
}

#[derive(Subcommand)]
enum EscrowCmd {
    /// Write an escrow definition. The address commits to every term here.
    New {
        #[arg(long)]
        out: PathBuf,
        /// Buyer x-only pubkey, hex. Defaults to the wallet's own key.
        #[arg(long)]
        buyer: Option<String>,
        /// The buyer's reputation pseudonym — the identity their chain entries
        /// belong to. Kept separate from the payment key so trading does not
        /// collapse per-context pseudonyms into one linkable identity.
        #[arg(long, requires = "buyer_context")]
        buyer_seed: Option<PathBuf>,
        #[arg(long)]
        buyer_context: Option<String>,
        /// Optional arbiter. Without one the escrow runs in pure-timeout mode
        /// and has no dispute path at all.
        #[arg(long)]
        arbiter: Option<String>,
        #[arg(long)]
        reward: u64,
        #[arg(long)]
        bond: u64,
        /// Absolute DAA score after which refund and slash become available.
        #[arg(long)]
        deadline: u64,
        /// DAA scores the maker must wait after shipping before auto-releasing.
        #[arg(long, default_value_t = 1000)]
        auto_release: u64,
        /// blake3 of the design file, hex.
        #[arg(long)]
        file_hash: String,
        /// Wallet whose key is the default buyer.
        #[arg(long)]
        wallet: Option<PathBuf>,
    },
    /// Print the escrow address and terms.
    Show {
        #[arg(long)]
        escrow: PathBuf,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    /// Fund the escrow (buyer).
    Open {
        #[arg(long)]
        escrow: PathBuf,
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        rpc: Option<String>,
        #[arg(long)]
        submit: bool,
    },
    /// Claim the job, posting the bond (maker).
    Claim {
        #[arg(long)]
        escrow: PathBuf,
        #[arg(long)]
        wallet: PathBuf,
        /// Maker payment key to record. Defaults to the wallet's own key.
        #[arg(long)]
        maker: Option<String>,
        /// The maker's reputation pseudonym. The covenant requires a signature
        /// from it, so a maker cannot bind someone else's identity — nor omit
        /// one and thereby dodge any future default.
        #[arg(long, requires = "rep_context")]
        rep_seed: PathBuf,
        #[arg(long)]
        rep_context: Option<String>,
        #[arg(long)]
        rpc: Option<String>,
        #[arg(long)]
        submit: bool,
    },
    /// Attest a tracking hash (maker).
    Ship {
        #[arg(long)]
        escrow: PathBuf,
        #[arg(long)]
        wallet: PathBuf,
        /// Hash of the carrier tracking number, hex.
        #[arg(long)]
        tracking: String,
        #[arg(long)]
        rpc: Option<String>,
        #[arg(long)]
        submit: bool,
    },
    /// Build the attestation this escrow's settlement owes a party.
    ///
    /// Every field is dictated by the escrow, so both sides derive the same
    /// body; the holder signs it as owner and the counterparty countersigns.
    Attest {
        #[arg(long)]
        escrow: PathBuf,
        /// The party's reputation pseudonym — the identity the escrow bound,
        /// not the key that paid.
        #[arg(long, requires = "context")]
        seed: PathBuf,
        #[arg(long)]
        context: Option<String>,
        /// That party's chain, to position the entry.
        #[arg(long)]
        chain: Option<PathBuf>,
        #[arg(long)]
        ts: Option<u64>,
    },
    /// Release reward + bond to the maker (buyer).
    Settle {
        #[arg(long)]
        escrow: PathBuf,
        #[arg(long)]
        wallet: PathBuf,
        /// Co-signed attestation file to commit. Repeat for the mirror.
        #[arg(long = "att", required = true)]
        atts: Vec<PathBuf>,
        #[arg(long)]
        rpc: Option<String>,
        #[arg(long)]
        submit: bool,
    },
    /// Take reward + bond after a maker fails to ship (buyer).
    ///
    /// Derives the maker's default attestation automatically — it needs no
    /// signature from them, which is the whole point.
    Slash {
        #[arg(long)]
        escrow: PathBuf,
        #[arg(long)]
        wallet: PathBuf,
        /// Where to write the default attestation the slash produces.
        #[arg(long)]
        default_out: PathBuf,
        /// The maker's chain, if known, to position the entry.
        #[arg(long)]
        maker_chain: Option<PathBuf>,
        #[arg(long)]
        rpc: Option<String>,
        #[arg(long)]
        submit: bool,
    },
    /// Contest a delivery (buyer, arbitrated escrows only).
    Dispute {
        #[arg(long)]
        escrow: PathBuf,
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        rpc: Option<String>,
        #[arg(long)]
        submit: bool,
    },
    /// Resolve a dispute (arbiter plus the beneficiary).
    Resolve {
        #[arg(long)]
        escrow: PathBuf,
        /// The beneficiary's wallet — the maker's or the buyer's.
        #[arg(long)]
        wallet: PathBuf,
        /// The arbiter's key file. Resolution needs both signatures.
        #[arg(long)]
        arbiter_key: PathBuf,
        /// Who the dispute is resolved in favour of.
        #[arg(long, value_enum)]
        to: ResolveTo,
        #[arg(long = "id", required = true)]
        ids: Vec<String>,
        #[arg(long)]
        rpc: Option<String>,
        #[arg(long)]
        submit: bool,
    },
    /// Reclaim an unclaimed job after the deadline (buyer).
    Refund {
        #[arg(long)]
        escrow: PathBuf,
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        rpc: Option<String>,
        #[arg(long)]
        submit: bool,
    },
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn load_seed(path: &PathBuf) -> Result<[u8; 32]> {
    let s = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let b = hex::decode(s.trim()).context("seed file must be 64 hex chars")?;
    b.try_into().map_err(|_| anyhow!("seed must be 32 bytes"))
}

fn load_keypair(seed: &PathBuf, context: &str) -> Result<Keypair> {
    Ok(derive_context_keypair(&load_seed(seed)?, context))
}

fn load_wallet(path: &PathBuf) -> Result<Keypair> {
    let bytes = load_seed(path).with_context(|| format!("reading wallet key {}", path.display()))?;
    Keypair::from_seckey_slice(&Secp256k1::new(), &bytes).context("invalid wallet secret key")
}

fn parse_outpoint(s: &str) -> Result<Outpoint> {
    let (txid_hex, idx) = s.split_once(':').ok_or_else(|| anyhow!("anchor must be txid:index"))?;
    let txid: [u8; 32] = hex::decode(txid_hex)
        .context("bad txid hex")?
        .try_into()
        .map_err(|_| anyhow!("txid must be 32 bytes"))?;
    Ok(Outpoint { txid, index: idx.parse().context("bad output index")? })
}

fn parse_id(s: &str) -> Result<[u8; 32]> {
    hex::decode(s.trim())
        .with_context(|| format!("bad attestation id hex: {s}"))?
        .try_into()
        .map_err(|_| anyhow!("attestation id must be 32 bytes"))
}

fn load_chain(path: &PathBuf) -> Result<Chain> {
    let s = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(serde_json::from_str(&s)?)
}

/// Slurp stdin. Callers deserialize with a concrete type, so no `serde` trait
/// bound (and no extra dependency) is needed here.
fn stdin_str() -> Result<String> {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s)?;
    Ok(s)
}

/// A tokio runtime plus a connected client. The runtime must outlive every
/// blocking call made through the verifier, so callers keep this alive.
struct RpcSession {
    rt: tokio::runtime::Runtime,
    client: Arc<dyn RpcApi>,
    url: String,
}

fn open_rpc(url: &str) -> Result<RpcSession> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .context("starting tokio runtime")?;
    let client = rt.block_on(rpc::connect(url))?;
    Ok(RpcSession { rt, client, url: url.to_string() })
}

/// How a chain was checked — recorded in machine-readable output so an
/// unanchored score can never be mistaken for a verified one.
enum AnchorStatus {
    Verified(String),
    UnverifiedOffline,
}

impl AnchorStatus {
    fn label(&self) -> &'static str {
        match self {
            AnchorStatus::Verified(_) => "verified",
            AnchorStatus::UnverifiedOffline => "UNVERIFIED_OFFLINE",
        }
    }
}

const OFFLINE_WARNING: &str = "\
!! ------------------------------------------------------------------ !!
!!  OFFLINE MODE — ANCHORING WAS NOT CHECKED                          !!
!!  Structure and signatures only. Nothing here proves any trade was  !!
!!  settled on-chain, and unanchored attestations are worthless by    !!
!!  definition: forging them costs a keypair, not a fee. Do NOT use   !!
!!  this result to decide whether to trade with someone.              !!
!! ------------------------------------------------------------------ !!";

/// Structure + signatures, and — unless explicitly offline — anchoring.
fn verify_chain(chain: &Chain, opts: &RpcOpts) -> Result<AnchorStatus> {
    if opts.offline {
        if opts.rpc.is_some() {
            bail!("--offline and --rpc are mutually exclusive: pick verified or unverified");
        }
        eprintln!("{OFFLINE_WARNING}");
        chain.verify()?;
        return Ok(AnchorStatus::UnverifiedOffline);
    }

    let url = rpc::endpoint(&opts.rpc).ok_or_else(|| {
        anyhow!(
            "no kaspad endpoint. Pass --rpc grpc://host:16110 (or set {}). \
             To check structure and signatures without any anchoring proof, \
             pass --offline — but understand that such a result means nothing.",
            rpc::RPC_ENV
        )
    })?;

    let scan_from = opts
        .scan_from
        .as_deref()
        .map(|h| RpcHash::from_str(h).map_err(|e| anyhow!("bad --scan-from hash: {e}")))
        .transpose()?;
    let cfg = ScanConfig {
        scan_from,
        max_batches: opts.max_batches,
        min_confirmations: opts.min_confirmations,
        max_spend_scan_blocks: opts.max_spend_scan_blocks,
    };

    let session = open_rpc(&url)?;
    let verifier = KaspadAnchorVerifier::new(session.client.clone(), session.rt.handle().clone(), cfg);
    // One scan for the whole chain rather than one per attestation.
    verifier.prefetch(chain.attestations.iter().map(|a| &a.body.anchor))?;
    chain.verify_anchored(&verifier)?;
    Ok(AnchorStatus::Verified(session.url.clone()))
}

/// Build the mirror of a countersigned attestation: same settlement, same
/// anchor, roles swapped, owned by the counterparty.
///
/// `outcome` is deliberately NOT copied blindly. An outcome is recorded
/// *against the owner of the chain it sits in*, so flipping the owner changes
/// what the field asserts:
///
/// - `Success` mirrors to `Success` — both sides performed, both earn credit.
/// - `DisputedResolved` mirrors verbatim — the dispute was a joint fact.
/// - `Default` has no honest mirror. It means "the owner defaulted"; writing it
///   into the counterparty's chain would accuse the wronged party, and writing
///   `Success` instead would silently assert something this settlement never
///   established. It is also unobtainable in practice: the mirror must be
///   countersigned by the defaulter, who will not sign. Defaults belong on the
///   covenant's unilateral path (spec 1.5), not here.
fn mirror_body(att: &Attestation, prev: Option<[u8; 32]>, index: u64) -> Result<AttestationBody> {
    let outcome = match att.body.outcome {
        Outcome::Success => Outcome::Success,
        Outcome::DisputedResolved => Outcome::DisputedResolved,
        Outcome::Default => bail!(
            "refusing to mirror a Default attestation: an outcome is recorded against the chain \
             owner, so there is no honest role-flipped form of \"the owner defaulted\". The \
             counterparty's side of a default must come from the escrow covenant's unilateral \
             path, which is the counter-signer of record on slashes."
        ),
    };
    Ok(AttestationBody {
        v: att.body.v,
        anchor: att.body.anchor,
        role: match att.body.role {
            Role::Provider => Role::Client,
            Role::Client => Role::Provider,
        },
        owner: att.body.counterparty,
        counterparty: att.body.owner,
        outcome,
        amount_bucket: att.body.amount_bucket,
        prev,
        index,
        ts: att.body.ts,
    })
}

fn parse_xonly(s: &str) -> Result<secp256k1::XOnlyPublicKey> {
    let b = hex::decode(s.trim()).context("bad pubkey hex")?;
    Ok(secp256k1::XOnlyPublicKey::from_slice(&b)?)
}

/// Submit a built escrow transition, or explain what was not sent.
fn finish(
    session: &RpcSession,
    file: &mut escrow::EscrowFile,
    path: &std::path::Path,
    tx: kaspa_consensus_core::tx::Transaction,
    live: escrow::Live,
    submit: bool,
    what: &str,
) -> Result<()> {
    eprintln!("{what}: {} sompi -> {}", live.value, live.outpoint);
    if !submit {
        eprintln!(
            "NOT submitted. Re-run with --submit to broadcast. The escrow state file is left \\
             untouched, so nothing is recorded until the chain has it."
        );
        println!("{}", tx.id());
        return Ok(());
    }
    let txid = session.rt.block_on(anchor::submit_rpc_tx(&session.client, (&tx).into()))?;
    file.live = Some(live);
    escrow::save(path, file)?;
    eprintln!("SUBMITTED — escrow state written to {}", path.display());
    println!("{txid}");
    Ok(())
}

fn escrow_session(rpc: &Option<String>) -> Result<RpcSession> {
    let url = rpc::endpoint(rpc).ok_or_else(|| {
        anyhow!("no kaspad endpoint. Pass --rpc grpc://host:16110 or set {}", rpc::RPC_ENV)
    })?;
    open_rpc(&url)
}

fn board_rt() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .context("starting tokio runtime")
}

fn report(what: &str, id: &str, results: Vec<(String, String)>) {
    eprintln!("{what} {id}");
    for (relay, verdict) in &results {
        eprintln!("  {relay}: {verdict}");
    }
    if results.iter().all(|(_, v)| v != "accepted") {
        eprintln!("WARNING: no relay accepted it — nobody can see this yet");
    }
    println!("{id}");
}

fn run_job(cmd: JobCmd) -> Result<()> {
    let rt = board_rt()?;
    match cmd {
        JobCmd::Post {
            escrow: path,
            seed,
            context,
            job_id,
            process,
            material,
            tolerance,
            qty,
            region,
            file_ptr,
            rep_head,
            relay,
        } => {
            let urls = board::relays(&relay.relays)?;
            let ctx = context.ok_or_else(|| anyhow!("--context is required"))?;
            let key = load_keypair(&seed, &ctx)?;
            let f = escrow::load(&path)?;
            let posting = board::posting_from_escrow(
                &f.terms, process, material, tolerance, qty, region, file_ptr, rep_head,
            );
            let (addr, results) = rt.block_on(board::post(&urls, &key, &job_id, &posting, now()))?;
            eprintln!("job address {addr}");
            report("posted", &addr, results);
        }
        JobCmd::List { process, region, relay } => {
            let urls = board::relays(&relay.relays)?;
            let jobs = rt.block_on(board::list(&urls, process.as_deref(), region.as_deref()))?;
            eprintln!("{} job(s)", jobs.len());
            for (id, p, e) in jobs {
                println!(
                    "{}\n  {} {} x{} to {} | reward {} bond {} | deadline {} | escrow {}",
                    krep_board::job::job_address(&e.author()?, &id),
                    p.process,
                    p.material,
                    p.qty,
                    p.ship_region,
                    p.reward,
                    p.maker_bond,
                    p.deadline,
                    &p.escrow_template[..16]
                );
            }
        }
        JobCmd::Claim { job_addr, seed, context, chain, payment, bond_txid, note, relay } => {
            let urls = board::relays(&relay.relays)?;
            let ctx = context.ok_or_else(|| anyhow!("--context is required"))?;
            let key = load_keypair(&seed, &ctx)?;
            let rep_head = match &chain {
                Some(c) if c.exists() => load_chain(c)?.head().map(hex::encode).unwrap_or_default(),
                _ => String::new(),
            };
            let c = krep_board::job::Claim {
                v: 1,
                rep_head,
                rep_pubkey: hex::encode(key.x_only_public_key().0.serialize()),
                payment_pubkey: payment,
                bond_txid,
                note,
            };
            let (id, results) = rt.block_on(board::claim(&urls, &key, &job_addr, &c, now()))?;
            report("claimed", &id, results);
        }
        JobCmd::Claims { job_addr, relay } => {
            let urls = board::relays(&relay.relays)?;
            let claims = rt.block_on(board::claims_for(&urls, &job_addr))?;
            eprintln!("{} claim(s) on {job_addr}", claims.len());
            for (c, e) in claims {
                println!(
                    "{}\n  rep {} head {} | pay {} | bond tx {}{}",
                    e.id,
                    &c.rep_pubkey[..16.min(c.rep_pubkey.len())],
                    if c.rep_head.is_empty() { "(none)" } else { &c.rep_head[..16.min(c.rep_head.len())] },
                    &c.payment_pubkey[..16.min(c.payment_pubkey.len())],
                    &c.bond_txid[..16.min(c.bond_txid.len())],
                    c.note.map(|n| format!(" | {n}")).unwrap_or_default()
                );
            }
        }
        JobCmd::Accept { job_addr, seed, context, claim_id, escrow: path, network, relay } => {
            let urls = board::relays(&relay.relays)?;
            let ctx = context.ok_or_else(|| anyhow!("--context is required"))?;
            let key = load_keypair(&seed, &ctx)?;
            let f = escrow::load(&path)?;
            let live = f.live.as_ref().ok_or_else(|| {
                anyhow!("that escrow is not open yet — fund it before accepting, or the winner has nothing to claim")
            })?;
            let net = NetworkType::from_str(&network).map_err(|e| anyhow!("bad --network: {e}"))?;
            let a = krep_board::job::Acceptance {
                v: 1,
                claim_id,
                escrow_address: krep_escrow::script::escrow_address(&f.terms, net.into())
                    .map_err(|e| anyhow!("{e}"))?
                    .to_string(),
                escrow_outpoint: live.outpoint.clone(),
            };
            let (id, results) = rt.block_on(board::accept(&urls, &key, &job_addr, &a, now()))?;
            report("accepted", &id, results);
        }
        JobCmd::Dm { seed, context, to, message, relay } => {
            let urls = board::relays(&relay.relays)?;
            let ctx = context.ok_or_else(|| anyhow!("--context is required"))?;
            let key = load_keypair(&seed, &ctx)?;
            let to = parse_xonly(&to)?;
            let (id, results) = rt.block_on(board::dm_send(&urls, &key, &to, &message, now()))?;
            eprintln!("sent privately to {}", hex::encode(to.serialize()));
            report("gift wrap", &id, results);
        }
        JobCmd::Inbox { seed, context, relay } => {
            let urls = board::relays(&relay.relays)?;
            let ctx = context.ok_or_else(|| anyhow!("--context is required"))?;
            let key = load_keypair(&seed, &ctx)?;
            let msgs = rt.block_on(board::dm_inbox(&urls, &key))?;
            eprintln!("{} message(s)", msgs.len());
            for (r, wrapped_at) in msgs {
                println!("from {} (wrap seen at {wrapped_at})\n  {}", &r.pubkey[..16], r.content);
            }
        }
        JobCmd::Awarded { job_addr, relay } => {
            let urls = board::relays(&relay.relays)?;
            match rt.block_on(board::acceptance_for(&urls, &job_addr))? {
                None => eprintln!("no acceptance yet for {job_addr}"),
                Some((a, e)) => {
                    eprintln!("awarded by the buyer at {}", e.created_at);
                    eprintln!("  winning claim {}", a.claim_id);
                    eprintln!("  escrow        {}", a.escrow_address);
                    eprintln!("  outpoint      {}", a.escrow_outpoint);
                    eprintln!(
                        "Check that escrow against the posting before bonding anything:\n                           krep job verify --job-addr {job_addr} --escrow <file>"
                    );
                    println!("{}", a.claim_id);
                }
            }
        }
        JobCmd::Verify { job_addr, escrow: path, relay } => {
            let urls = board::relays(&relay.relays)?;
            let f = escrow::load(&path)?;
            let jobs = rt.block_on(board::list(&urls, None, None))?;
            let found = jobs
                .into_iter()
                .find(|(id, _, e)| {
                    e.author().map(|a| krep_board::job::job_address(&a, id) == job_addr).unwrap_or(false)
                })
                .ok_or_else(|| anyhow!("no posting found at {job_addr}"))?;
            board::matches_escrow(&found.1, &f.terms)?;
            eprintln!("posting matches the escrow it names: reward, bond, deadline and file hash all agree");
            println!("{job_addr}");
        }
    }
    Ok(())
}

fn run_escrow(cmd: EscrowCmd) -> Result<()> {
    match cmd {
        EscrowCmd::New {
            out,
            buyer,
            buyer_seed,
            buyer_context,
            arbiter,
            reward,
            bond,
            deadline,
            auto_release,
            file_hash,
            wallet,
        } => {
            let buyer = match (&buyer, &wallet) {
                (Some(b), _) => parse_xonly(b)?,
                (None, Some(w)) => load_wallet(w)?.x_only_public_key().0,
                (None, None) => bail!("pass --buyer <pubkey> or --wallet <file>"),
            };
            let buyer_rep = match (&buyer_seed, &buyer_context) {
                (Some(s), Some(c)) => load_keypair(s, c)?.x_only_public_key().0,
                _ => bail!(
                    "pass --buyer-seed and --buyer-context: the buyer's reputation pseudonym is \
                     deliberately not the same key that pays"
                ),
            };
            let terms = krep_escrow::Terms {
                buyer,
                buyer_rep,
                arbiter: arbiter.as_deref().map(parse_xonly).transpose()?,
                reward,
                maker_bond: bond,
                deadline,
                auto_release_delay: auto_release,
                file_hash: parse_id(&file_hash)?,
            };
            if out.exists() {
                bail!("{} already exists", out.display());
            }
            escrow::save(&out, &escrow::EscrowFile { terms, live: None })?;
            eprintln!("escrow definition written to {}", out.display());
        }
        EscrowCmd::Show { escrow: path, network } => {
            let f = escrow::load(&path)?;
            let net = NetworkType::from_str(&network).map_err(|e| anyhow!("bad --network: {e}"))?;
            println!("{}", escrow::describe(&f.terms, net.into())?);
            match &f.live {
                Some(l) => println!("phase    {} at {} ({} sompi)", l.phase, l.outpoint, l.value),
                None => println!("phase    not yet opened"),
            }
        }
        EscrowCmd::Open { escrow: path, wallet, rpc, submit } => {
            let mut f = escrow::load(&path)?;
            if f.live.is_some() {
                bail!("this escrow is already open");
            }
            let key = load_wallet(&wallet)?;
            let s = escrow_session(&rpc)?;
            let (tx, live) = s.rt.block_on(escrow::open(&s.client, &key, &f.terms))?;
            finish(&s, &mut f, &path, tx, live, submit, "OPEN")?;
        }
        EscrowCmd::Claim { escrow: path, wallet, maker, rep_seed, rep_context, rpc, submit } => {
            let mut f = escrow::load(&path)?;
            let live = f.live.as_ref().ok_or_else(|| anyhow!("escrow is not open yet"))?;
            let key = load_wallet(&wallet)?;
            let maker = match &maker {
                Some(m) => parse_xonly(m)?,
                None => key.x_only_public_key().0,
            };
            let ctx = rep_context.ok_or_else(|| anyhow!("--rep-context is required"))?;
            let rep = load_keypair(&rep_seed, &ctx)?;
            let s = escrow_session(&rpc)?;
            let (tx, next) = s.rt.block_on(escrow::claim(&s.client, &key, &f.terms, live, maker, &rep))?;
            finish(&s, &mut f, &path, tx, next, submit, "CLAIM")?;
        }
        EscrowCmd::Ship { escrow: path, wallet, tracking, rpc, submit } => {
            let mut f = escrow::load(&path)?;
            let live = f.live.as_ref().ok_or_else(|| anyhow!("escrow is not open yet"))?;
            let key = load_wallet(&wallet)?;
            let s = escrow_session(&rpc)?;
            let (tx, next) =
                s.rt.block_on(escrow::ship(&s.client, &key, &f.terms, live, parse_id(&tracking)?))?;
            finish(&s, &mut f, &path, tx, next, submit, "SHIP")?;
        }
        EscrowCmd::Attest { escrow: path, seed, context, chain, ts } => {
            let f = escrow::load(&path)?;
            let live = f.live.as_ref().ok_or_else(|| anyhow!("escrow is not open yet"))?;
            let ctx = context.ok_or_else(|| anyhow!("--context is required"))?;
            let key = load_keypair(&seed, &ctx)?;
            let me = key.x_only_public_key().0;
            let p = escrow::parties(&f.terms, live)?;
            // Which side of the trade this pseudonym is on decides the role,
            // and the escrow decides everything else.
            let (counterparty, role) = if me == p.maker_rep {
                (p.buyer_rep, Role::Provider)
            } else if me == p.buyer_rep {
                (p.maker_rep, Role::Client)
            } else {
                bail!(
                    "that pseudonym is not bound to this escrow — the covenant names {} (maker) \
                     and {} (buyer)",
                    hex::encode(p.maker_rep.serialize()),
                    hex::encode(p.buyer_rep.serialize())
                );
            };
            let (prev, index) = match &chain {
                Some(c) if c.exists() => {
                    let ch = load_chain(c)?;
                    if ch.owner != me {
                        bail!("--chain belongs to a different pseudonym");
                    }
                    (ch.head(), ch.attestations.len() as u64)
                }
                _ => (None, 0),
            };
            let body = escrow::settlement_body(
                &f.terms,
                live,
                me,
                counterparty,
                role,
                Outcome::Success,
                prev,
                index,
                ts.unwrap_or_else(now),
            )?;
            println!("{}", serde_json::to_string_pretty(&create_partial(&key, body)?)?);
        }
        EscrowCmd::Settle { escrow: path, wallet, atts, rpc, submit } => {
            let mut f = escrow::load(&path)?;
            let live = f.live.as_ref().ok_or_else(|| anyhow!("escrow is not open yet"))?;
            let key = load_wallet(&wallet)?;
            let mut ids: Vec<[u8; 32]> = Vec::new();
            for a in &atts {
                let att: Attestation = serde_json::from_str(
                    &fs::read_to_string(a).with_context(|| format!("reading {}", a.display()))?,
                )?;
                att.verify().map_err(|e| anyhow!("{}: {e}", a.display()))?;
                if att.body.anchor != parse_outpoint(&live.outpoint)? {
                    bail!("{} is anchored to a different outpoint than this settlement spends", a.display());
                }
                ids.push(att.id());
            }
            // The payout goes to the payment key; the attestations above belong
            // to the pseudonyms. Two different jobs, two different identities.
            let maker = escrow::parties(&f.terms, live)?.maker;
            let s = escrow_session(&rpc)?;
            let (tx, next) = s.rt.block_on(escrow::payout(
                &s.client,
                &key,
                &f.terms,
                live,
                krep_escrow::script::Branch::Settle,
                maker,
                &ids,
                0,
                vec![key],
            ))?;
            finish(&s, &mut f, &path, tx, next, submit, "SETTLE")?;
        }
        EscrowCmd::Slash { escrow: path, wallet, default_out, maker_chain, rpc, submit } => {
            let mut f = escrow::load(&path)?;
            let live = f.live.as_ref().ok_or_else(|| anyhow!("escrow is not open yet"))?;
            let key = load_wallet(&wallet)?;
            let (prev, index) = match &maker_chain {
                Some(c) if c.exists() => {
                    let ch = load_chain(c)?;
                    (ch.head(), ch.attestations.len() as u64)
                }
                _ => (None, 0),
            };
            let default_att = escrow::default_attestation(&f.terms, live, prev, index, now())?;
            let ids = vec![default_att.id()];
            fs::write(&default_out, serde_json::to_string_pretty(&default_att)?)?;
            eprintln!(
                "default attestation written to {} — the maker never signed it and cannot\n\
                 repudiate it; anyone with a node can check it once this slash confirms",
                default_out.display()
            );
            let deadline = f.terms.deadline;
            let buyer = f.terms.buyer;
            let s = escrow_session(&rpc)?;
            let (tx, next) = s.rt.block_on(escrow::payout(
                &s.client,
                &key,
                &f.terms,
                live,
                krep_escrow::script::Branch::Slash,
                buyer,
                &ids,
                deadline,
                vec![key],
            ))?;
            finish(&s, &mut f, &path, tx, next, submit, "SLASH")?;
        }
        EscrowCmd::Dispute { escrow: path, wallet, rpc, submit } => {
            let mut f = escrow::load(&path)?;
            let live = f.live.as_ref().ok_or_else(|| anyhow!("escrow is not open yet"))?;
            let key = load_wallet(&wallet)?;
            let s = escrow_session(&rpc)?;
            let (tx, next) = s.rt.block_on(escrow::dispute(&s.client, &key, &f.terms, live))?;
            finish(&s, &mut f, &path, tx, next, submit, "DISPUTE")?;
        }
        EscrowCmd::Resolve { escrow: path, wallet, arbiter_key, to, ids, rpc, submit } => {
            let mut f = escrow::load(&path)?;
            let live = f.live.as_ref().ok_or_else(|| anyhow!("escrow is not open yet"))?;
            let key = load_wallet(&wallet)?;
            let arbiter = load_wallet(&arbiter_key)?;
            let ids: Vec<[u8; 32]> = ids.iter().map(|s| parse_id(s)).collect::<Result<_>>()?;
            let p = escrow::parties(&f.terms, live)?;
            let (branch, beneficiary) = match to {
                ResolveTo::Maker => (krep_escrow::script::Branch::ResolveToMaker, p.maker),
                ResolveTo::Buyer => (krep_escrow::script::Branch::ResolveToBuyer, p.buyer),
            };
            let s = escrow_session(&rpc)?;
            // Beneficiary first, arbiter above it — the order the branch reads.
            let (tx, next) = s.rt.block_on(escrow::payout(
                &s.client,
                &key,
                &f.terms,
                live,
                branch,
                beneficiary,
                &ids,
                0,
                vec![key, arbiter],
            ))?;
            finish(&s, &mut f, &path, tx, next, submit, "RESOLVE")?;
        }
        EscrowCmd::Refund { escrow: path, wallet, rpc, submit } => {
            let mut f = escrow::load(&path)?;
            let live = f.live.as_ref().ok_or_else(|| anyhow!("escrow is not open yet"))?;
            let key = load_wallet(&wallet)?;
            let s = escrow_session(&rpc)?;
            let (tx, next) = s.rt.block_on(escrow::refund(&s.client, &key, &f.terms, live))?;
            finish(&s, &mut f, &path, tx, next, submit, "REFUND")?;
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Keygen { out } => {
            let mut seed = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut seed);
            if out.exists() {
                bail!("{} already exists — refusing to overwrite a seed", out.display());
            }
            fs::write(&out, hex::encode(seed))?;
            eprintln!("seed written to {} — back it up, it IS your reputation", out.display());
        }
        Cmd::Pubkey { seed, context } => {
            let kp = load_keypair(&seed, &context)?;
            println!("{}", hex::encode(kp.x_only_public_key().0.serialize()));
        }
        Cmd::Create { seed, context, chain, anchor, role, counterparty, outcome, bucket, ts } => {
            let kp = load_keypair(&seed, &context)?;
            let owner = kp.x_only_public_key().0;
            let (prev, index) = match &chain {
                Some(p) if p.exists() => {
                    let c = load_chain(p)?;
                    if c.owner != owner {
                        bail!("chain owner does not match this seed+context pseudonym");
                    }
                    (c.head(), c.attestations.len() as u64)
                }
                _ => (None, 0),
            };
            let cp_bytes = hex::decode(&counterparty).context("bad counterparty hex")?;
            let body = AttestationBody {
                v: 1,
                anchor: parse_outpoint(&anchor)?,
                role: match role {
                    RoleArg::Provider => Role::Provider,
                    RoleArg::Client => Role::Client,
                },
                owner,
                counterparty: secp256k1::XOnlyPublicKey::from_slice(&cp_bytes)?,
                outcome: match outcome {
                    OutcomeArg::Success => Outcome::Success,
                    OutcomeArg::Default => Outcome::Default,
                    OutcomeArg::DisputedResolved => Outcome::DisputedResolved,
                },
                amount_bucket: bucket,
                prev,
                index,
                ts: ts.unwrap_or_else(now),
            };
            let partial = create_partial(&kp, body)?;
            println!("{}", serde_json::to_string_pretty(&partial)?);
        }
        Cmd::Countersign { seed, context, wallet, mirror_out, mirror_chain } => {
            let kp = match (&seed, &context, &wallet) {
                (Some(s), Some(c), None) => load_keypair(s, c)?,
                (None, _, Some(w)) => load_wallet(w)?,
                _ => bail!("pass either --seed with --context, or --wallet"),
            };
            let partial: PartialAttestation = serde_json::from_str(&stdin_str()?)?;
            let att = countersign(&kp, partial)?;
            println!("{}", serde_json::to_string_pretty(&att)?);

            if let Some(path) = mirror_out {
                let me = kp.x_only_public_key().0;
                // Position the mirror in the countersigner's own chain.
                let (prev, index) = match &mirror_chain {
                    Some(p) if p.exists() => {
                        let c = load_chain(p)?;
                        if c.owner != me {
                            bail!("--mirror-chain owner does not match this seed+context pseudonym");
                        }
                        (c.head(), c.attestations.len() as u64)
                    }
                    _ => (None, 0),
                };
                let body = mirror_body(&att, prev, index)?;
                // The mirror's owner is us, so we sign it first and the original
                // owner countersigns — the same two-party handshake, mirrored.
                let partial = create_partial(&kp, body)?;
                fs::write(&path, serde_json::to_string_pretty(&partial)?)?;
                eprintln!(
                    "mirror partial written to {} — send it to {} to countersign, \
                     then anchor both ids in one tx:\n  krep anchor --id <their id> --id <your id>",
                    path.display(),
                    hex::encode(att.body.owner.serialize())
                );
            }
        }
        Cmd::Append { chain } => {
            let att: Attestation = serde_json::from_str(&stdin_str()?)?;
            let mut c = if chain.exists() {
                load_chain(&chain)?
            } else {
                Chain::new(att.body.owner)
            };
            c.append(att)?;
            fs::write(&chain, serde_json::to_string_pretty(&c)?)?;
            eprintln!(
                "appended; chain length {} head {}",
                c.attestations.len(),
                c.head().map(hex::encode).unwrap_or_default()
            );
        }
        Cmd::Verify { chain, rpc: opts } => {
            let c = load_chain(&chain)?;
            let status = verify_chain(&c, &opts)?;
            match &status {
                AnchorStatus::Verified(url) => eprintln!(
                    "OK: {} attestations, head {} — all anchors confirmed on-chain via {url}",
                    c.attestations.len(),
                    c.head().map(hex::encode).unwrap_or_default()
                ),
                AnchorStatus::UnverifiedOffline => eprintln!(
                    "structure+signatures OK: {} attestations, head {} — ANCHORING UNVERIFIED",
                    c.attestations.len(),
                    c.head().map(hex::encode).unwrap_or_default()
                ),
            }
        }
        Cmd::Score { chain, rpc: opts } => {
            let c = load_chain(&chain)?;
            // Never score a chain whose anchors have not been checked without
            // saying so in the output itself.
            let status = verify_chain(&c, &opts)?;
            let out = serde_json::json!({
                "anchor_status": status.label(),
                "rpc": match &status {
                    AnchorStatus::Verified(url) => Some(url.clone()),
                    AnchorStatus::UnverifiedOffline => None,
                },
                "score": c.score(),
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Cmd::Id => {
            let att: Attestation = serde_json::from_str(&stdin_str()?)?;
            println!("{}", hex::encode(att.id()));
        }
        Cmd::WalletNew { out } => {
            if out.exists() {
                bail!("{} already exists — refusing to overwrite a key", out.display());
            }
            let secp = Secp256k1::new();
            let (sk, _) = secp.generate_keypair(&mut rand::thread_rng());
            fs::write(&out, hex::encode(sk.secret_bytes()))?;
            eprintln!("wallet key written to {} — this pays anchor fees, not your rep", out.display());
        }
        Cmd::WalletAddress { wallet, network } => {
            let kp = load_wallet(&wallet)?;
            let net = NetworkType::from_str(&network)
                .map_err(|e| anyhow!("bad --network {network:?}: {e}"))?;
            println!("{}", anchor::address_for(net.into(), &kp));
        }
        Cmd::Send { wallet, to, amount, rpc: rpc_url, submit } => {
            let key = load_wallet(&wallet)?;
            let url = rpc::endpoint(&rpc_url).ok_or_else(|| {
                anyhow!("no kaspad endpoint. Pass --rpc grpc://host:16110 or set {}", rpc::RPC_ENV)
            })?;
            let session = open_rpc(&url)?;
            let dest = kaspa_addresses::Address::try_from(to.as_str()).map_err(|e| anyhow!("bad address: {e}"))?;
            let tx = session.rt.block_on(escrow::send(&session.client, &key, &dest, amount))?;
            if submit {
                let txid = session.rt.block_on(anchor::submit_rpc_tx(&session.client, (&tx).into()))?;
                eprintln!("SUBMITTED");
                println!("{txid}");
            } else {
                eprintln!("NOT submitted. Re-run with --submit to broadcast.");
                println!("{}", tx.id());
            }
        }
        Cmd::WalletPubkey { wallet } => {
            println!("{}", hex::encode(load_wallet(&wallet)?.x_only_public_key().0.serialize()));
        }
        Cmd::WalletUtxos { wallet, rpc: rpc_url } => {
            let kp = load_wallet(&wallet)?;
            let url = rpc::endpoint(&rpc_url).ok_or_else(|| {
                anyhow!("no kaspad endpoint. Pass --rpc grpc://host:16110 or set {}", rpc::RPC_ENV)
            })?;
            let session = open_rpc(&url)?;
            let (address, utxos) = session.rt.block_on(anchor::spendable(&session.client, &kp))?;
            eprintln!("{} spendable outpoint(s) for {address}", utxos.len());
            for (outpoint, entry) in &utxos {
                println!("{}:{}\t{} sompi", outpoint.transaction_id, outpoint.index, entry.amount);
            }
        }
        Cmd::Job { cmd } => run_job(cmd)?,
        Cmd::Escrow { cmd } => run_escrow(cmd)?,
        Cmd::Submit { tx, rpc: rpc_url } => {
            let raw = fs::read_to_string(&tx).with_context(|| format!("reading {}", tx.display()))?;
            let signed = anchor::from_json(&raw)?;
            let url = rpc::endpoint(&rpc_url).ok_or_else(|| {
                anyhow!("no kaspad endpoint. Pass --rpc grpc://host:16110 or set {}", rpc::RPC_ENV)
            })?;
            eprintln!(
                "submitting {} — payload {} bytes: {}",
                tx.display(),
                signed.payload.len(),
                hex::encode(&signed.payload)
            );
            let session = open_rpc(&url)?;
            let txid = session.rt.block_on(anchor::submit_rpc_tx(&session.client, signed))?;
            eprintln!("SUBMITTED — this spent real funds and cannot be undone");
            println!("{txid}");
        }
        Cmd::Anchor { wallet, ids, spend, rpc: rpc_url, submit, out, fee_rate } => {
            let kp = load_wallet(&wallet)?;
            let ids: Vec<[u8; 32]> = ids.iter().map(|s| parse_id(s)).collect::<Result<_>>()?;
            let to_spend = parse_outpoint(&spend)?;
            let url = rpc::endpoint(&rpc_url).ok_or_else(|| {
                anyhow!("no kaspad endpoint. Pass --rpc grpc://host:16110 or set {}", rpc::RPC_ENV)
            })?;
            let session = open_rpc(&url)?;
            let plan = session.rt.block_on(anchor::build(
                &session.client,
                &kp,
                &ids,
                fee_rate,
                kaspa_consensus_core::tx::TransactionOutpoint::new(
                    RpcHash::from_bytes(to_spend.txid),
                    to_spend.index,
                ),
            ))?;
            plan.self_check()?;

            eprintln!("anchor tx built from {} (signatures self-verified)", plan.address);
            eprintln!("  spends anchor outpoint {}:{}", hex::encode(to_spend.txid), to_spend.index);
            eprintln!(
                "  inputs {} totalling {} sompi -> 1 output of {} sompi",
                plan.input_count, plan.total_in, plan.out_value
            );
            eprintln!("  fee {} sompi at feerate {} (mass {})", plan.fee, plan.feerate, plan.mass);
            eprintln!("  payload {} bytes committing {} attestation id(s)", plan.payload.len(), ids.len());
            eprintln!("  payload hex {}", hex::encode(&plan.payload));

            if let Some(path) = &out {
                fs::write(path, anchor::to_json(&plan)?)?;
                eprintln!("signed transaction written to {}", path.display());
            }

            if submit {
                let txid = session.rt.block_on(anchor::submit(&session.client, &plan))?;
                eprintln!("SUBMITTED — this spent real funds and cannot be undone");
                println!("{txid}");
            } else {
                eprintln!("NOT submitted.");
                match &out {
                    Some(path) => eprintln!(
                        "Send exactly this transaction with:\n                           krep submit --tx {} --rpc <url>",
                        path.display()
                    ),
                    None => eprintln!(
                        "NOTE: re-running with --submit rebuilds the transaction against the \
                         node's live fee estimate, which drifts — so the fee, the change amount \
                         and the txid below can all differ from what is finally sent. To review \
                         and then send the very same bytes, use --out <file> and `krep submit`; \
                         to make the build reproducible, pin --fee-rate."
                    ),
                }
                println!("{}", plan.txid());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use krep_core::{Attestation, derive_context_keypair};

    fn kp(tag: &str) -> Keypair {
        let mut seed = [0u8; 32];
        seed[..tag.len()].copy_from_slice(tag.as_bytes());
        derive_context_keypair(&seed, "test")
    }

    fn settlement(owner: &Keypair, cp: &Keypair, outcome: Outcome) -> Attestation {
        let body = AttestationBody {
            v: 1,
            anchor: Outpoint { txid: [9u8; 32], index: 1 },
            role: Role::Provider,
            owner: owner.x_only_public_key().0,
            counterparty: cp.x_only_public_key().0,
            outcome,
            amount_bucket: 3,
            prev: None,
            index: 0,
            ts: 1_700_000_000,
        };
        countersign(cp, create_partial(owner, body).unwrap()).unwrap()
    }

    #[test]
    fn mirror_flips_roles_and_keeps_the_settlement() {
        let a = kp("provider");
        let b = kp("client");
        let att = settlement(&a, &b, Outcome::Success);
        let m = mirror_body(&att, None, 0).unwrap();

        // Same settlement: same anchor, same size, same moment.
        assert_eq!(m.anchor, att.body.anchor, "both sides must point at one settlement");
        assert_eq!(m.amount_bucket, att.body.amount_bucket);
        assert_eq!(m.ts, att.body.ts);
        assert_eq!(m.v, att.body.v);

        // Flipped: the counterparty now owns it, in the opposite role.
        assert_eq!(m.owner, att.body.counterparty);
        assert_eq!(m.counterparty, att.body.owner);
        assert_eq!(att.body.role, Role::Provider);
        assert_eq!(m.role, Role::Client);
        assert!(m.validate_fields().is_ok());
    }

    #[test]
    fn mirror_is_co_signable_and_lands_in_the_other_chain() {
        let a = kp("provider");
        let b = kp("client");
        let att = settlement(&a, &b, Outcome::Success);

        // B owns the mirror, so B signs first and A countersigns.
        let m = mirror_body(&att, None, 0).unwrap();
        let mirrored = countersign(&a, create_partial(&b, m).unwrap()).unwrap();
        mirrored.verify().expect("mirror must be a valid co-signed attestation");

        // Each attestation belongs to its own owner's chain, and the two are
        // distinct objects with distinct ids sharing one anchor.
        let mut chain_a = Chain::new(a.x_only_public_key().0);
        let mut chain_b = Chain::new(b.x_only_public_key().0);
        chain_a.append(att.clone()).expect("original belongs to A");
        chain_b.append(mirrored.clone()).expect("mirror belongs to B");

        assert_ne!(att.id(), mirrored.id(), "distinct attestations must have distinct ids");
        assert_eq!(att.body.anchor, mirrored.body.anchor, "one settlement, one anchor tx");

        // And the shared 64-byte payload commits both.
        let payload = anchor::build_payload(&[att.id(), mirrored.id()]).unwrap();
        assert_eq!(payload.len(), 64);
        assert!(krep_core::kaspad::payload_commits(&payload, &att.id()));
        assert!(krep_core::kaspad::payload_commits(&payload, &mirrored.id()));

        // Both sides now score from the one settlement.
        assert_eq!(chain_a.score().trades, 1);
        assert_eq!(chain_b.score().trades, 1);
    }

    #[test]
    fn mirror_appends_to_a_non_empty_chain() {
        let a = kp("provider");
        let b = kp("client");
        let att = settlement(&a, &b, Outcome::Success);

        // B already has history; the mirror must slot in at the right position.
        let earlier = settlement(&b, &kp("someone-else"), Outcome::Success);
        let mut chain_b = Chain::new(b.x_only_public_key().0);
        chain_b.append(earlier).unwrap();

        let m = mirror_body(&att, chain_b.head(), chain_b.attestations.len() as u64).unwrap();
        let mirrored = countersign(&a, create_partial(&b, m).unwrap()).unwrap();
        chain_b.append(mirrored).expect("mirror must link onto B's existing chain");

        assert_eq!(chain_b.attestations.len(), 2);
        chain_b.verify().expect("B's chain stays valid with the mirror appended");
    }

    #[test]
    fn disputed_mirrors_verbatim_but_default_is_refused() {
        let a = kp("provider");
        let b = kp("client");

        let disputed = settlement(&a, &b, Outcome::DisputedResolved);
        let m = mirror_body(&disputed, None, 0).unwrap();
        assert_eq!(m.outcome, Outcome::DisputedResolved, "a dispute is a joint fact");

        // "The owner defaulted" has no honest role-flipped form.
        let defaulted = settlement(&a, &b, Outcome::Default);
        let err = mirror_body(&defaulted, None, 0).unwrap_err();
        assert!(err.to_string().contains("refusing to mirror a Default"), "got {err}");
    }
}
