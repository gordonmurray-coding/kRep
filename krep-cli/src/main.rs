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
        /// Settlement outpoint: <txid_hex>:<output_index>
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
        #[arg(long)]
        seed: PathBuf,
        #[arg(long)]
        context: String,
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
    /// Build a payload-carrying transaction committing one or two attestation
    /// ids. Prints the signed transaction; broadcasts only with --submit.
    Anchor {
        /// Wallet key file (64 hex chars) that pays the fee.
        #[arg(long)]
        wallet: PathBuf,
        /// Attestation id to commit, hex. Repeat for a second (mirror) id.
        #[arg(long = "id", required = true)]
        ids: Vec<String>,
        /// kaspad endpoint. Falls back to $KREP_RPC.
        #[arg(long)]
        rpc: Option<String>,
        /// Broadcast the transaction. Without this nothing is sent.
        #[arg(long)]
        submit: bool,
        /// Override feerate in sompi per gram.
        #[arg(long)]
        fee_rate: Option<f64>,
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
    };

    let session = open_rpc(&url)?;
    let verifier = KaspadAnchorVerifier::new(session.client.clone(), session.rt.handle().clone(), cfg);
    // One scan for the whole chain rather than one per attestation.
    verifier.prefetch(chain.attestations.iter().map(|a| &a.body.anchor))?;
    chain.verify_anchored(&verifier)?;
    Ok(AnchorStatus::Verified(session.url.clone()))
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
        Cmd::Countersign { seed, context } => {
            let kp = load_keypair(&seed, &context)?;
            let partial: PartialAttestation = serde_json::from_str(&stdin_str()?)?;
            let att = countersign(&kp, partial)?;
            println!("{}", serde_json::to_string_pretty(&att)?);
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
        Cmd::Anchor { wallet, ids, rpc: rpc_url, submit, fee_rate } => {
            let kp = load_wallet(&wallet)?;
            let ids: Vec<[u8; 32]> = ids.iter().map(|s| parse_id(s)).collect::<Result<_>>()?;
            let url = rpc::endpoint(&rpc_url).ok_or_else(|| {
                anyhow!("no kaspad endpoint. Pass --rpc grpc://host:16110 or set {}", rpc::RPC_ENV)
            })?;
            let session = open_rpc(&url)?;
            let plan = session.rt.block_on(anchor::build(&session.client, &kp, &ids, fee_rate))?;
            plan.self_check()?;

            eprintln!("anchor tx built from {} (signatures self-verified)", plan.address);
            eprintln!(
                "  inputs {} totalling {} sompi -> 1 output of {} sompi",
                plan.input_count, plan.total_in, plan.out_value
            );
            eprintln!("  fee {} sompi at feerate {} (mass {})", plan.fee, plan.feerate, plan.mass);
            eprintln!("  payload {} bytes committing {} attestation id(s)", plan.payload.len(), ids.len());
            eprintln!("  payload hex {}", hex::encode(&plan.payload));

            if submit {
                let txid = session.rt.block_on(anchor::submit(&session.client, &plan))?;
                eprintln!("SUBMITTED — this spent real funds and cannot be undone");
                println!("{txid}");
            } else {
                eprintln!(
                    "NOT submitted. Re-run with --submit to broadcast (this spends real funds). \
                     The txid below is what the transaction WILL have if submitted unchanged."
                );
                println!("{}", plan.txid());
            }
        }
    }
    Ok(())
}
