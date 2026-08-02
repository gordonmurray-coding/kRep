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
//!   # owner appends:
//!   krep append --chain mychain.json < att.json
//!   krep verify --chain mychain.json
//!   krep score  --chain mychain.json

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use krep_core::chain::Chain;
use krep_core::{
    countersign, create_partial, derive_context_keypair, Attestation, AttestationBody, Outcome,
    Outpoint, PartialAttestation, Role, TrustEverythingAnchor,
};
use rand::RngCore;
use secp256k1::Keypair;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
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
    /// Verify a chain's structure and signatures (anchoring check is stubbed in M1).
    Verify {
        #[arg(long)]
        chain: PathBuf,
    },
    /// Print the default score breakdown for a chain.
    Score {
        #[arg(long)]
        chain: PathBuf,
    },
    /// Print an attestation's id (the value the settlement tx payload must commit).
    Id,
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

fn parse_outpoint(s: &str) -> Result<Outpoint> {
    let (txid_hex, idx) = s.split_once(':').ok_or_else(|| anyhow!("anchor must be txid:index"))?;
    let txid: [u8; 32] = hex::decode(txid_hex)
        .context("bad txid hex")?
        .try_into()
        .map_err(|_| anyhow!("txid must be 32 bytes"))?;
    Ok(Outpoint { txid, index: idx.parse().context("bad output index")? })
}

fn load_chain(path: &PathBuf) -> Result<Chain> {
    let s = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(serde_json::from_str(&s)?)
}

fn stdin_json<T: serde::de::DeserializeOwned>() -> Result<T> {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s)?;
    Ok(serde_json::from_str(&s)?)
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
            let partial: PartialAttestation = stdin_json()?;
            let att = countersign(&kp, partial)?;
            println!("{}", serde_json::to_string_pretty(&att)?);
        }
        Cmd::Append { chain } => {
            let att: Attestation = stdin_json()?;
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
        Cmd::Verify { chain } => {
            let c = load_chain(&chain)?;
            // M1: structure + signatures. Swap TrustEverythingAnchor for the
            // kaspad wRPC verifier once wired to testnet-10.
            c.verify_anchored(&TrustEverythingAnchor)?;
            eprintln!(
                "OK: {} attestations, head {} (anchoring check STUBBED — do not trust for real trades yet)",
                c.attestations.len(),
                c.head().map(hex::encode).unwrap_or_default()
            );
        }
        Cmd::Score { chain } => {
            let c = load_chain(&chain)?;
            c.verify()?;
            println!("{}", serde_json::to_string_pretty(&c.score())?);
        }
        Cmd::Id => {
            let att: Attestation = stdin_json()?;
            println!("{}", hex::encode(att.id()));
        }
    }
    Ok(())
}
