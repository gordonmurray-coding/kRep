//! `krep job` — the FabMesh job board over Nostr.
//!
//! Relays are untrusted infrastructure. Nothing here believes a relay about
//! anything: every event is signature-checked on arrival, replaceable events
//! are de-duplicated locally rather than trusting the relay to have done it,
//! and the facts that matter — the escrow, the bond, the reputation chain —
//! live on Kaspa where a relay cannot touch them. Publishing reports each
//! relay's verdict separately, because "one relay accepted it" and "the job is
//! visible" are different claims.

use anyhow::{bail, Result};
use krep_board::job::{job_address, Acceptance, Claim, JobPost, KIND_ACCEPT, KIND_CLAIM, KIND_JOB};
use krep_board::relay::{newest_per_address, publish_all, query_all, Filter};
use krep_board::Event;
use krep_escrow::Terms;
use secp256k1::Keypair;
use std::time::Duration;

pub const RELAY_ENV: &str = "KREP_RELAYS";
const TIMEOUT: Duration = Duration::from_secs(10);

pub fn relays(flag: &[String]) -> Result<Vec<String>> {
    if !flag.is_empty() {
        return Ok(flag.to_vec());
    }
    let from_env: Vec<String> = std::env::var(RELAY_ENV)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if from_env.is_empty() {
        bail!("no relays. Pass --relay wss://… (repeatable) or set {RELAY_ENV}");
    }
    Ok(from_env)
}

/// Build the posting from the escrow, so the two cannot disagree.
///
/// Reward, bond, deadline and file hash all come from the terms the escrow
/// address already commits to. A buyer advertising different numbers than the
/// escrow enforces would be the most natural way to mislead a maker, and this
/// removes the opportunity rather than asking anyone to check.
#[allow(clippy::too_many_arguments)]
pub fn posting_from_escrow(
    terms: &Terms,
    process: String,
    material: String,
    tolerance_class: String,
    qty: u32,
    ship_region: String,
    file_ptr: String,
    buyer_rep_hint: Option<String>,
) -> JobPost {
    JobPost {
        v: 1,
        kind: "fab_job".into(),
        file_hash: hex::encode(terms.file_hash),
        file_ptr,
        process,
        material,
        tolerance_class,
        qty,
        reward: terms.reward,
        maker_bond: terms.maker_bond,
        deadline: terms.deadline,
        ship_region,
        escrow_template: hex::encode(terms.id()),
        buyer_rep_hint,
    }
}

pub async fn post(
    urls: &[String],
    key: &Keypair,
    job_id: &str,
    posting: &JobPost,
    created_at: u64,
) -> Result<(String, Vec<(String, String)>)> {
    let event = posting.to_event(key, job_id, created_at);
    let addr = job_address(&key.x_only_public_key().0, job_id);
    Ok((addr, publish_all(urls, &event, TIMEOUT).await))
}

pub async fn list(urls: &[String], process: Option<&str>, region: Option<&str>) -> Result<Vec<(String, JobPost, Event)>> {
    let filter = Filter { kinds: Some(vec![KIND_JOB]), limit: Some(200), ..Default::default() };
    let events = newest_per_address(query_all(urls, &filter, TIMEOUT).await);
    let mut out = Vec::new();
    for e in events {
        let Ok((id, post)) = JobPost::from_event(&e) else { continue };
        if process.is_some_and(|p| post.process != p) {
            continue;
        }
        if region.is_some_and(|r| post.ship_region != r) {
            continue;
        }
        out.push((id, post, e));
    }
    Ok(out)
}

pub async fn claim(
    urls: &[String],
    key: &Keypair,
    job_addr: &str,
    claim: &Claim,
    created_at: u64,
) -> Result<(String, Vec<(String, String)>)> {
    let event = claim.to_event(key, job_addr, created_at);
    Ok((event.id.clone(), publish_all(urls, &event, TIMEOUT).await))
}

pub async fn claims_for(urls: &[String], job_addr: &str) -> Result<Vec<(Claim, Event)>> {
    let filter = Filter {
        kinds: Some(vec![KIND_CLAIM]),
        a_tags: Some(vec![job_addr.to_string()]),
        limit: Some(200),
        ..Default::default()
    };
    let mut out = Vec::new();
    for e in query_all(urls, &filter, TIMEOUT).await {
        if let Ok((addr, c)) = Claim::from_event(&e) {
            // A relay is free to return events we did not ask for.
            if addr == job_addr {
                out.push((c, e));
            }
        }
    }
    Ok(out)
}

pub async fn accept(
    urls: &[String],
    key: &Keypair,
    job_addr: &str,
    accept: &Acceptance,
    created_at: u64,
) -> Result<(String, Vec<(String, String)>)> {
    let event = accept.to_event(key, job_addr, created_at);
    Ok((event.id.clone(), publish_all(urls, &event, TIMEOUT).await))
}

pub async fn acceptance_for(urls: &[String], job_addr: &str) -> Result<Option<(Acceptance, Event)>> {
    let filter = Filter {
        kinds: Some(vec![KIND_ACCEPT]),
        a_tags: Some(vec![job_addr.to_string()]),
        limit: Some(50),
        ..Default::default()
    };
    let mut found: Option<(Acceptance, Event)> = None;
    for e in query_all(urls, &filter, TIMEOUT).await {
        let Ok(a) = Acceptance::from_event(&e) else { continue };
        // The buyer is whoever the job address names; anyone else "accepting"
        // is noise, and honouring it would let a stranger redirect a maker to
        // an escrow they control.
        let buyer = job_addr.split(':').nth(1).unwrap_or_default();
        if e.pubkey != buyer {
            continue;
        }
        if found.as_ref().is_none_or(|(_, prev)| prev.created_at < e.created_at) {
            found = Some((a, e));
        }
    }
    Ok(found)
}

/// Check a posting against the escrow it claims to be backed by.
///
/// This is the check a maker must not skip: the posting is just words on a
/// relay, while the escrow address is what will actually hold and release the
/// money. If the two disagree, the posting is lying.
pub fn matches_escrow(posting: &JobPost, terms: &Terms) -> Result<()> {
    let expected = hex::encode(terms.id());
    if posting.escrow_template != expected {
        bail!("posting names escrow template {} but these terms are {expected}", posting.escrow_template);
    }
    if posting.reward != terms.reward || posting.maker_bond != terms.maker_bond {
        bail!(
            "posting advertises reward {} / bond {}, escrow enforces {} / {}",
            posting.reward,
            posting.maker_bond,
            terms.reward,
            terms.maker_bond
        );
    }
    if posting.deadline != terms.deadline {
        bail!("posting deadline {} differs from the escrow's {}", posting.deadline, terms.deadline);
    }
    if posting.file_hash != hex::encode(terms.file_hash) {
        bail!("posting file hash does not match the escrow's");
    }
    Ok(())
}

