//! Append-only per-pseudonym attestation chains: verification and scoring.

use crate::{AnchorVerifier, Attestation, KrepError, Outcome, Result};
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chain {
    #[serde(with = "crate::xonly")]
    pub owner: XOnlyPublicKey,
    pub attestations: Vec<Attestation>,
}

impl Chain {
    pub fn new(owner: XOnlyPublicKey) -> Self {
        Chain { owner, attestations: Vec::new() }
    }

    /// Head id (what a pseudonym publishes as its reputation pointer).
    pub fn head(&self) -> Option<[u8; 32]> {
        self.attestations.last().map(|a| a.id())
    }

    /// Append with full link validation.
    pub fn append(&mut self, att: Attestation) -> Result<()> {
        let expected_index = self.attestations.len() as u64;
        let expected_prev = self.head();
        if att.body.owner != self.owner {
            return Err(KrepError::Chain {
                index: expected_index,
                reason: "attestation owner != chain owner".into(),
            });
        }
        if att.body.index != expected_index {
            return Err(KrepError::Chain {
                index: expected_index,
                reason: format!("expected index {expected_index}, got {}", att.body.index),
            });
        }
        if att.body.prev != expected_prev {
            return Err(KrepError::Chain {
                index: expected_index,
                reason: "prev does not match current head".into(),
            });
        }
        att.verify()?;
        self.attestations.push(att);
        Ok(())
    }

    /// Full structural + cryptographic verification of the chain.
    /// Does NOT check anchoring — pass an [`AnchorVerifier`] to [`Chain::verify_anchored`].
    pub fn verify(&self) -> Result<()> {
        let mut prev_id: Option<[u8; 32]> = None;
        let mut prev_ts: u64 = 0;
        for (i, att) in self.attestations.iter().enumerate() {
            let i64 = i as u64;
            if att.body.owner != self.owner {
                return Err(KrepError::Chain { index: i64, reason: "owner mismatch".into() });
            }
            if att.body.index != i64 {
                return Err(KrepError::Chain { index: i64, reason: "index mismatch".into() });
            }
            if att.body.prev != prev_id {
                return Err(KrepError::Chain { index: i64, reason: "broken prev link".into() });
            }
            if att.body.ts < prev_ts {
                return Err(KrepError::Chain { index: i64, reason: "timestamp regression".into() });
            }
            att.verify()?;
            prev_id = Some(att.id());
            prev_ts = att.body.ts;
        }
        Ok(())
    }

    /// [`Chain::verify`] plus on-chain anchoring of every attestation.
    /// This is the verification real counterparties must run.
    pub fn verify_anchored<A: AnchorVerifier>(&self, anchor: &A) -> Result<()> {
        self.verify()?;
        for (i, att) in self.attestations.iter().enumerate() {
            let ok = anchor
                .is_anchored(&att.id(), &att.body.anchor)
                .map_err(|e| KrepError::Chain { index: i as u64, reason: format!("anchor query failed: {e}") })?;
            if !ok {
                return Err(KrepError::Chain {
                    index: i as u64,
                    reason: "attestation not anchored on-chain".into(),
                });
            }
        }
        Ok(())
    }

    /// Client-side scoring. Deliberately simple and transparent — verifiers are
    /// free to score however they like; this is a sane default.
    pub fn score(&self) -> Score {
        let n = self.attestations.len() as u64;
        let mut defaults = 0u64;
        let mut disputes = 0u64;
        let mut volume_hist = [0u64; 4];
        let mut counterparties: HashSet<[u8; 32]> = HashSet::new();
        for att in &self.attestations {
            match att.body.outcome {
                Outcome::Default => defaults += 1,
                Outcome::DisputedResolved => disputes += 1,
                Outcome::Success => {}
            }
            let b = att.body.amount_bucket.clamp(1, 4) as usize - 1;
            volume_hist[b] += 1;
            counterparties.insert(att.body.counterparty.serialize());
        }
        let unique = counterparties.len() as u64;
        Score {
            trades: n,
            defaults,
            disputes,
            default_rate: if n > 0 { defaults as f64 / n as f64 } else { 0.0 },
            unique_counterparties: unique,
            // 1.0 = every trade a fresh counterparty; low values flag wash rings.
            counterparty_diversity: if n > 0 { unique as f64 / n as f64 } else { 0.0 },
            first_ts: self.attestations.first().map(|a| a.body.ts),
            last_ts: self.attestations.last().map(|a| a.body.ts),
            volume_hist,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Score {
    pub trades: u64,
    pub defaults: u64,
    pub disputes: u64,
    pub default_rate: f64,
    pub unique_counterparties: u64,
    pub counterparty_diversity: f64,
    pub first_ts: Option<u64>,
    pub last_ts: Option<u64>,
    /// Count of trades per amount bucket 1..=4.
    pub volume_hist: [u64; 4],
}
