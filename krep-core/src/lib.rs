//! kRep core — pseudonymous reputation from anchored trade attestations.
//!
//! Design (spec v0.1):
//! - A pseudonym is a secp256k1 x-only (schnorr) keypair, same curve as Kaspa.
//! - An attestation is co-signed by both trade parties and belongs to exactly
//!   one owner's append-only hash-linked chain (`prev` + `index`).
//! - An attestation is only *valid reputation* if its id is anchored in the
//!   payload of a confirmed Kaspa settlement transaction (see [`AnchorVerifier`]).
//!   Anchoring is generic: any settlement tx (FabMesh escrow, kUSD liquidation,
//!   GPU rental payout) can anchor an attestation.

pub mod chain;

use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, Message, Secp256k1, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Domain tag for signing digests. Bump the version on any layout change.
pub const SIGN_DOMAIN: &str = "krep/attest/v1/sign";
/// Domain tag for attestation ids (the value committed on-chain).
pub const ID_DOMAIN: &str = "krep/attest/v1/id";
/// Domain tag for context key derivation.
pub const CTX_DOMAIN: &str = "krep/ctx/v1";

#[derive(Debug, Error)]
pub enum KrepError {
    #[error("invalid signature: {0}")]
    BadSignature(String),
    #[error("invalid field: {0}")]
    BadField(String),
    #[error("chain error at index {index}: {reason}")]
    Chain { index: u64, reason: String },
    #[error("hex/parse error: {0}")]
    Parse(String),
}

pub type Result<T> = std::result::Result<T, KrepError>;

/// Role of the attestation *owner* in the settled trade.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Provided the good/service (maker, seller, GPU host, arbiter…).
    Provider,
    /// Paid for it.
    Client,
}

impl Role {
    fn byte(self) -> u8 {
        match self {
            Role::Provider => 0,
            Role::Client => 1,
        }
    }
}

/// Outcome recorded against the *owner* of the chain this attestation sits in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    /// Owner defaulted. Normally emitted unilaterally by the escrow covenant's
    /// slash path (the covenant is the counter-signer of record) since a
    /// defaulter won't co-sign their own default.
    Default,
    DisputedResolved,
}

impl Outcome {
    fn byte(self) -> u8 {
        match self {
            Outcome::Success => 0,
            Outcome::Default => 1,
            Outcome::DisputedResolved => 2,
        }
    }
}

/// Reference to the settlement transaction output that anchors this attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outpoint {
    pub txid: [u8; 32],
    pub index: u32,
}

impl Serialize for Outpoint {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{}:{}", hex::encode(self.txid), self.index))
    }
}

impl<'de> Deserialize<'de> for Outpoint {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let (txid_hex, idx) = s
            .split_once(':')
            .ok_or_else(|| serde::de::Error::custom("expected txid:index"))?;
        let bytes = hex::decode(txid_hex).map_err(serde::de::Error::custom)?;
        let txid: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("txid must be 32 bytes"))?;
        let index: u32 = idx.parse().map_err(serde::de::Error::custom)?;
        Ok(Outpoint { txid, index })
    }
}

/// Kept as the non-optional counterpart to [`hex32_opt`] for future fields
/// (no current body field is a bare 32-byte hash).
#[allow(dead_code)]
mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let b = hex::decode(&s).map_err(serde::de::Error::custom)?;
        b.try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

mod hex32_opt {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_some(&hex::encode(b)),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        let s: Option<String> = Option::deserialize(d)?;
        match s {
            None => Ok(None),
            Some(s) => {
                let b = hex::decode(&s).map_err(serde::de::Error::custom)?;
                Ok(Some(b.try_into().map_err(|_| {
                    serde::de::Error::custom("expected 32 bytes")
                })?))
            }
        }
    }
}

pub(crate) mod xonly {
    use secp256k1::XOnlyPublicKey;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &XOnlyPublicKey, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v.serialize()))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<XOnlyPublicKey, D::Error> {
        let s = String::deserialize(d)?;
        let b = hex::decode(&s).map_err(serde::de::Error::custom)?;
        XOnlyPublicKey::from_slice(&b).map_err(serde::de::Error::custom)
    }
}

mod schnorr_sig {
    use secp256k1::schnorr::Signature;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &Signature, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v.as_ref()))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Signature, D::Error> {
        let s = String::deserialize(d)?;
        let b = hex::decode(&s).map_err(serde::de::Error::custom)?;
        Signature::from_slice(&b).map_err(serde::de::Error::custom)
    }
}

/// The signed content of an attestation (everything except the signatures).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationBody {
    pub v: u8,
    /// Settlement tx output whose payload commits this attestation's id.
    pub anchor: Outpoint,
    pub role: Role,
    /// Chain owner — the pseudonym accruing this reputation entry.
    #[serde(with = "xonly")]
    pub owner: XOnlyPublicKey,
    #[serde(with = "xonly")]
    pub counterparty: XOnlyPublicKey,
    pub outcome: Outcome,
    /// Coarse volume tier, 1..=4. Never the raw amount.
    pub amount_bucket: u8,
    /// blake3 id of the owner's previous attestation; None only at index 0.
    #[serde(with = "hex32_opt", default)]
    pub prev: Option<[u8; 32]>,
    /// Position in the owner's chain, starting at 0, strictly sequential.
    pub index: u64,
    /// Unix seconds.
    pub ts: u64,
}

impl AttestationBody {
    /// Canonical byte layout. Fixed field order, fixed widths, LE integers.
    /// This — not JSON — is what gets signed and hashed.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 36 + 1 + 32 + 32 + 1 + 1 + 32 + 8 + 8);
        out.push(self.v);
        out.extend_from_slice(&self.anchor.txid);
        out.extend_from_slice(&self.anchor.index.to_le_bytes());
        out.push(self.role.byte());
        out.extend_from_slice(&self.owner.serialize());
        out.extend_from_slice(&self.counterparty.serialize());
        out.push(self.outcome.byte());
        out.push(self.amount_bucket);
        out.extend_from_slice(&self.prev.unwrap_or([0u8; 32]));
        out.extend_from_slice(&self.index.to_le_bytes());
        out.extend_from_slice(&self.ts.to_le_bytes());
        out
    }

    /// Digest both parties sign.
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key(SIGN_DOMAIN);
        h.update(&self.canonical_bytes());
        *h.finalize().as_bytes()
    }

    pub fn validate_fields(&self) -> Result<()> {
        if self.v != 1 {
            return Err(KrepError::BadField(format!("unsupported version {}", self.v)));
        }
        if !(1..=4).contains(&self.amount_bucket) {
            return Err(KrepError::BadField("amount_bucket must be 1..=4".into()));
        }
        if self.owner == self.counterparty {
            return Err(KrepError::BadField("owner == counterparty".into()));
        }
        match (self.index, &self.prev) {
            (0, Some(_)) => Err(KrepError::BadField("index 0 must have prev = null".into())),
            (i, None) if i > 0 => Err(KrepError::BadField("index > 0 requires prev".into())),
            _ => Ok(()),
        }
    }
}

/// A fully co-signed attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    #[serde(flatten)]
    pub body: AttestationBody,
    #[serde(with = "schnorr_sig")]
    pub sig_owner: Signature,
    #[serde(with = "schnorr_sig")]
    pub sig_counterparty: Signature,
}

impl Attestation {
    /// The 32-byte value committed in the settlement tx payload.
    /// Includes both signatures, so anchoring proves the co-signed object existed.
    pub fn id(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key(ID_DOMAIN);
        h.update(&self.body.canonical_bytes());
        h.update(self.sig_owner.as_ref());
        h.update(self.sig_counterparty.as_ref());
        *h.finalize().as_bytes()
    }

    /// Field sanity + both schnorr signatures.
    pub fn verify(&self) -> Result<()> {
        self.body.validate_fields()?;
        let secp = Secp256k1::verification_only();
        let msg = Message::from_digest(self.body.signing_digest());
        secp.verify_schnorr(&self.sig_owner, &msg, &self.body.owner)
            .map_err(|e| KrepError::BadSignature(format!("owner: {e}")))?;
        secp.verify_schnorr(&self.sig_counterparty, &msg, &self.body.counterparty)
            .map_err(|e| KrepError::BadSignature(format!("counterparty: {e}")))?;
        Ok(())
    }
}

/// A body signed by one side, awaiting the counter-signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialAttestation {
    #[serde(flatten)]
    pub body: AttestationBody,
    #[serde(with = "schnorr_sig")]
    pub sig_owner: Signature,
}

/// Deterministic schnorr signature over the body digest.
pub fn sign_body(keypair: &Keypair, body: &AttestationBody) -> Signature {
    let secp = Secp256k1::new();
    let msg = Message::from_digest(body.signing_digest());
    secp.sign_schnorr_no_aux_rand(&msg, keypair)
}

/// Owner signs first.
pub fn create_partial(owner: &Keypair, body: AttestationBody) -> Result<PartialAttestation> {
    body.validate_fields()?;
    let (xonly, _) = owner.x_only_public_key();
    if xonly != body.owner {
        return Err(KrepError::BadField("signing key is not body.owner".into()));
    }
    let sig_owner = sign_body(owner, &body);
    Ok(PartialAttestation { body, sig_owner })
}

/// Counterparty completes it.
pub fn countersign(counterparty: &Keypair, partial: PartialAttestation) -> Result<Attestation> {
    let (xonly, _) = counterparty.x_only_public_key();
    if xonly != partial.body.counterparty {
        return Err(KrepError::BadField("signing key is not body.counterparty".into()));
    }
    let sig_counterparty = sign_body(counterparty, &partial.body);
    let att = Attestation {
        body: partial.body,
        sig_owner: partial.sig_owner,
        sig_counterparty,
    };
    att.verify()?;
    Ok(att)
}

/// Derive an unlinkable per-context keypair from a 32-byte master seed.
///
/// `context` is a free-form label ("fabmesh", "gpu-rental", "arbiter"…).
/// Different contexts yield computationally unlinkable pseudonyms; the same
/// seed+context always yields the same key. (Deliberately simpler than BIP32 —
/// hardened-equivalent, no public derivation, which is what pseudonyms want.)
pub fn derive_context_keypair(seed: &[u8; 32], context: &str) -> Keypair {
    let secp = Secp256k1::new();
    let mut counter: u32 = 0;
    loop {
        let mut h = blake3::Hasher::new_derive_key(CTX_DOMAIN);
        h.update(seed);
        h.update(context.as_bytes());
        h.update(&counter.to_le_bytes());
        let candidate = h.finalize();
        if let Ok(kp) = Keypair::from_seckey_slice(&secp, candidate.as_bytes()) {
            return kp; // probability of a retry is ~2^-128; the loop is belt-and-braces
        }
        counter += 1;
    }
}

/// Verifies that an attestation id is committed on-chain.
///
/// M1 ships the trait + a stub; the real implementation queries a kaspad
/// (wRPC) for `anchor.txid`, confirms acceptance, and checks that the tx
/// payload contains the 32-byte id (testnet-10 first, then mainnet via
/// rustynode). Every scoring path must treat unanchored attestations as
/// nonexistent — anchoring IS the Sybil cost.
pub trait AnchorVerifier {
    fn is_anchored(&self, id: &[u8; 32], anchor: &Outpoint) -> std::io::Result<bool>;
}

/// Accepts everything. For tests and offline chain-structure checks ONLY.
pub struct TrustEverythingAnchor;

impl AnchorVerifier for TrustEverythingAnchor {
    fn is_anchored(&self, _id: &[u8; 32], _anchor: &Outpoint) -> std::io::Result<bool> {
        Ok(true)
    }
}
