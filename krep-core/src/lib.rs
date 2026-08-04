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
pub mod field;
#[cfg(feature = "kaspad")]
pub mod kaspad;

use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, Message, Secp256k1, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Domain tag for signing digests. Bump the version on any layout change.
pub const SIGN_DOMAIN: &str = "krep/attest/v1/sign";
/// Domain tag for v1 attestation ids (blake3). Kept so chains anchored before
/// the change keep verifying — the payloads that committed them are immutable.
pub const ID_DOMAIN: &str = "krep/attest/v1/id";
/// Domain separator for v2 ids, absorbed into the Poseidon2 sponge.
///
/// v2 exists so a circuit can recompute an id from its body. The accumulator
/// can only hold ids, so proving anything about an attestation's *contents*
/// means rehashing the body in-circuit — and blake3 is neither in Noir's
/// stdlib nor cheap there. Poseidon2 costs a handful of permutations.
pub const ID_DOMAIN_V2: u128 = 0x6b7265702f61762f32; // "krep/av/2"
/// Domain tag for ids of covenant-witnessed attestations. Deliberately distinct
/// from [`ID_DOMAIN`] so a co-signed attestation and a covenant-witnessed one
/// can never collide, and so existing v1 chains keep verifying unchanged.
pub const COVENANT_ID_DOMAIN: &str = "krep/attest/v2/covenant-id";
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

mod hex_vec {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
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
        if !(1..=2).contains(&self.v) {
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

/// Proof that a covenant authorized an attestation nobody signed.
///
/// A defaulter will not co-sign their own default — and will not sign it as
/// *owner* either, so a covenant-witnessed attestation carries no signatures at
/// all. Its authority is the on-chain fact that a specific branch of a specific
/// covenant executed. This is SPEC 1.5's "the covenant is the second signer of
/// record", made checkable.
///
/// Deliberately protocol-agnostic: kRep does not know what a FabMesh escrow is.
/// It checks only that the anchored outpoint was locked by `redeem_script`, that
/// spending it took branch `branch`, and that the escrow state named this
/// attestation's owner. Deciding whether `redeem_script` is a covenant worth
/// trusting is the relying party's job — that is what SPEC 2.1's
/// `escrow_template` hash is for.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CovenantWitness {
    /// The redeem script the anchor outpoint was locked by (P2SH preimage).
    #[serde(with = "hex_vec")]
    pub redeem_script: Vec<u8>,
    /// Branch selector the spending transaction chose.
    pub branch: u8,
    /// Byte offset, within the *anchored* transaction's payload, at which the
    /// covenant records the pubkey this attestation is about. Without this an
    /// attacker who controls any slash could mint defaults against strangers.
    pub owner_offset: u16,
}

impl CovenantWitness {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.redeem_script.len() + 11);
        out.extend_from_slice(&(self.redeem_script.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.redeem_script);
        out.push(self.branch);
        out.extend_from_slice(&self.owner_offset.to_le_bytes());
        out
    }
}

/// What authorizes an attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Authorization {
    /// Both parties signed. The ordinary case.
    CoSigned {
        #[serde(with = "schnorr_sig")]
        sig_owner: Signature,
        #[serde(with = "schnorr_sig")]
        sig_counterparty: Signature,
    },
    /// Nobody signed; a covenant executed. Only ever legitimate for outcomes
    /// the subject would refuse to sign.
    Covenant { covenant_witness: CovenantWitness },
}

/// A fully authorized attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    #[serde(flatten)]
    pub body: AttestationBody,
    #[serde(flatten)]
    pub auth: Authorization,
}

impl Attestation {
    /// Convenience constructor for the ordinary co-signed case.
    pub fn co_signed(body: AttestationBody, sig_owner: Signature, sig_counterparty: Signature) -> Self {
        Attestation { body, auth: Authorization::CoSigned { sig_owner, sig_counterparty } }
    }

    pub fn sig_owner(&self) -> Option<&Signature> {
        match &self.auth {
            Authorization::CoSigned { sig_owner, .. } => Some(sig_owner),
            _ => None,
        }
    }

    pub fn sig_counterparty(&self) -> Option<&Signature> {
        match &self.auth {
            Authorization::CoSigned { sig_counterparty, .. } => Some(sig_counterparty),
            _ => None,
        }
    }

    pub fn covenant_witness(&self) -> Option<&CovenantWitness> {
        match &self.auth {
            Authorization::Covenant { covenant_witness } => Some(covenant_witness),
            _ => None,
        }
    }

    /// The 32-byte value committed in the settlement tx payload.
    ///
    /// Which hash is used is decided by the body's own version field, so a
    /// chain anchored under v1 keeps verifying against payloads that can never
    /// be rewritten, while v2 attestations get an id a circuit can recompute.
    pub fn id(&self) -> [u8; 32] {
        match &self.auth {
            Authorization::CoSigned { sig_owner, sig_counterparty } if self.body.v >= 2 => {
                // Signatures are absorbed as opaque bytes. The circuit never
                // verifies them — it only needs the id to bind to them, so that
                // recomputing the id from a body proves that body is the one
                // the settlement anchored.
                let mut bytes = self.body.canonical_bytes();
                bytes.extend_from_slice(sig_owner.as_ref());
                bytes.extend_from_slice(sig_counterparty.as_ref());
                field::hash_tagged_bytes(ID_DOMAIN_V2, &bytes)
            }
            Authorization::CoSigned { sig_owner, sig_counterparty } => {
                let mut h = blake3::Hasher::new_derive_key(ID_DOMAIN);
                h.update(&self.body.canonical_bytes());
                h.update(sig_owner.as_ref());
                h.update(sig_counterparty.as_ref());
                *h.finalize().as_bytes()
            }
            Authorization::Covenant { covenant_witness } => {
                let mut h = blake3::Hasher::new_derive_key(COVENANT_ID_DOMAIN);
                h.update(&self.body.canonical_bytes());
                h.update(&covenant_witness.canonical_bytes());
                *h.finalize().as_bytes()
            }
        }
    }

    /// Field sanity, plus whatever can be checked without a node.
    ///
    /// For a covenant-witnessed attestation that is *only* field sanity: its
    /// authority lives on-chain, so it is meaningless until
    /// [`chain::Chain::verify_anchored`] has checked it against a node. Offline
    /// verification deliberately does not pretend otherwise.
    pub fn verify(&self) -> Result<()> {
        self.body.validate_fields()?;
        match &self.auth {
            Authorization::CoSigned { sig_owner, sig_counterparty } => {
                let secp = Secp256k1::verification_only();
                let msg = Message::from_digest(self.body.signing_digest());
                secp.verify_schnorr(sig_owner, &msg, &self.body.owner)
                    .map_err(|e| KrepError::BadSignature(format!("owner: {e}")))?;
                secp.verify_schnorr(sig_counterparty, &msg, &self.body.counterparty)
                    .map_err(|e| KrepError::BadSignature(format!("counterparty: {e}")))?;
                Ok(())
            }
            Authorization::Covenant { covenant_witness } => {
                if covenant_witness.redeem_script.is_empty() {
                    return Err(KrepError::BadField("covenant witness has no redeem script".into()));
                }
                // A covenant witness is only ever an answer to "the subject
                // would not sign this". Allowing it for a Success would let
                // anyone who can drive a covenant mint praise for themselves.
                if self.body.outcome == Outcome::Success {
                    return Err(KrepError::BadField(
                        "a Success attestation must be co-signed, not covenant-witnessed".into(),
                    ));
                }
                Ok(())
            }
        }
    }

    /// Does this attestation need a node before it means anything?
    pub fn needs_chain_proof(&self) -> bool {
        matches!(self.auth, Authorization::Covenant { .. })
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
    let att = Attestation::co_signed(partial.body, partial.sig_owner, sig_counterparty);
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
/// The real implementation is [`kaspad::KaspadAnchorVerifier`] (feature
/// `kaspad`): it queries a node for `anchor.txid`, requires the transaction to
/// have been accepted by the virtual chain, and checks that its payload
/// contains the 32-byte id. Every scoring path must treat unanchored
/// attestations as nonexistent — anchoring IS the Sybil cost.
///
/// Implementations must distinguish "provably not anchored" (`Ok(false)`) from
/// "could not determine" (`Err`). Reporting the second as the first would let a
/// node outage read as a fraudulent chain.
pub trait AnchorVerifier {
    fn is_anchored(&self, id: &[u8; 32], anchor: &Outpoint) -> std::io::Result<bool>;

    /// Check the three things a covenant witness claims, none of which can be
    /// checked offline:
    ///
    /// 1. the anchor outpoint really was locked by `witness.redeem_script`,
    /// 2. the transaction that spent it really took branch `witness.branch`,
    /// 3. the escrow state really named `owner` at `witness.owner_offset`.
    ///
    /// (3) is what stops an attacker who can drive *any* covenant from minting
    /// defaults against strangers: the pubkey being defamed has to be the one
    /// the covenant itself recorded.
    fn covenant_witnessed(
        &self,
        anchor: &Outpoint,
        witness: &CovenantWitness,
        owner: &XOnlyPublicKey,
    ) -> std::io::Result<bool>;
}

/// Accepts everything. For tests and offline chain-structure checks ONLY.
pub struct TrustEverythingAnchor;

impl AnchorVerifier for TrustEverythingAnchor {
    fn is_anchored(&self, _id: &[u8; 32], _anchor: &Outpoint) -> std::io::Result<bool> {
        Ok(true)
    }
    fn covenant_witnessed(
        &self,
        _anchor: &Outpoint,
        _witness: &CovenantWitness,
        _owner: &XOnlyPublicKey,
    ) -> std::io::Result<bool> {
        Ok(true)
    }
}
