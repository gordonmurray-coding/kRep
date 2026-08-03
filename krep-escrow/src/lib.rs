//! FabMesh escrow covenant — kRep M2.
//!
//! The escrow is a single UTXO whose script public key is `P2SH(covenant)`. The
//! *immutable* terms of the job live inside that script, so the escrow address
//! itself commits to them: change the reward, the bond, a deadline or the
//! arbiter and you get a different address. The *mutable* state — which phase
//! the job is in, who claimed it, what they shipped — lives in the transaction
//! payload and is re-stated on every transition.
//!
//! ```text
//! OPEN ──claim (maker bonds stake)──▶ CLAIMED
//! CLAIMED ──maker attests tracking hash──▶ SHIPPED
//! CLAIMED ──deadline passes, no ship──▶ SLASH
//! SHIPPED ──buyer signs release──▶ SETTLED
//! SHIPPED ──T_auto elapses, no dispute──▶ SETTLED (auto-release)
//! SHIPPED ──buyer disputes──▶ DISPUTED
//! DISPUTED ──2-of-3 with arbiter key──▶ SETTLED or SLASH
//! OPEN ──deadline, no claims──▶ REFUND
//! ```
//!
//! `SETTLED`, `SLASH` and `REFUND` are terminal: they spend the escrow out of
//! the covenant entirely, so no covenant state follows them. The first two are
//! the kRep integration point — the covenant requires their payload to commit
//! the attestation id, which is what makes reputation a settlement side effect
//! rather than a separate, skippable step.
//!
//! # Reading the previous state
//!
//! A script cannot ask "what payload did the transaction I am spending have?".
//! The idiom (borrowed from rusty-kaspa's own covenant example) is to have the
//! spender *supply* the previous transaction's `rest` and `payload` on the
//! stack, then recompute `blake2b_with_key("TransactionID", rest ‖ payload)`
//! and require it to equal the outpoint txid being spent. A forged prior state
//! yields a different txid and the spend fails, so supplied state is as good as
//! authenticated state.

pub mod script;
pub mod state;
pub mod tx;

pub use state::{EscrowState, Phase, StateError, STATE_BYTES};

use kaspa_hashes::Hash;
use secp256k1::XOnlyPublicKey;

/// Domain tag for the escrow terms commitment.
pub const TERMS_DOMAIN: &str = "krep/escrow/v1/terms";

mod xonly_hex {
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
    pub mod opt {
        use secp256k1::XOnlyPublicKey;
        use serde::{Deserialize, Deserializer, Serializer};
        pub fn serialize<S: Serializer>(v: &Option<XOnlyPublicKey>, s: S) -> Result<S::Ok, S::Error> {
            match v {
                Some(k) => s.serialize_some(&hex::encode(k.serialize())),
                None => s.serialize_none(),
            }
        }
        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<XOnlyPublicKey>, D::Error> {
            let s: Option<String> = Option::deserialize(d)?;
            match s {
                None => Ok(None),
                Some(s) => {
                    let b = hex::decode(&s).map_err(serde::de::Error::custom)?;
                    Ok(Some(XOnlyPublicKey::from_slice(&b).map_err(serde::de::Error::custom)?))
                }
            }
        }
    }
}

mod hex32_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s)
            .map_err(serde::de::Error::custom)?
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

/// The immutable half of an escrow: baked into the covenant script, and
/// therefore into the escrow address.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Terms {
    /// Funds the job, signs its transitions, and receives the refund/slash.
    #[serde(with = "xonly_hex")]
    pub buyer: XOnlyPublicKey,
    /// The buyer's reputation pseudonym — the identity their chain entries
    /// belong to. Separate from `buyer` so a participant's payment key and
    /// their reputation are not forced to be the same identity, which would
    /// make per-context pseudonyms pointless the moment they traded.
    #[serde(with = "xonly_hex")]
    pub buyer_rep: XOnlyPublicKey,
    /// Optional per-job arbiter for the 2-of-3 dispute path. `None` runs the
    /// escrow in pure-timeout mode — a lower trust ceiling with zero third
    /// parties, which is a legitimate configuration, not a degraded one.
    #[serde(with = "xonly_hex::opt", default)]
    pub arbiter: Option<XOnlyPublicKey>,
    /// Paid to the maker on settlement, in sompi.
    pub reward: u64,
    /// Maker's stake, added at claim time. Slashed to the buyer on default.
    /// This is the anti-no-show mechanism and what makes fake-trade farming
    /// expensive — see SPEC 1.4.
    pub maker_bond: u64,
    /// DAA score after which an unclaimed job can be refunded, and a claimed
    /// but unshipped job can be slashed.
    pub deadline: u64,
    /// DAA scores to wait after SHIPPED before the maker may auto-release.
    /// Protects the maker from a buyer who simply goes quiet.
    pub auto_release_delay: u64,
    /// blake3 of the design file — the job's identity.
    #[serde(with = "hex32_serde")]
    pub file_hash: [u8; 32],
}

impl Terms {
    /// Canonical bytes. Fixed field order, fixed widths, LE integers — the same
    /// discipline as [`krep_core::AttestationBody::canonical_bytes`], and for
    /// the same reason: this is what gets committed, not any JSON rendering.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 + 32 + 33 + 8 + 8 + 8 + 8 + 32);
        out.push(1u8); // version
        out.extend_from_slice(&self.buyer.serialize());
        out.extend_from_slice(&self.buyer_rep.serialize());
        match &self.arbiter {
            Some(a) => {
                out.push(1);
                out.extend_from_slice(&a.serialize());
            }
            None => {
                out.push(0);
                out.extend_from_slice(&[0u8; 32]);
            }
        }
        out.extend_from_slice(&self.reward.to_le_bytes());
        out.extend_from_slice(&self.maker_bond.to_le_bytes());
        out.extend_from_slice(&self.deadline.to_le_bytes());
        out.extend_from_slice(&self.auto_release_delay.to_le_bytes());
        out.extend_from_slice(&self.file_hash);
        out
    }

    /// The `escrow_template` hash a job posting advertises, and the value a
    /// verifier checks an escrow against.
    pub fn id(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key(TERMS_DOMAIN);
        h.update(&self.canonical_bytes());
        *h.finalize().as_bytes()
    }

    /// Total value the escrow holds once claimed.
    pub fn claimed_value(&self) -> u64 {
        self.reward.saturating_add(self.maker_bond)
    }

    pub fn arbitrated(&self) -> bool {
        self.arbiter.is_some()
    }
}

/// Kaspa's transaction-id hasher key, used to authenticate a supplied previous
/// state against the outpoint being spent.
pub const TX_ID_KEY: &[u8] = b"TransactionID";

/// Recompute a transaction id from the two halves a spender supplies.
pub fn tx_id_from_parts(rest: &[u8], payload: &[u8]) -> Hash {
    use kaspa_hashes::HasherBase;
    let mut h = kaspa_hashes::TransactionID::new();
    h.update(rest).update(payload);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, Secp256k1};

    fn key(b: u8) -> XOnlyPublicKey {
        Keypair::from_seckey_slice(&Secp256k1::new(), &[b; 32]).unwrap().x_only_public_key().0
    }

    fn terms() -> Terms {
        Terms {
            buyer: key(1),
            buyer_rep: key(3),
            arbiter: Some(key(2)),
            reward: 500_000_000,
            maker_bond: 100_000_000,
            deadline: 1_000_000,
            auto_release_delay: 50_000,
            file_hash: [7u8; 32],
        }
    }

    #[test]
    fn terms_id_is_sensitive_to_every_field() {
        let base = terms();
        let id = base.id();

        let mut t = base.clone();
        t.reward += 1;
        assert_ne!(id, t.id(), "reward must bind");

        let mut t = base.clone();
        t.maker_bond += 1;
        assert_ne!(id, t.id(), "bond must bind");

        let mut t = base.clone();
        t.deadline += 1;
        assert_ne!(id, t.id(), "deadline must bind");

        let mut t = base.clone();
        t.auto_release_delay += 1;
        assert_ne!(id, t.id(), "auto-release delay must bind");

        let mut t = base.clone();
        t.file_hash[0] ^= 1;
        assert_ne!(id, t.id(), "file hash must bind");

        let mut t = base.clone();
        t.buyer = key(9);
        assert_ne!(id, t.id(), "buyer must bind");

        let mut t = base.clone();
        t.buyer_rep = key(9);
        assert_ne!(id, t.id(), "buyer pseudonym must bind");

        let mut t = base.clone();
        t.arbiter = Some(key(9));
        assert_ne!(id, t.id(), "arbiter must bind");

        let mut t = base.clone();
        t.arbiter = None;
        assert_ne!(id, t.id(), "dropping the arbiter must change the escrow");
    }

    #[test]
    fn arbiterless_terms_are_not_confusable_with_a_zero_arbiter() {
        // The presence flag must distinguish "no arbiter" from an arbiter whose
        // serialization happens to be zeros, or a job could be silently
        // downgraded to pure-timeout mode.
        let mut a = terms();
        a.arbiter = None;
        assert!(!a.arbitrated());
        assert_eq!(a.canonical_bytes()[65], 0, "absence flag");

        let b = terms();
        assert!(b.arbitrated());
        assert_eq!(b.canonical_bytes()[65], 1, "presence flag");
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn canonical_bytes_are_fixed_width() {
        // 1 version + 32 buyer + 32 buyer_rep + 1 flag + 32 arbiter + 8*4 + 32 file hash
        assert_eq!(terms().canonical_bytes().len(), 162);
        let mut t = terms();
        t.arbiter = None;
        assert_eq!(t.canonical_bytes().len(), 162, "absent arbiter still occupies its slot");
    }

    #[test]
    fn claimed_value_is_reward_plus_bond() {
        let t = terms();
        assert_eq!(t.claimed_value(), 600_000_000);

        // Saturating, so absurd terms cannot wrap the escrow's value to a small
        // number and let a maker claim a large job for nothing.
        let t = Terms { reward: u64::MAX, maker_bond: 10, ..terms() };
        assert_eq!(t.claimed_value(), u64::MAX);
    }
}
