//! NIP-01 events: the only thing a relay understands.
//!
//! An event's id is the SHA-256 of a canonical JSON array, and its signature is
//! a schnorr signature over that id by the author's key — the same curve and
//! the same signing primitive kRep attestations already use, so a pseudonym is
//! directly usable as a Nostr identity without any extra key material.

use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, Message, Secp256k1, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EventError {
    #[error("bad signature: {0}")]
    BadSignature(String),
    #[error("event id does not match its contents")]
    IdMismatch,
    #[error("malformed: {0}")]
    Malformed(String),
}

pub type Result<T> = std::result::Result<T, EventError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

/// The array an event id is computed over. NIP-01 fixes the order and requires
/// compact serialization — no spaces, fields in exactly this sequence.
fn id_preimage(pubkey: &str, created_at: u64, kind: u32, tags: &[Vec<String>], content: &str) -> String {
    serde_json::json!([0, pubkey, created_at, kind, tags, content]).to_string()
}

pub fn event_id(pubkey: &str, created_at: u64, kind: u32, tags: &[Vec<String>], content: &str) -> [u8; 32] {
    use kaspa_hashes::sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(id_preimage(pubkey, created_at, kind, tags, content).as_bytes());
    h.finalize().into()
}

impl Event {
    /// Build and sign. The author is any secp256k1 keypair — in this project,
    /// a kRep pseudonym.
    pub fn sign(key: &Keypair, kind: u32, tags: Vec<Vec<String>>, content: String, created_at: u64) -> Event {
        let pubkey = hex::encode(key.x_only_public_key().0.serialize());
        let id = event_id(&pubkey, created_at, kind, &tags, &content);
        let secp = Secp256k1::new();
        let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(id), key);
        Event {
            id: hex::encode(id),
            pubkey,
            created_at,
            kind,
            tags,
            content,
            sig: hex::encode(sig.as_ref()),
        }
    }

    /// Recompute the id and check the signature.
    ///
    /// Both halves matter: an event whose id is not the hash of its contents is
    /// one whose contents were swapped after signing, and a relay is not
    /// trusted to have checked either.
    pub fn verify(&self) -> Result<()> {
        let expected = event_id(&self.pubkey, self.created_at, self.kind, &self.tags, &self.content);
        let claimed = hex::decode(&self.id).map_err(|e| EventError::Malformed(format!("id: {e}")))?;
        if claimed != expected {
            return Err(EventError::IdMismatch);
        }
        let pk = XOnlyPublicKey::from_slice(
            &hex::decode(&self.pubkey).map_err(|e| EventError::Malformed(format!("pubkey: {e}")))?,
        )
        .map_err(|e| EventError::Malformed(format!("pubkey: {e}")))?;
        let sig = Signature::from_slice(
            &hex::decode(&self.sig).map_err(|e| EventError::Malformed(format!("sig: {e}")))?,
        )
        .map_err(|e| EventError::Malformed(format!("sig: {e}")))?;
        Secp256k1::verification_only()
            .verify_schnorr(&sig, &Message::from_digest(expected), &pk)
            .map_err(|e| EventError::BadSignature(e.to_string()))
    }

    pub fn author(&self) -> Result<XOnlyPublicKey> {
        let b = hex::decode(&self.pubkey).map_err(|e| EventError::Malformed(format!("pubkey: {e}")))?;
        XOnlyPublicKey::from_slice(&b).map_err(|e| EventError::Malformed(format!("pubkey: {e}")))
    }

    /// First value of the first tag with this name.
    pub fn tag(&self, name: &str) -> Option<&str> {
        self.tags.iter().find(|t| t.first().map(String::as_str) == Some(name))?.get(1).map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> Keypair {
        Keypair::from_seckey_slice(&Secp256k1::new(), &[b; 32]).unwrap()
    }

    #[test]
    fn signed_events_verify_and_tampering_does_not() {
        let k = key(1);
        let e = Event::sign(&k, 30402, vec![vec!["d".into(), "job-1".into()]], "hello".into(), 1_700_000_000);
        e.verify().expect("a freshly signed event must verify");
        assert_eq!(e.tag("d"), Some("job-1"));
        assert_eq!(e.author().unwrap(), k.x_only_public_key().0);

        // Every field is covered by the id, so changing any of them breaks it.
        for mutate in [
            (|e: &mut Event| e.content = "goodbye".into()) as fn(&mut Event),
            |e: &mut Event| e.kind = 1,
            |e: &mut Event| e.created_at += 1,
            |e: &mut Event| e.tags.push(vec!["x".into()]),
            |e: &mut Event| e.pubkey = hex::encode(key(2).x_only_public_key().0.serialize()),
        ] {
            let mut bad = e.clone();
            mutate(&mut bad);
            assert!(matches!(bad.verify(), Err(EventError::IdMismatch)), "tampering must be caught");
        }
    }

    #[test]
    fn an_id_that_matches_but_a_signature_that_does_not_is_rejected() {
        // A relay could recompute an id honestly and still hand back an event
        // signed by someone else entirely.
        let real = Event::sign(&key(1), 1, vec![], "x".into(), 1);
        let forged = Event::sign(&key(2), 1, vec![], "x".into(), 1);
        let mut hybrid = real.clone();
        hybrid.sig = forged.sig;
        assert!(matches!(hybrid.verify(), Err(EventError::BadSignature(_))));
    }

    #[test]
    fn the_id_preimage_follows_nip01_exactly() {
        // Order and compactness are consensus for event ids across every relay
        // and client, so this is pinned rather than left to serde's whim.
        let s = id_preimage("ab", 7, 1, &[vec!["e".into(), "f".into()]], "hi");
        assert_eq!(s, r#"[0,"ab",7,1,[["e","f"]],"hi"]"#);
    }

    #[test]
    fn a_pseudonym_is_directly_usable_as_a_nostr_identity() {
        // Same curve, same signing primitive as attestations — no separate key
        // material, so a chain head and the events advertising it are provably
        // the same person.
        let seed = [9u8; 32];
        let pseudonym = krep_core::derive_context_keypair(&seed, "fabmesh");
        let e = Event::sign(&pseudonym, 30402, vec![], "job".into(), 1);
        e.verify().unwrap();
        assert_eq!(e.pubkey, hex::encode(pseudonym.x_only_public_key().0.serialize()));
    }
}
