//! NIP-17 private direct messages, over NIP-59 gift wrapping.
//!
//! Three layers, each hiding something different:
//!
//! - **rumor** (kind 14) — the message. Unsigned *on purpose*: a signed chat
//!   message is a transferable proof of what you said, so the recipient can
//!   read it but cannot prove to anyone else that you wrote it.
//! - **seal** (kind 13) — the rumor, encrypted to the recipient and signed by
//!   the sender's real key. This is what proves authorship, and only the
//!   recipient can open it.
//! - **gift wrap** (kind 1059) — the seal, encrypted to the recipient and
//!   signed by a throwaway key generated per message.
//!
//! What a relay sees is a kind 1059 from a pubkey that has never appeared
//! before, addressed to the recipient. It learns who is receiving and roughly
//! when; it does not learn who sent it, or that two messages came from the
//! same person.
//!
//! In FabMesh this carries the two things that genuinely cannot be public: the
//! shipping address, and the key that decrypts the design file.

use crate::event::{Event, EventError, Result};
use crate::nip44;
use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};

pub const KIND_RUMOR: u32 = 14;
pub const KIND_SEAL: u32 = 13;
pub const KIND_GIFT_WRAP: u32 = 1059;

/// How far back timestamps may be jittered. Exact times correlate messages
/// with each other and with on-chain activity, so both the seal and the wrap
/// get their own random offset.
const MAX_JITTER: u64 = 2 * 24 * 60 * 60;

/// An unsigned event. Serialized without a `sig` field at all.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rumor {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

impl Rumor {
    pub fn new(author: &XOnlyPublicKey, to: &XOnlyPublicKey, content: String, created_at: u64) -> Rumor {
        let pubkey = hex::encode(author.serialize());
        let tags = vec![vec!["p".into(), hex::encode(to.serialize())]];
        let id = crate::event::event_id(&pubkey, created_at, KIND_RUMOR, &tags, &content);
        Rumor { id: hex::encode(id), pubkey, created_at, kind: KIND_RUMOR, tags, content }
    }

    pub fn author(&self) -> Result<XOnlyPublicKey> {
        let b = hex::decode(&self.pubkey).map_err(|e| EventError::Malformed(format!("pubkey: {e}")))?;
        XOnlyPublicKey::from_slice(&b).map_err(|e| EventError::Malformed(format!("pubkey: {e}")))
    }
}

fn jitter(now: u64, seed: &[u8]) -> u64 {
    // Derived from the message rather than a global RNG so tests are
    // reproducible; the value only needs to be unpredictable to an observer.
    let mut h = [0u8; 8];
    h.copy_from_slice(&blake_seed(seed)[..8]);
    now.saturating_sub(u64::from_le_bytes(h) % MAX_JITTER)
}

fn blake_seed(seed: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut d = Sha256::new();
    d.update(seed);
    d.finalize().into()
}

/// Wrap a message for `to`, so that only they can read it and nobody can tell
/// who sent it.
pub fn wrap(sender: &Keypair, to: &XOnlyPublicKey, message: &str, now: u64) -> Result<Event> {
    let secp = Secp256k1::new();
    let author = sender.x_only_public_key().0;
    let rumor = Rumor::new(&author, to, message.to_string(), now);

    let ck = nip44::conversation_key(&sender.secret_key(), to)
        .map_err(|e| EventError::Malformed(format!("conversation key: {e}")))?;
    let sealed = nip44::encrypt(serde_json::to_string(&rumor).expect("serializable").as_bytes(), &ck)
        .map_err(|e| EventError::Malformed(format!("sealing: {e}")))?;
    let seal = Event::sign(sender, KIND_SEAL, vec![], sealed, jitter(now, rumor.id.as_bytes()));

    // A fresh key per message: reusing one would link every message from this
    // sender back together, which is the whole thing the wrap exists to stop.
    let mut ephemeral_secret = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut ephemeral_secret);
    let ephemeral = Keypair::from_secret_key(
        &secp,
        &SecretKey::from_slice(&ephemeral_secret).map_err(|e| EventError::Malformed(e.to_string()))?,
    );

    let wrap_ck = nip44::conversation_key(&ephemeral.secret_key(), to)
        .map_err(|e| EventError::Malformed(format!("wrap key: {e}")))?;
    let wrapped = nip44::encrypt(serde_json::to_string(&seal).expect("serializable").as_bytes(), &wrap_ck)
        .map_err(|e| EventError::Malformed(format!("wrapping: {e}")))?;
    Ok(Event::sign(
        &ephemeral,
        KIND_GIFT_WRAP,
        vec![vec!["p".into(), hex::encode(to.serialize())]],
        wrapped,
        jitter(now, seal.id.as_bytes()),
    ))
}

/// Open a gift wrap addressed to us, returning the message and who really sent
/// it.
pub fn unwrap(recipient: &Keypair, gift: &Event) -> Result<Rumor> {
    if gift.kind != KIND_GIFT_WRAP {
        return Err(EventError::Malformed(format!("kind {} is not a gift wrap", gift.kind)));
    }
    gift.verify()?;

    let wrap_ck = nip44::conversation_key(&recipient.secret_key(), &gift.author()?)
        .map_err(|e| EventError::Malformed(format!("wrap key: {e}")))?;
    let seal_json = nip44::decrypt(&gift.content, &wrap_ck)
        .map_err(|e| EventError::Malformed(format!("unwrapping: {e}")))?;
    let seal: Event = serde_json::from_slice(&seal_json)
        .map_err(|e| EventError::Malformed(format!("seal is not an event: {e}")))?;
    if seal.kind != KIND_SEAL {
        return Err(EventError::Malformed(format!("kind {} is not a seal", seal.kind)));
    }
    // The seal's signature is what establishes authorship; the wrap's proves
    // nothing about who wrote the message.
    seal.verify()?;

    let seal_ck = nip44::conversation_key(&recipient.secret_key(), &seal.author()?)
        .map_err(|e| EventError::Malformed(format!("seal key: {e}")))?;
    let rumor_json = nip44::decrypt(&seal.content, &seal_ck)
        .map_err(|e| EventError::Malformed(format!("opening seal: {e}")))?;
    let rumor: Rumor = serde_json::from_slice(&rumor_json)
        .map_err(|e| EventError::Malformed(format!("rumor is not an event: {e}")))?;

    // Without this a sender could seal a rumor attributed to somebody else and
    // the recipient would believe it came from them.
    if rumor.pubkey != seal.pubkey {
        return Err(EventError::Malformed("rumor author does not match the seal's signer".into()));
    }
    if rumor.kind != KIND_RUMOR {
        return Err(EventError::Malformed(format!("kind {} is not a chat rumor", rumor.kind)));
    }
    Ok(rumor)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp(b: u8) -> Keypair {
        Keypair::from_seckey_slice(&Secp256k1::new(), &[b; 32]).unwrap()
    }

    #[test]
    fn a_wrapped_message_round_trips_to_its_real_sender() {
        let alice = kp(1);
        let bob = kp(2);
        let gift = wrap(&alice, &bob.x_only_public_key().0, "ship to 12 Example St, Berlin", 1_700_000_000).unwrap();

        let rumor = unwrap(&bob, &gift).unwrap();
        assert_eq!(rumor.content, "ship to 12 Example St, Berlin");
        assert_eq!(rumor.author().unwrap(), alice.x_only_public_key().0, "authorship survives the wrap");
    }

    #[test]
    fn the_relay_learns_nothing_about_the_sender() {
        let alice = kp(1);
        let bob = kp(2);
        let gift = wrap(&alice, &bob.x_only_public_key().0, "secret", 1_700_000_000).unwrap();

        // The outer event is signed by a throwaway key, not Alice.
        assert_ne!(gift.pubkey, hex::encode(alice.x_only_public_key().0.serialize()));
        assert_eq!(gift.kind, KIND_GIFT_WRAP);
        assert_eq!(gift.tag("p"), Some(hex::encode(bob.x_only_public_key().0.serialize()).as_str()));
        // And nothing of the plaintext survives into anything public.
        assert!(!gift.content.contains("secret"));
        assert!(gift.verify().is_ok(), "still a well-formed event to the relay");

        // Two messages from the same sender share no visible identifier.
        let second = wrap(&alice, &bob.x_only_public_key().0, "secret", 1_700_000_000).unwrap();
        assert_ne!(gift.pubkey, second.pubkey, "a reused wrap key would link messages together");
    }

    #[test]
    fn only_the_addressee_can_open_it() {
        let alice = kp(1);
        let bob = kp(2);
        let eve = kp(3);
        let gift = wrap(&alice, &bob.x_only_public_key().0, "the address", 1).unwrap();
        assert!(unwrap(&eve, &gift).is_err(), "a third party must not be able to read it");
        assert!(unwrap(&alice, &gift).is_err(), "not even the sender can re-open their own wrap");
    }

    #[test]
    fn a_sealed_rumor_cannot_impersonate_someone_else() {
        let mallory = kp(4);
        let bob = kp(2);
        let victim = kp(5).x_only_public_key().0;

        // Mallory seals a rumor claiming to be from the victim.
        let forged = Rumor::new(&victim, &bob.x_only_public_key().0, "I accept your terms".into(), 1);
        let ck = nip44::conversation_key(&mallory.secret_key(), &bob.x_only_public_key().0).unwrap();
        let sealed = nip44::encrypt(serde_json::to_string(&forged).unwrap().as_bytes(), &ck).unwrap();
        let seal = Event::sign(&mallory, KIND_SEAL, vec![], sealed, 1);

        let eph = kp(6);
        let wck = nip44::conversation_key(&eph.secret_key(), &bob.x_only_public_key().0).unwrap();
        let wrapped = nip44::encrypt(serde_json::to_string(&seal).unwrap().as_bytes(), &wck).unwrap();
        let gift = Event::sign(&eph, KIND_GIFT_WRAP, vec![], wrapped, 1);

        let err = unwrap(&bob, &gift).unwrap_err();
        assert!(
            format!("{err}").contains("does not match the seal"),
            "the rumor's claimed author must be the seal's signer, got {err}"
        );
    }

    #[test]
    fn the_message_itself_is_never_signed() {
        // A signed chat message is a transferable receipt of what you said.
        // The rumor deliberately has no signature, so the recipient can read it
        // but cannot prove authorship to a third party.
        let r = Rumor::new(&kp(1).x_only_public_key().0, &kp(2).x_only_public_key().0, "hi".into(), 1);
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("\"sig\""), "a rumor must carry no signature");
    }

    #[test]
    fn timestamps_are_jittered_away_from_the_real_moment() {
        let now = 1_800_000_000;
        let gift = wrap(&kp(1), &kp(2).x_only_public_key().0, "x", now).unwrap();
        // The outer timestamp must not pin the message to when it was sent.
        assert!(gift.created_at <= now);
        assert!(now - gift.created_at <= MAX_JITTER);
    }
}
