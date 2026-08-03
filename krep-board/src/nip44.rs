//! NIP-44 v2 encryption.
//!
//! ChaCha20 for confidentiality, HMAC-SHA256 for integrity, HKDF-SHA256 to
//! derive both from an ECDH shared secret. Encrypt-then-MAC, with the nonce
//! authenticated as associated data.
//!
//! Everything here is checked against the official NIP-44 test vectors — 35
//! conversation keys, 24 padding cases, full encrypt/decrypt round trips and
//! the invalid-input cases. A hand-read of the spec is not evidence; the
//! vectors are.

use base64::Engine;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Mac, SimpleHmac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;

const VERSION: u8 = 2;
const SALT: &[u8] = b"nip44-v2";
const MIN_PLAINTEXT: usize = 1;
const MAX_PLAINTEXT: usize = 65535;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Nip44Error {
    #[error("plaintext must be {MIN_PLAINTEXT}..={MAX_PLAINTEXT} bytes, got {0}")]
    PlaintextLength(usize),
    #[error("payload is malformed: {0}")]
    Malformed(&'static str),
    #[error("unsupported version {0}")]
    Version(u8),
    #[error("message authentication failed")]
    BadMac,
    #[error("invalid key: {0}")]
    Key(String),
}

pub type Result<T> = std::result::Result<T, Nip44Error>;

/// Shared secret for a pair of participants, reusable across messages.
///
/// Derived from the raw x-coordinate of the ECDH point — *not* the hashed
/// shared secret most libraries hand you by default, which is a common way to
/// get NIP-44 subtly wrong and silently fail to interoperate.
pub fn conversation_key(secret: &secp256k1::SecretKey, peer: &secp256k1::XOnlyPublicKey) -> Result<[u8; 32]> {
    let full = peer.public_key(secp256k1::Parity::Even);
    let point = secp256k1::ecdh::shared_secret_point(&full, secret);
    // The conversation key is HKDF-Extract's PRK over the raw x-coordinate.
    Ok(hkdf_extract(SALT, &point[..32]))
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut mac = <SimpleHmac<Sha256> as Mac>::new_from_slice(salt).expect("hmac accepts any key length");
    mac.update(ikm);
    mac.finalize().into_bytes().into()
}

/// Per-message keys, bound to the nonce so no two messages share a keystream.
fn message_keys(conversation_key: &[u8; 32], nonce: &[u8; 32]) -> Result<([u8; 32], [u8; 12], [u8; 32])> {
    let hk = Hkdf::<Sha256>::from_prk(conversation_key).map_err(|_| Nip44Error::Key("bad prk".into()))?;
    let mut out = [0u8; 76];
    hk.expand(nonce, &mut out).map_err(|_| Nip44Error::Key("hkdf expand".into()))?;
    let mut chacha_key = [0u8; 32];
    let mut chacha_nonce = [0u8; 12];
    let mut hmac_key = [0u8; 32];
    chacha_key.copy_from_slice(&out[0..32]);
    chacha_nonce.copy_from_slice(&out[32..44]);
    hmac_key.copy_from_slice(&out[44..76]);
    Ok((chacha_key, chacha_nonce, hmac_key))
}

/// Padded length for a plaintext, per NIP-44's scheme.
///
/// Padding to coarse buckets rather than to a fixed block is what stops the
/// ciphertext length from revealing the message length precisely — an address
/// is a very different size from "ok".
pub fn calc_padded_len(len: usize) -> usize {
    if len <= 32 {
        return 32;
    }
    let next_power = 1usize << (usize::BITS - (len - 1).leading_zeros()) as usize;
    let chunk = if next_power <= 256 { 32 } else { next_power / 8 };
    chunk * ((len - 1) / chunk + 1)
}

fn pad(plaintext: &[u8]) -> Result<Vec<u8>> {
    let len = plaintext.len();
    if !(MIN_PLAINTEXT..=MAX_PLAINTEXT).contains(&len) {
        return Err(Nip44Error::PlaintextLength(len));
    }
    let mut out = Vec::with_capacity(2 + calc_padded_len(len));
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.extend_from_slice(plaintext);
    out.resize(2 + calc_padded_len(len), 0);
    Ok(out)
}

fn unpad(padded: &[u8]) -> Result<Vec<u8>> {
    if padded.len() < 2 {
        return Err(Nip44Error::Malformed("padded message too short"));
    }
    let len = u16::from_be_bytes([padded[0], padded[1]]) as usize;
    let body = padded.get(2..2 + len).ok_or(Nip44Error::Malformed("declared length exceeds payload"))?;
    // The declared length must be the one the padding scheme would have
    // produced, or an attacker could re-cut a valid ciphertext.
    if len < MIN_PLAINTEXT || padded.len() != 2 + calc_padded_len(len) {
        return Err(Nip44Error::Malformed("padding does not match declared length"));
    }
    Ok(body.to_vec())
}

/// Encrypt with an explicit nonce. Used by the test vectors; callers should
/// prefer [`encrypt`], which generates one.
pub fn encrypt_with_nonce(plaintext: &[u8], conversation_key: &[u8; 32], nonce: &[u8; 32]) -> Result<String> {
    let (ck, cn, hk) = message_keys(conversation_key, nonce)?;
    let mut buf = pad(plaintext)?;
    chacha20::ChaCha20::new(&ck.into(), &cn.into()).apply_keystream(&mut buf);

    let mut mac = <SimpleHmac<Sha256> as Mac>::new_from_slice(&hk).expect("any key length");
    // The nonce is authenticated as associated data, so it cannot be swapped.
    mac.update(nonce);
    mac.update(&buf);
    let tag = mac.finalize().into_bytes();

    let mut payload = Vec::with_capacity(1 + 32 + buf.len() + 32);
    payload.push(VERSION);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(&buf);
    payload.extend_from_slice(&tag);
    Ok(base64::engine::general_purpose::STANDARD.encode(payload))
}

pub fn encrypt(plaintext: &[u8], conversation_key: &[u8; 32]) -> Result<String> {
    use rand::RngCore;
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    encrypt_with_nonce(plaintext, conversation_key, &nonce)
}

pub fn decrypt(payload: &str, conversation_key: &[u8; 32]) -> Result<Vec<u8>> {
    // Reject the "unencrypted" marker outright rather than letting it reach
    // the base64 decoder.
    if payload.starts_with('#') {
        return Err(Nip44Error::Version(b'#'));
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(payload)
        .map_err(|_| Nip44Error::Malformed("not valid base64"))?;
    if raw.len() < 1 + 32 + 32 + 2 {
        return Err(Nip44Error::Malformed("payload too short"));
    }
    if raw[0] != VERSION {
        return Err(Nip44Error::Version(raw[0]));
    }
    let nonce: [u8; 32] = raw[1..33].try_into().expect("checked length");
    let ct = &raw[33..raw.len() - 32];
    let tag = &raw[raw.len() - 32..];

    let (ck, cn, hk) = message_keys(conversation_key, &nonce)?;
    let mut mac = <SimpleHmac<Sha256> as Mac>::new_from_slice(&hk).expect("any key length");
    mac.update(&nonce);
    mac.update(ct);
    // Constant time: a timing-variable compare would leak the tag byte by byte.
    if mac.finalize().into_bytes().ct_eq(tag).unwrap_u8() != 1 {
        return Err(Nip44Error::BadMac);
    }

    let mut buf = ct.to_vec();
    chacha20::ChaCha20::new(&ck.into(), &cn.into()).apply_keystream(&mut buf);
    unpad(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, Secp256k1, SecretKey};

    /// The official vectors, vendored so the suite does not depend on network.
    fn vectors() -> serde_json::Value {
        serde_json::from_str(include_str!("../tests/nip44.vectors.json")).expect("vectors parse")
    }

    fn hex32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    #[test]
    fn conversation_keys_match_the_official_vectors() {
        let v = vectors();
        let cases = v["v2"]["valid"]["get_conversation_key"].as_array().unwrap();
        assert!(cases.len() >= 30, "expected the full vector set");
        let secp = Secp256k1::new();
        for c in cases {
            let sec1 = SecretKey::from_slice(&hex::decode(c["sec1"].as_str().unwrap()).unwrap()).unwrap();
            // Vectors give the peer either as a second secret key or directly
            // as an x-only pubkey.
            let pub2 = match (c.get("sec2").and_then(|v| v.as_str()), c.get("pub2").and_then(|v| v.as_str())) {
                (Some(sec2), _) => Keypair::from_secret_key(
                    &secp,
                    &SecretKey::from_slice(&hex::decode(sec2).unwrap()).unwrap(),
                )
                .x_only_public_key()
                .0,
                (None, Some(pub2)) => {
                    secp256k1::XOnlyPublicKey::from_slice(&hex::decode(pub2).unwrap()).unwrap()
                }
                _ => panic!("vector has neither sec2 nor pub2"),
            };
            let got = conversation_key(&sec1, &pub2).unwrap();
            assert_eq!(hex::encode(got), c["conversation_key"].as_str().unwrap(), "{c}");
        }
    }

    #[test]
    fn padding_matches_the_official_vectors() {
        let v = vectors();
        for pair in v["v2"]["valid"]["calc_padded_len"].as_array().unwrap() {
            let a = pair[0].as_u64().unwrap() as usize;
            let b = pair[1].as_u64().unwrap() as usize;
            assert_eq!(calc_padded_len(a), b, "padded len for {a}");
        }
    }

    #[test]
    fn encrypt_decrypt_matches_the_official_vectors() {
        let v = vectors();
        for c in v["v2"]["valid"]["encrypt_decrypt"].as_array().unwrap() {
            let ck = hex32(c["conversation_key"].as_str().unwrap());
            let nonce = hex32(c["nonce"].as_str().unwrap());
            let plaintext = c["plaintext"].as_str().unwrap();
            let expected = c["payload"].as_str().unwrap();

            let got = encrypt_with_nonce(plaintext.as_bytes(), &ck, &nonce).unwrap();
            assert_eq!(got, expected, "ciphertext for {plaintext:?}");
            let back = decrypt(expected, &ck).unwrap();
            assert_eq!(String::from_utf8(back).unwrap(), plaintext);
        }
    }

    #[test]
    fn the_invalid_vectors_are_all_rejected() {
        let v = vectors();
        for c in v["v2"]["invalid"]["decrypt"].as_array().unwrap() {
            let ck = hex32(c["conversation_key"].as_str().unwrap());
            let payload = c["payload"].as_str().unwrap();
            assert!(
                decrypt(payload, &ck).is_err(),
                "must reject {}: {}",
                c["note"].as_str().unwrap_or(""),
                payload
            );
        }
        for c in v["v2"]["invalid"]["encrypt_msg_lengths"].as_array().unwrap() {
            let len = c.as_u64().unwrap() as usize;
            let ck = [7u8; 32];
            assert!(encrypt(&vec![b'a'; len], &ck).is_err(), "must reject a {len}-byte plaintext");
        }
    }

    #[test]
    fn a_tampered_ciphertext_does_not_decrypt() {
        let ck = [3u8; 32];
        let payload = encrypt(b"ship to 12 Example Street", &ck).unwrap();
        let mut raw = base64::engine::general_purpose::STANDARD.decode(&payload).unwrap();
        // Flip a bit in the ciphertext body. Without the MAC this would decrypt
        // to a corrupted address rather than fail.
        let i = raw.len() / 2;
        raw[i] ^= 1;
        let tampered = base64::engine::general_purpose::STANDARD.encode(&raw);
        assert_eq!(decrypt(&tampered, &ck), Err(Nip44Error::BadMac));
    }

    #[test]
    fn conversation_keys_are_symmetric_and_pair_specific() {
        let secp = Secp256k1::new();
        let a = Keypair::from_seckey_slice(&secp, &[1u8; 32]).unwrap();
        let b = Keypair::from_seckey_slice(&secp, &[2u8; 32]).unwrap();
        let c = Keypair::from_seckey_slice(&secp, &[3u8; 32]).unwrap();

        let ab = conversation_key(&a.secret_key(), &b.x_only_public_key().0).unwrap();
        let ba = conversation_key(&b.secret_key(), &a.x_only_public_key().0).unwrap();
        assert_eq!(ab, ba, "both sides must derive the same key");

        let ac = conversation_key(&a.secret_key(), &c.x_only_public_key().0).unwrap();
        assert_ne!(ab, ac, "a third party must not share the conversation");
        assert!(decrypt(&encrypt(b"hello", &ab).unwrap(), &ac).is_err());
    }
}
