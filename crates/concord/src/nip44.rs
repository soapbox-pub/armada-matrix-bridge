//! NIP-44 v2 under a raw conversation key, with the 65,535-byte plaintext cap
//! enforced at every layer (CORD-02 Appendix B): lenient publishers mint events
//! strict readers cannot decrypt.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use nostr::nips::nip44::v2::{ConversationKey, decrypt_to_bytes, encrypt_to_bytes_with_nonce};
use rand::RngCore;

use crate::Bytes32;

pub const MAX_PLAINTEXT: usize = 65_535;

#[derive(Debug, thiserror::Error)]
pub enum Nip44Error {
    #[error("plaintext exceeds the NIP-44 65,535-byte cap")]
    Oversize,
    #[error("plaintext is empty")]
    Empty,
    #[error("payload is not base64")]
    Base64,
    #[error("payload failed to decrypt")]
    Decrypt,
    #[error("plaintext is not UTF-8")]
    Utf8,
}

pub fn encrypt(conv_key: &Bytes32, plaintext: &[u8]) -> Result<String, Nip44Error> {
    if plaintext.is_empty() {
        return Err(Nip44Error::Empty);
    }
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(Nip44Error::Oversize);
    }
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let payload = encrypt_to_bytes_with_nonce(&ConversationKey::new(*conv_key), plaintext, nonce)
        .map_err(|_| Nip44Error::Oversize)?;
    Ok(STANDARD.encode(payload))
}

pub fn encrypt_str(conv_key: &Bytes32, plaintext: &str) -> Result<String, Nip44Error> {
    encrypt(conv_key, plaintext.as_bytes())
}

pub fn decrypt(conv_key: &Bytes32, payload: &str) -> Result<Vec<u8>, Nip44Error> {
    // A payload of a capped plaintext is at most ~87 KB of base64.
    if payload.len() > 2 * MAX_PLAINTEXT || payload.starts_with('#') {
        return Err(Nip44Error::Decrypt);
    }
    let bytes = STANDARD.decode(payload).map_err(|_| Nip44Error::Base64)?;
    let plain = decrypt_to_bytes(&ConversationKey::new(*conv_key), &bytes).map_err(|_| Nip44Error::Decrypt)?;
    if plain.len() > MAX_PLAINTEXT {
        return Err(Nip44Error::Oversize);
    }
    Ok(plain)
}

pub fn decrypt_str(conv_key: &Bytes32, payload: &str) -> Result<String, Nip44Error> {
    String::from_utf8(decrypt(conv_key, payload)?).map_err(|_| Nip44Error::Utf8)
}
