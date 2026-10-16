//! Matrix encrypted attachments (`EncryptedFile`): AES-256-CTR with the key as a
//! JWK and a SHA-256 of the ciphertext.

use aes::Aes256;
use anyhow::{Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use ctr::cipher::{KeyIvInit, StreamCipher};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::Bridge;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

fn b64(s: &str) -> Result<Vec<u8>> {
    let s = s.trim_end_matches('=');
    STANDARD_NO_PAD.decode(s).or_else(|_| URL_SAFE_NO_PAD.decode(s)).map_err(|_| anyhow!("bad base64"))
}

/// Download and decrypt an `EncryptedFile`.
pub async fn download_encrypted(b: &Bridge, file: &Value) -> Result<Vec<u8>> {
    let mxc = file["url"].as_str().ok_or_else(|| anyhow!("encrypted file without url"))?;
    let key: [u8; 32] = b64(file["key"]["k"].as_str().unwrap_or_default())?.try_into().map_err(|_| anyhow!("bad key length"))?;
    let iv: [u8; 16] = b64(file["iv"].as_str().unwrap_or_default())?.try_into().map_err(|_| anyhow!("bad iv length"))?;
    let (mut data, _) = b.mx.download(mxc, b.config.bridge.max_media_bytes).await?;
    if let Some(want) = file["hashes"]["sha256"].as_str()
        && b64(want)? != Sha256::digest(&data).as_slice()
    {
        bail!("encrypted file hash mismatch");
    }
    Aes256Ctr::new(&key.into(), &iv.into()).apply_keystream(&mut data);
    Ok(data)
}

/// Encrypt bytes for an encrypted room: returns the ciphertext and the
/// `EncryptedFile` JSON minus its `url`.
pub fn encrypt_attachment(plain: &[u8]) -> (Vec<u8>, Value) {
    let key: [u8; 32] = rand::random();
    // The counter half of the IV starts at zero (spec recommendation).
    let mut iv = [0u8; 16];
    iv[..8].copy_from_slice(&rand::random::<[u8; 8]>());
    let mut data = plain.to_vec();
    Aes256Ctr::new(&key.into(), &iv.into()).apply_keystream(&mut data);
    let file = json!({
        "v": "v2",
        "key": { "kty": "oct", "key_ops": ["encrypt", "decrypt"], "alg": "A256CTR", "k": URL_SAFE_NO_PAD.encode(key), "ext": true },
        "iv": STANDARD_NO_PAD.encode(iv),
        "hashes": { "sha256": STANDARD_NO_PAD.encode(Sha256::digest(&data)) },
    });
    (data, file)
}
