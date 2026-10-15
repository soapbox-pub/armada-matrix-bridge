//! Attachments: NIP-92 `imeta` tags and the Vector/0xChat client-side encryption
//! Armada uses (AES-256-GCM, 16-byte nonce, blob = `ciphertext || tag`).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::aes::Aes256;
use aes_gcm::{AesGcm, Nonce};
use aes_gcm::aead::consts::U16;
use rand::RngCore;
use sha2::{Digest, Sha256};

type Aes256Gcm16 = AesGcm<Aes256, U16>;

/// One parsed `imeta` tag.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Imeta {
    pub url: String,
    pub mime: Option<String>,
    /// sha256 of the blob as stored (ciphertext when encrypted).
    pub x: Option<String>,
    /// sha256 of the plaintext.
    pub ox: Option<String>,
    pub size: Option<u64>,
    pub dim: Option<(u32, u32)>,
    pub blurhash: Option<String>,
    pub alt: Option<String>,
    pub thumb: Option<String>,
    pub encryption: Option<MediaKey>,
    pub duration: Option<f64>,
    pub waveform: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaKey {
    pub key: [u8; 32],
    pub nonce: [u8; 16],
}

impl Imeta {
    /// Parse an `["imeta", "url …", "m …", …]` tag.
    pub fn parse(tag: &[String]) -> Option<Imeta> {
        if tag.first().map(String::as_str) != Some("imeta") {
            return None;
        }
        let mut m = Imeta::default();
        let (mut key, mut nonce, mut algo) = (None, None, None);
        for part in &tag[1..] {
            let Some((name, value)) = part.split_once(' ') else { continue };
            let value = value.to_owned();
            match name {
                "url" => m.url = value,
                "m" => m.mime = Some(value),
                "x" => m.x = Some(value),
                "ox" => m.ox = Some(value),
                "size" => m.size = value.parse().ok(),
                "dim" => {
                    m.dim = value.split_once('x').and_then(|(w, h)| Some((w.parse().ok()?, h.parse().ok()?)));
                }
                "blurhash" => m.blurhash = Some(value),
                "alt" => m.alt = Some(value),
                "thumb" => m.thumb = Some(value),
                "duration" => m.duration = value.parse().ok(),
                "waveform" => m.waveform = Some(value),
                "encryption-algorithm" => algo = Some(value),
                "decryption-key" => key = hex::decode(&value).ok().and_then(|k| k.try_into().ok()),
                "decryption-nonce" => nonce = hex::decode(&value).ok().and_then(|n| n.try_into().ok()),
                _ => {}
            }
        }
        if algo.as_deref() == Some("aes-gcm")
            && let (Some(key), Some(nonce)) = (key, nonce)
        {
            m.encryption = Some(MediaKey { key, nonce });
        }
        (!m.url.is_empty()).then_some(m)
    }

    pub fn to_tag(&self) -> Vec<String> {
        let mut t = vec!["imeta".to_owned(), format!("url {}", self.url)];
        let mut push = |name: &str, v: Option<String>| {
            if let Some(v) = v {
                t.push(format!("{name} {v}"));
            }
        };
        push("m", self.mime.clone());
        push("x", self.x.clone());
        push("ox", self.ox.clone());
        push("size", self.size.map(|s| s.to_string()));
        push("dim", self.dim.map(|(w, h)| format!("{w}x{h}")));
        push("blurhash", self.blurhash.clone());
        push("alt", self.alt.clone());
        push("duration", self.duration.map(|d| d.to_string()));
        if let Some(enc) = &self.encryption {
            push("encryption-algorithm", Some("aes-gcm".into()));
            push("decryption-key", Some(hex::encode(enc.key)));
            push("decryption-nonce", Some(hex::encode(enc.nonce)));
        }
        t
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Encrypt a blob under a fresh key: returns `(ciphertext||tag, key)`.
pub fn encrypt(plain: &[u8]) -> (Vec<u8>, MediaKey) {
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut key);
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm16::new(&key.into());
    let ct = cipher.encrypt(Nonce::<U16>::from_slice(&nonce), plain).expect("AES-GCM encryption is infallible for in-memory buffers");
    (ct, MediaKey { key, nonce })
}

pub fn decrypt(blob: &[u8], k: &MediaKey) -> Option<Vec<u8>> {
    Aes256Gcm16::new(&k.key.into()).decrypt(Nonce::<U16>::from_slice(&k.nonce), blob).ok()
}

/// Decrypt a community icon/banner pointer's blob (hex key and nonce).
pub fn decrypt_pointer(blob: &[u8], key_hex: &str, nonce_hex: &str) -> Option<Vec<u8>> {
    let key: [u8; 32] = hex::decode(key_hex).ok()?.try_into().ok()?;
    let nonce = hex::decode(nonce_hex).ok()?;
    match nonce.len() {
        16 => decrypt(blob, &MediaKey { key, nonce: nonce.try_into().ok()? }),
        12 => aes_gcm::Aes256Gcm::new(&key.into()).decrypt(aes_gcm::Nonce::from_slice(&nonce), blob).ok(),
        _ => None,
    }
}
