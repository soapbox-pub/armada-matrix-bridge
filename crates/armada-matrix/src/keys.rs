//! Everything derived from the master secret: Matrix users' Armada puppets, the
//! bridge's own key, and the seal for secrets at rest.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use nostr::prelude::{Keys, SecretKey};
use sha2::Sha256;

const PUPPET_LABEL: &str = "armada-matrix/puppet/v1/";
const BOT_LABEL: &str = "armada-matrix/bot/v1";
const SEAL_LABEL: &str = "armada-matrix/seal/v1";

#[derive(Clone)]
pub struct KeyRing {
    master: [u8; 32],
    seal: Aes256Gcm,
}

fn hkdf(master: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(None, master).expand(info, &mut out).expect("32 bytes");
    out
}

impl KeyRing {
    pub fn new(master: [u8; 32]) -> Self {
        let seal = Aes256Gcm::new(&hkdf(&master, SEAL_LABEL.as_bytes()).into());
        KeyRing { master, seal }
    }

    fn derive_keys(&self, label: &str) -> Keys {
        // A seed that is not a valid scalar (~2^-128) retries with a counter.
        for counter in 0u8..=255 {
            let mut info = label.as_bytes().to_vec();
            if counter > 0 {
                info.push(counter);
            }
            if let Ok(sk) = SecretKey::from_slice(&hkdf(&self.master, &info)) {
                return Keys::new(sk);
            }
        }
        unreachable!("256 scalar rejections")
    }

    /// The Armada identity a Matrix user posts under. Stateless: the same MXID
    /// always yields the same key.
    pub fn puppet(&self, mxid: &str) -> Keys {
        self.derive_keys(&format!("{PUPPET_LABEL}{mxid}"))
    }

    /// The passphrase for the Matrix crypto stores.
    pub fn crypto_passphrase(&self) -> String {
        hex::encode(hkdf(&self.master, b"armada-matrix/crypto-store/v1"))
    }

    pub fn default_bot(&self) -> Keys {
        self.derive_keys(BOT_LABEL)
    }

    /// AES-256-GCM seal: `nonce[12] ‖ ciphertext`.
    pub fn seal(&self, plain: &[u8]) -> Vec<u8> {
        let nonce: [u8; 12] = rand::random();
        let mut out = nonce.to_vec();
        out.extend(self.seal.encrypt(Nonce::from_slice(&nonce), plain).expect("in-memory AES-GCM"));
        out
    }

    pub fn unseal(&self, sealed: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(sealed.len() > 12, "sealed blob too short");
        self.seal.decrypt(Nonce::from_slice(&sealed[..12]), &sealed[12..]).map_err(|_| anyhow::anyhow!("sealed blob failed to open (wrong master secret?)"))
    }
}

/// Parse an nsec or 64-hex secret key.
pub fn parse_secret(s: &str) -> anyhow::Result<Keys> {
    Keys::parse(s.trim()).map_err(|e| anyhow::anyhow!("invalid Nostr secret key: {e}"))
}
