//! Derivations — CORD-02 Appendix A (frozen). Changing any labeled byte
//! re-addresses every prior event: treat this file as wire format.
//!
//! `hkdf(secret, label, id, epoch) = HKDF-SHA256(ikm=secret, salt=∅,
//! info = utf8(label) || 0x00 || id[32] || epoch_be[8]?, L=32)`.

use hkdf::Hkdf;
use nostr::prelude::{Keys, PublicKey, SecretKey};
use sha2::{Digest, Sha256};

use crate::Bytes32;

const LABEL_CHANNEL: &str = "concord/channel";
const LABEL_CONTROL: &str = "concord/control";
const LABEL_CONTROL_SIGNER: &str = "concord/control-signer";
const LABEL_REKEY_PSEUDONYM: &str = "concord/rekey-pseudonym";
const LABEL_BASE_REKEY_PSEUDONYM: &str = "concord/base-rekey-pseudonym";
const LABEL_RECIPIENT_PSEUDONYM: &str = "concord/recipient-pseudonym";
const LABEL_GUESTBOOK: &str = "concord/guestbook";
const LABEL_VOICE_SIGNER: &str = "concord/voice-signer";
const LABEL_DISSOLVED: &str = "concord/dissolved";
const LABEL_GRANT: &str = "concord/grant";
const LABEL_BANLIST: &str = "concord/banlist";
const LABEL_INVITE_LINKS: &str = "concord/invite-links";
const LABEL_PINS: &str = "concord/pins";
const LABEL_SIGNAL: &str = "concord/signal";
const LABEL_INVITE_KEY: &str = "concord/invite-key";
const LABEL_COMMUNITY: &str = "concord/community";
const LABEL_EPOCH_COMMITMENT: &str = "concord/epoch-key-commitment";

const ZERO32: Bytes32 = [0; 32];

fn build_info(label: &str, id: &Bytes32, epoch: Option<u64>) -> Vec<u8> {
    let mut info = Vec::with_capacity(label.len() + 41);
    info.extend_from_slice(label.as_bytes());
    info.push(0);
    info.extend_from_slice(id);
    if let Some(epoch) = epoch {
        info.extend_from_slice(&epoch.to_be_bytes());
    }
    info
}

fn hkdf32(ikm: &[u8], info: &[u8]) -> Bytes32 {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(None, ikm)
        .expand(info, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    out
}

/// A.3: retry with an appended counter byte until the seed is a valid scalar.
fn hkdf_to_secret_key(ikm: &[u8], base_info: &[u8]) -> SecretKey {
    if let Ok(sk) = SecretKey::from_slice(&hkdf32(ikm, base_info)) {
        return sk;
    }
    let mut info = base_info.to_vec();
    info.push(0);
    for counter in 0..=u8::MAX {
        *info.last_mut().unwrap() = counter;
        if let Ok(sk) = SecretKey::from_slice(&hkdf32(ikm, &info)) {
            return sk;
        }
    }
    unreachable!("257 consecutive scalar rejections")
}

/// A plane's stream keypair (A.2): the x-only pubkey is the on-wire address, the
/// secret signs its wraps, and the NIP-44 self-ECDH key encrypts them.
#[derive(Clone)]
pub struct GroupKey {
    pub keys: Keys,
    pub conv_key: Bytes32,
}

impl GroupKey {
    pub fn from_secret(sk: SecretKey) -> Self {
        let keys = Keys::new(sk);
        let conv_key = conversation_key(keys.secret_key(), &keys.public_key());
        Self { keys, conv_key }
    }

    pub fn pubkey(&self) -> PublicKey {
        self.keys.public_key()
    }

    pub fn pk_hex(&self) -> String {
        self.keys.public_key().to_hex()
    }
}

impl std::fmt::Debug for GroupKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupKey").field("pk", &self.pk_hex()).finish_non_exhaustive()
    }
}

/// The NIP-44 v2 conversation key between a secret and a public key.
pub fn conversation_key(sk: &SecretKey, pk: &PublicKey) -> Bytes32 {
    let ck = nostr::nips::nip44::v2::ConversationKey::derive(sk, pk).expect("valid keys always agree");
    let mut out = [0u8; 32];
    out.copy_from_slice(ck.as_bytes());
    out
}

fn group_key(label: &str, secret: &Bytes32, id: &Bytes32, epoch: Option<u64>) -> GroupKey {
    GroupKey::from_secret(hkdf_to_secret_key(secret, &build_info(label, id, epoch)))
}

/// A Channel's group key: `secret` is the community_root (Public, at the root
/// epoch) or the Channel's own key (Private, at its channel epoch) — CORD-03 §1.
pub fn channel_group_key(secret: &Bytes32, channel_id: &Bytes32, epoch: u64) -> GroupKey {
    group_key(LABEL_CHANNEL, secret, channel_id, Some(epoch))
}

/// The Control Plane's community_root-keyed key: post-split the READ key; on a
/// legacy epoch the whole plane (address and signer too).
pub fn control_group_key(root: &Bytes32, community_id: &Bytes32, epoch: u64) -> GroupKey {
    group_key(LABEL_CONTROL, root, community_id, Some(epoch))
}

/// The Control Plane's staff-only signer: its pk is the plane's address.
pub fn control_signer_group_key(control_root: &Bytes32, community_id: &Bytes32, epoch: u64) -> GroupKey {
    group_key(LABEL_CONTROL_SIGNER, control_root, community_id, Some(epoch))
}

pub fn guestbook_group_key(root: &Bytes32, community_id: &Bytes32, epoch: u64) -> GroupKey {
    group_key(LABEL_GUESTBOOK, root, community_id, Some(epoch))
}

/// A Channel's SFU room keypair (CORD-07 §1); never a stream address.
pub fn voice_group_key(secret: &Bytes32, channel_id: &Bytes32, epoch: u64) -> GroupKey {
    group_key(LABEL_VOICE_SIGNER, secret, channel_id, Some(epoch))
}

/// The dissolution tombstone's address — community_id-keyed, epoch-free.
pub fn dissolved_group_key(community_id: &Bytes32) -> GroupKey {
    group_key(LABEL_DISSOLVED, community_id, &ZERO32, None)
}

/// A private Channel's rekey address for `new_epoch`, keyed by the prior root.
pub fn channel_rekey_group_key(prior_root: &Bytes32, channel_id: &Bytes32, new_epoch: u64) -> GroupKey {
    group_key(LABEL_REKEY_PSEUDONYM, prior_root, channel_id, Some(new_epoch))
}

/// The base-rotation rekey address for `new_epoch`, keyed by the prior root.
pub fn base_rekey_group_key(prior_root: &Bytes32, community_id: &Bytes32, new_epoch: u64) -> GroupKey {
    group_key(LABEL_BASE_REKEY_PSEUDONYM, prior_root, community_id, Some(new_epoch))
}

pub fn grant_locator(community_id: &Bytes32, member: &Bytes32) -> Bytes32 {
    hkdf32(community_id, &build_info(LABEL_GRANT, member, None))
}

pub fn pins_locator(community_id: &Bytes32, channel_id: &Bytes32) -> Bytes32 {
    hkdf32(community_id, &build_info(LABEL_PINS, channel_id, None))
}

pub fn banlist_locator(community_id: &Bytes32) -> Bytes32 {
    hkdf32(community_id, &build_info(LABEL_BANLIST, &ZERO32, None))
}

pub fn invite_links_locator(community_id: &Bytes32, creator: &Bytes32) -> Bytes32 {
    hkdf32(community_id, &build_info(LABEL_INVITE_LINKS, creator, None))
}

/// A Community Signal's coordinate: the id slot is `sha256(utf8(signal_id))`.
pub fn signal_locator(community_id: &Bytes32, signal_id: &str) -> Bytes32 {
    let id: Bytes32 = Sha256::digest(signal_id.as_bytes()).into();
    hkdf32(community_id, &build_info(LABEL_SIGNAL, &id, None))
}

/// A rekey blob's per-recipient locator (CORD-06 §2), from public inputs only.
pub fn recipient_locator(rotator: &Bytes32, recipient: &Bytes32, scope_id: &Bytes32, new_epoch: u64) -> Bytes32 {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(rotator);
    ikm[32..].copy_from_slice(recipient);
    hkdf32(&ikm, &build_info(LABEL_RECIPIENT_PSEUDONYM, scope_id, Some(new_epoch)))
}

/// The public-invite bundle key, used directly as a NIP-44 conversation key.
pub fn invite_bundle_key(token: &[u8]) -> Bytes32 {
    hkdf32(token, &build_info(LABEL_INVITE_KEY, &ZERO32, None))
}

/// `sha256("concord/community" || owner_xonly || owner_salt)` (A.4).
pub fn community_id_of(owner: &Bytes32, owner_salt: &Bytes32) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(LABEL_COMMUNITY.as_bytes());
    h.update(owner);
    h.update(owner_salt);
    h.finalize().into()
}

/// `sha256("concord/epoch-key-commitment" || prev_epoch_be || prev_key)` (A.5).
pub fn epoch_key_commitment(prev_epoch: u64, prev_key: &Bytes32) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(LABEL_EPOCH_COMMITMENT.as_bytes());
    h.update(prev_epoch.to_be_bytes());
    h.update(prev_key);
    h.finalize().into()
}
