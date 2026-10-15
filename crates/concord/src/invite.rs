//! Invites — CORD-05. A link is `$BASE/invite/<naddr>#<fragment>`: the naddr
//! names the bundle `(33301, link_signer, d="")`, and the fragment carries a
//! 16-byte unlock token plus up to 3 bootstrap relays.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use nostr::nips::nip19::{FromBech32, Nip19Coordinate};
use nostr::prelude::{Event, Keys, Kind, Tag, Timestamp, UnsignedEvent};
use nostr::event::FinalizeEvent;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::control::{ImagePointer, cap_relays};
use crate::derive::{community_id_of, invite_bundle_key};
use crate::{hex32, kinds, nip44, to_hex};

pub const TOKEN_BYTES: usize = 16;
pub const MAX_BOOTSTRAP_RELAYS: usize = 3;
pub const FRAGMENT_VERSION: u8 = 4;
pub const MAX_BUNDLE_CHANNELS: usize = 256;
pub const BUNDLE_DESCRIPTION_MAX_BYTES: usize = 500;
const FLAG_STOCK_SET: u8 = 0x01;

/// The CORD-05 §3 relay dictionary, generation 4.
pub const RELAY_DICTIONARY: [(u8, &str); 4] = [
    (1, "wss://jskitty.com/nostr"),
    (2, "wss://asia.vectorapp.io/nostr"),
    (3, "wss://relay.ditto.pub"),
    (4, "wss://relay.dreamith.to"),
];

pub fn stock_relays() -> Vec<String> {
    RELAY_DICTIONARY.iter().map(|(_, u)| (*u).to_owned()).collect()
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InviteError {
    #[error("not an invite link")]
    BadLink,
    #[error("malformed invite fragment: {0}")]
    BadFragment(&'static str),
    #[error("not a valid invite bundle: {0}")]
    BadBundle(String),
    #[error("the bundle's owner does not reproduce its community_id")]
    OwnerMismatch,
    #[error("this invite link has been revoked")]
    Revoked,
    #[error("this invite link has expired")]
    Expired,
    #[error("bundle exceeds protocol bounds")]
    Bounds,
}

/// A private Channel key as an invite carries it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleChannel {
    pub id: String,
    pub key: String,
    pub epoch: u64,
    #[serde(default)]
    pub name: String,
}

/// The CORD-05 §1 `CommunityInvite`. Unknown fields round-trip through `extra`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InviteBundle {
    pub community_id: String,
    pub owner: String,
    pub owner_salt: String,
    pub community_root: String,
    pub root_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_pk: Option<String>,
    #[serde(default)]
    pub channels: Vec<BundleChannel>,
    #[serde(default)]
    pub relays: Vec<String>,
    #[serde(default)]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<ImagePointer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Unix ms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator_npub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl InviteBundle {
    /// Bound and verify a decrypted bundle however it arrived (CORD-05 §1/§6).
    pub fn validate(mut self) -> Result<Self, InviteError> {
        if self.channels.len() > MAX_BUNDLE_CHANNELS {
            return Err(InviteError::Bounds);
        }
        self.relays = cap_relays(std::mem::take(&mut self.relays));
        if let Some(d) = &mut self.description {
            truncate_utf8(d, BUNDLE_DESCRIPTION_MAX_BYTES);
        }
        let (Some(cid), Some(owner), Some(salt)) = (hex32(&self.community_id), hex32(&self.owner), hex32(&self.owner_salt)) else {
            return Err(InviteError::OwnerMismatch);
        };
        if community_id_of(&owner, &salt) != cid {
            return Err(InviteError::OwnerMismatch);
        }
        self.community_id = self.community_id.to_lowercase();
        self.owner = self.owner.to_lowercase();
        Ok(self)
    }

    pub fn is_expired(&self, now_ms: u64) -> bool {
        self.expires_at.is_some_and(|e| now_ms > e)
    }
}

fn truncate_utf8(s: &mut String, max: usize) {
    if s.len() <= max {
        return;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
}

/// Encode `[version][flags][relays?][token:16]` as unpadded base64url.
pub fn encode_fragment(token: &[u8; TOKEN_BYTES], relays: &[String]) -> Result<String, InviteError> {
    let stock = stock_relays();
    let mut bytes = vec![FRAGMENT_VERSION];
    if relays == stock.as_slice() {
        bytes.push(FLAG_STOCK_SET);
    } else {
        let bounded = &relays[..relays.len().min(MAX_BOOTSTRAP_RELAYS)];
        bytes.push(0);
        bytes.push(bounded.len() as u8);
        for relay in bounded {
            if let Some((id, _)) = RELAY_DICTIONARY.iter().find(|(_, u)| *u == relay) {
                bytes.push(*id);
            } else if let Some(host) = relay.strip_prefix("wss://") {
                let len = u8::try_from(host.len()).map_err(|_| InviteError::BadFragment("relay host too long"))?;
                bytes.push(0);
                bytes.push(len);
                bytes.extend_from_slice(host.as_bytes());
            } else {
                let len = u8::try_from(relay.len()).map_err(|_| InviteError::BadFragment("relay URL too long"))?;
                bytes.push(255);
                bytes.push(len);
                bytes.extend_from_slice(relay.as_bytes());
            }
        }
    }
    bytes.extend_from_slice(token);
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Decode an invite fragment into its token and bootstrap relays.
pub fn decode_fragment(fragment: &str) -> Result<([u8; TOKEN_BYTES], Vec<String>), InviteError> {
    let trimmed = fragment.trim().trim_end_matches('=');
    let bytes = URL_SAFE_NO_PAD.decode(trimmed).map_err(|_| InviteError::BadFragment("not base64url"))?;
    let mut o = 0usize;
    let need = |o: usize, n: usize| if o + n > bytes.len() { Err(InviteError::BadFragment("truncated")) } else { Ok(()) };
    need(o, 2)?;
    let version = bytes[o];
    o += 1;
    if version < FRAGMENT_VERSION {
        return Err(InviteError::BadFragment("legacy invite format"));
    }
    if version > FRAGMENT_VERSION {
        return Err(InviteError::BadFragment("invite format is newer than this bridge"));
    }
    let flags = bytes[o];
    o += 1;
    let mut relays = Vec::new();
    if flags & FLAG_STOCK_SET != 0 {
        relays = stock_relays();
    } else {
        need(o, 1)?;
        let count = bytes[o] as usize;
        o += 1;
        if count > MAX_BOOTSTRAP_RELAYS {
            return Err(InviteError::BadFragment("too many bootstrap relays"));
        }
        for _ in 0..count {
            need(o, 1)?;
            let lead = bytes[o];
            o += 1;
            if (1..=254).contains(&lead) {
                // Unknown dictionary ids are skipped: the dictionary grows.
                if let Some((_, url)) = RELAY_DICTIONARY.iter().find(|(id, _)| *id == lead) {
                    relays.push((*url).to_owned());
                }
            } else {
                need(o, 1)?;
                let len = bytes[o] as usize;
                o += 1;
                need(o, len)?;
                let text = String::from_utf8_lossy(&bytes[o..o + len]).into_owned();
                o += len;
                relays.push(if lead == 255 { text } else { format!("wss://{text}") });
            }
        }
    }
    need(o, TOKEN_BYTES)?;
    let mut token = [0u8; TOKEN_BYTES];
    token.copy_from_slice(&bytes[o..o + TOKEN_BYTES]);
    if o + TOKEN_BYTES != bytes.len() {
        return Err(InviteError::BadFragment("trailing bytes"));
    }
    Ok((token, relays))
}

/// A parsed invite link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteLink {
    /// The link signer's pubkey (hex): the bundle coordinate's author.
    pub link_signer: String,
    pub token: [u8; TOKEN_BYTES],
    pub bootstrap_relays: Vec<String>,
    pub naddr: String,
}

fn naddr_signer(naddr: &str) -> Option<String> {
    let coord = Nip19Coordinate::from_bech32(naddr).ok()?;
    (coord.kind == Kind::Custom(kinds::INVITE_BUNDLE) && coord.identifier.is_empty()).then(|| coord.public_key.to_hex())
}

/// Parse `…/invite/<naddr>#<fragment>` or a bare `<naddr>#<fragment>`.
pub fn parse_invite_link(input: &str) -> Result<InviteLink, InviteError> {
    let trimmed = input.trim();
    let (path, fragment) = trimmed.split_once('#').ok_or(InviteError::BadLink)?;
    let naddr = match path.find("/invite/") {
        Some(i) => &path[i + "/invite/".len()..],
        None if path.starts_with("naddr1") => path,
        None => return Err(InviteError::BadLink),
    };
    let naddr = naddr.trim_end_matches('/').split(['?', '/']).next().unwrap_or("");
    let link_signer = naddr_signer(naddr).ok_or(InviteError::BadLink)?;
    let (token, bootstrap_relays) = decode_fragment(fragment)?;
    Ok(InviteLink { link_signer, token, bootstrap_relays, naddr: naddr.to_owned() })
}

/// Verify and decrypt a fetched bundle event.
pub fn parse_bundle_event(event: &Event, link: &InviteLink, now_ms: u64) -> Result<InviteBundle, InviteError> {
    if event.kind != Kind::Custom(kinds::INVITE_BUNDLE) || event.pubkey.to_hex() != link.link_signer || event.verify().is_err() {
        return Err(InviteError::BadBundle("not a valid invite bundle event".into()));
    }
    let vsk = event.tags.iter().map(|t| t.as_slice()).find(|t| t.first().is_some_and(|n| n == "vsk")).and_then(|t| t.get(1)).cloned();
    match vsk.as_deref() {
        Some(kinds::VSK_INVITE_REVOKED) => return Err(InviteError::Revoked),
        Some(kinds::VSK_INVITE_LIVE) => {}
        other => return Err(InviteError::BadBundle(format!("unknown bundle marker {other:?}"))),
    }
    let plain = nip44::decrypt_str(&invite_bundle_key(&link.token), &event.content).map_err(|e| InviteError::BadBundle(e.to_string()))?;
    let bundle: InviteBundle = serde_json::from_str(&plain).map_err(|e| InviteError::BadBundle(e.to_string()))?;
    let bundle = bundle.validate()?;
    if bundle.is_expired(now_ms) {
        return Err(InviteError::Expired);
    }
    Ok(bundle)
}

/// Build the addressable bundle event, marked live.
pub fn build_bundle_event(bundle: &InviteBundle, token: &[u8; TOKEN_BYTES], link_signer: &Keys) -> Result<Event, InviteError> {
    let json = serde_json::to_string(bundle).map_err(|e| InviteError::BadBundle(e.to_string()))?;
    let content = nip44::encrypt_str(&invite_bundle_key(token), &json).map_err(|e| InviteError::BadBundle(e.to_string()))?;
    let tags = [Tag::parse(["d", ""]).unwrap(), Tag::parse(["vsk", kinds::VSK_INVITE_LIVE]).unwrap()];
    UnsignedEvent::new(link_signer.public_key(), Timestamp::now(), Kind::Custom(kinds::INVITE_BUNDLE), tags, content)
        .finalize(link_signer)
        .map_err(|e| InviteError::BadBundle(e.to_string()))
}

/// The hex token for display/storage.
pub fn token_hex(token: &[u8; TOKEN_BYTES]) -> String {
    to_hex(token)
}
