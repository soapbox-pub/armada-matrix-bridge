//! Rekeys and Refoundings — CORD-06, the receiving side. A rotation delivers
//! per-recipient blobs (kind 3303, chunked) at an address derived from the PRIOR
//! secret; a member finding no blob across ALL chunks of a rotation that could
//! have named them knows they were removed.
//!
//! Blob plaintexts are fixed-width, carried as base64 inside NIP-44 (Armada's
//! signer APIs are string-only):
//! - channel rotation: 72 = `scope_id[32] ‖ epoch_be[8] ‖ new_key[32]`;
//! - base rotation: 104 adds `new_control_pk[32]`; 136 (staff) adds `new_control_root[32]`;
//! - a 72-byte base blob is the legacy pre-split form.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;

use crate::derive::{control_signer_group_key, epoch_key_commitment, recipient_locator};
use crate::edition::Citation;
use crate::stream::Opened;
use crate::{Bytes32, hex32, is_hex64, kinds, nip44, parse_tag_decimal, to_hex};

pub const ROOT_SCOPE_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// How many channel epochs past the held one to watch.
pub const CHANNEL_REKEY_LOOKAHEAD: u64 = 8;

#[derive(Debug, thiserror::Error)]
pub enum RekeyError {
    #[error("not a rekey rumor")]
    NotRekey,
    #[error("malformed {0}")]
    Field(&'static str),
    #[error("blob is {0} bytes, which is not a valid form")]
    Width(usize),
    #[error("blob scope or epoch does not match the rotation")]
    Splice,
    #[error("control_root does not derive to its control_pk")]
    ControlMismatch,
    #[error("blob failed to decrypt")]
    Decrypt,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Blob {
    pub locator: String,
    pub wrapped: String,
}

#[derive(Clone, Debug)]
pub struct ParsedRekey {
    pub rotator: String,
    pub scope_hex: String,
    pub new_epoch: u64,
    pub prev_epoch: u64,
    pub prev_commit: String,
    pub chunk_index: u64,
    pub chunk_count: u64,
    pub blobs: Vec<Blob>,
    pub ms: u64,
    pub authority: Option<Citation>,
}

pub fn parse_rekey(opened: &Opened) -> Result<ParsedRekey, RekeyError> {
    let r = &opened.rumor;
    if r.kind != kinds::REKEY || opened.seal_kind() != kinds::SEAL_ENCRYPTED {
        return Err(RekeyError::NotRekey);
    }
    let scope = r.tag_value("scope").filter(|s| is_hex64(s)).ok_or(RekeyError::Field("scope"))?;
    let new_epoch = r.tag_value("newepoch").and_then(parse_tag_decimal).ok_or(RekeyError::Field("newepoch"))?;
    let prev_epoch = r.tag_value("prevepoch").and_then(parse_tag_decimal).ok_or(RekeyError::Field("prevepoch"))?;
    let prev_commit = r.tag_value("prevcommit").filter(|s| is_hex64(s)).ok_or(RekeyError::Field("prevcommit"))?;
    let (chunk_index, chunk_count) = match r.tag("chunk") {
        Some(t) => (
            t.get(1).and_then(|s| parse_tag_decimal(s)).ok_or(RekeyError::Field("chunk"))?,
            t.get(2).and_then(|s| parse_tag_decimal(s)).ok_or(RekeyError::Field("chunk"))?,
        ),
        None => (1, 1),
    };
    if chunk_index < 1 || chunk_count < 1 || chunk_index > chunk_count {
        return Err(RekeyError::Field("chunk"));
    }
    let raw: Vec<serde_json::Value> = serde_json::from_str(&r.content).map_err(|_| RekeyError::Field("content"))?;
    let blobs = raw.into_iter().filter_map(|v| serde_json::from_value(v).ok()).collect();
    Ok(ParsedRekey {
        rotator: r.pubkey.clone(),
        scope_hex: scope.to_lowercase(),
        new_epoch,
        prev_epoch,
        prev_commit: prev_commit.to_lowercase(),
        chunk_index,
        chunk_count,
        blobs,
        ms: opened.ms,
        authority: Citation::from_tags(&r.tags),
    })
}

/// One rotation's chunks, correlated by (rotator, scope, newepoch, prevcommit).
#[derive(Clone, Debug)]
pub struct Rotation {
    pub rotator: String,
    pub scope_hex: String,
    pub new_epoch: u64,
    pub prev_epoch: u64,
    pub prev_commit: String,
    pub chunk_count: u64,
    pub chunks: BTreeMap<u64, ParsedRekey>,
    pub authority: Option<Citation>,
}

impl Rotation {
    /// A missing chunk is never a removal.
    pub fn is_complete(&self) -> bool {
        self.chunks.len() as u64 >= self.chunk_count
    }

    pub fn find_blob(&self, locator_hex: &str) -> Option<&Blob> {
        self.chunks.values().flat_map(|c| c.blobs.iter()).find(|b| b.locator == locator_hex)
    }

    /// When this rotation published (newest chunk ms).
    pub fn published_ms(&self) -> u64 {
        self.chunks.values().map(|c| c.ms).max().unwrap_or(0)
    }

    /// Continuity against the held key: `prevcommit` must commit to exactly it.
    pub fn continues_from(&self, held_epoch: u64, held_key: &Bytes32) -> Continuity {
        if self.prev_epoch == held_epoch {
            if to_hex(&epoch_key_commitment(held_epoch, held_key)) == self.prev_commit { Continuity::Ok } else { Continuity::Fork }
        } else if self.prev_epoch > held_epoch {
            Continuity::Gap
        } else {
            Continuity::Fork
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Continuity {
    Ok,
    Gap,
    Fork,
}

pub fn group_rotations(parsed: Vec<ParsedRekey>) -> Vec<Rotation> {
    let mut by_key: BTreeMap<(String, String, u64, String), Rotation> = BTreeMap::new();
    for p in parsed {
        let key = (p.rotator.clone(), p.scope_hex.clone(), p.new_epoch, p.prev_commit.clone());
        let set = by_key.entry(key).or_insert_with(|| Rotation {
            rotator: p.rotator.clone(),
            scope_hex: p.scope_hex.clone(),
            new_epoch: p.new_epoch,
            prev_epoch: p.prev_epoch,
            prev_commit: p.prev_commit.clone(),
            chunk_count: p.chunk_count,
            chunks: BTreeMap::new(),
            authority: p.authority.clone(),
        });
        if p.chunk_count == set.chunk_count {
            set.chunks.insert(p.chunk_index, p);
        }
    }
    by_key.into_values().collect()
}

/// My blob's locator for a rotation.
pub fn my_locator(rotator: &str, me: &str, scope_hex: &str, new_epoch: u64) -> Option<String> {
    Some(to_hex(&recipient_locator(&hex32(rotator)?, &hex32(me)?, &hex32(scope_hex)?, new_epoch)))
}

/// Decrypt a blob under the rotator↔me pairwise key.
pub fn open_blob(blob: &Blob, my_sk: &nostr::prelude::SecretKey, rotator: &nostr::prelude::PublicKey) -> Result<Vec<u8>, RekeyError> {
    let conv = crate::derive::conversation_key(my_sk, rotator);
    let b64 = nip44::decrypt_str(&conv, &blob.wrapped).map_err(|_| RekeyError::Decrypt)?;
    STANDARD.decode(b64.trim()).map_err(|_| RekeyError::Decrypt)
}

fn read_epoch(plain: &[u8]) -> u64 {
    u64::from_be_bytes(plain[32..40].try_into().unwrap())
}

/// Parse a 72-byte channel blob, verifying its inner scope and epoch.
pub fn decode_channel_blob(plain: &[u8], channel_id: &Bytes32, epoch: u64) -> Result<Bytes32, RekeyError> {
    if plain.len() != 72 {
        return Err(RekeyError::Width(plain.len()));
    }
    if &plain[..32] != channel_id || read_epoch(plain) != epoch {
        return Err(RekeyError::Splice);
    }
    Ok(plain[40..72].try_into().unwrap())
}

#[derive(Clone, Debug)]
pub struct BaseBlob {
    pub new_root: Bytes32,
    /// Absent on a legacy 72-byte blob.
    pub control_pk: Option<String>,
    /// The staff write secret, already checked to derive to `control_pk`.
    pub control_root: Option<Bytes32>,
}

/// Parse a 72/104/136-byte base blob.
pub fn decode_base_blob(plain: &[u8], community_id: &Bytes32, epoch: u64) -> Result<BaseBlob, RekeyError> {
    if !matches!(plain.len(), 72 | 104 | 136) {
        return Err(RekeyError::Width(plain.len()));
    }
    if plain[..32] != [0u8; 32] || read_epoch(plain) != epoch {
        return Err(RekeyError::Splice);
    }
    let new_root: Bytes32 = plain[40..72].try_into().unwrap();
    if plain.len() == 72 {
        return Ok(BaseBlob { new_root, control_pk: None, control_root: None });
    }
    let control_pk = to_hex(&plain[72..104]);
    if plain.len() == 104 {
        return Ok(BaseBlob { new_root, control_pk: Some(control_pk), control_root: None });
    }
    let control_root: Bytes32 = plain[104..136].try_into().unwrap();
    if control_signer_group_key(&control_root, community_id, epoch).pk_hex() != control_pk {
        return Err(RekeyError::ControlMismatch);
    }
    Ok(BaseBlob { new_root, control_pk: Some(control_pk), control_root: Some(control_root) })
}

/// Parse a decrypted 40-byte Grant `control_wrap`: `epoch_be[8] ‖ control_root[32]`.
pub fn decode_control_wrap(plain: &[u8]) -> Option<(u64, Bytes32)> {
    (plain.len() == 40).then(|| (u64::from_be_bytes(plain[..8].try_into().unwrap()), plain[8..40].try_into().unwrap()))
}
