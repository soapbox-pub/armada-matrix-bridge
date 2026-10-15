//! Control Plane editions — CORD-04 §1. An edition is a kind-3308 rumor whose
//! machinery rides tags:
//!
//! ```text
//! ["vsk", n]               entity type
//! ["eid", hex32]           the entity's stable coordinate
//! ["ev",  n]               this edition's version, climbing from 1
//! ["ep",  hex32]           the previous edition's hash (absent on the first)
//! ["vac", eid, ver, hash]  the authority citation (absent when the owner acts)
//! ```

use sha2::{Digest, Sha256};

use crate::kinds;
use crate::rumor::Rumor;
use crate::stream::Opened;
use crate::{Bytes32, hex32, parse_tag_decimal, to_hex};

/// Edition-hash domain label (frozen; renaming it re-hashes every chain).
const EDITION_LABEL: &str = "vector-community/v1/edition";

/// `sha256(len64(label) ‖ label ‖ eid ‖ version_be ‖ has_prev ‖ prev|zero ‖ len64(content) ‖ content)`.
pub fn edition_hash(entity_id: &Bytes32, version: u64, prev: Option<&Bytes32>, content: &[u8]) -> Bytes32 {
    let mut h = Sha256::new();
    h.update((EDITION_LABEL.len() as u64).to_be_bytes());
    h.update(EDITION_LABEL.as_bytes());
    h.update(entity_id);
    h.update(version.to_be_bytes());
    match prev {
        Some(p) => {
            h.update([1]);
            h.update(p);
        }
        None => {
            h.update([0]);
            h.update([0u8; 32]);
        }
    }
    h.update((content.len() as u64).to_be_bytes());
    h.update(content);
    h.finalize().into()
}

/// The exact Grant edition an actor claims authority under (CORD-04 §5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Citation {
    pub entity_id: Bytes32,
    pub version: u64,
    pub edition_hash: Bytes32,
}

impl Citation {
    pub fn to_tag(&self) -> Vec<String> {
        vec!["vac".into(), to_hex(&self.entity_id), self.version.to_string(), to_hex(&self.edition_hash)]
    }

    pub fn from_tags(tags: &[Vec<String>]) -> Option<Self> {
        let t = tags.iter().find(|t| t.len() >= 4 && t[0] == "vac")?;
        Some(Citation { entity_id: hex32(&t[1])?, version: parse_tag_decimal(&t[2])?, edition_hash: hex32(&t[3])? })
    }
}

#[derive(Clone, Debug)]
pub struct Edition {
    pub author: String,
    pub vsk: String,
    pub entity_id: Bytes32,
    pub version: u64,
    pub prev: Option<Bytes32>,
    pub content: String,
    pub self_hash: Bytes32,
    pub created_at: u64,
    /// The rumor id — the equal-version tiebreak (lower wins).
    pub rumor_id: Bytes32,
    pub authority: Option<Citation>,
    /// The opened event, carrying the plaintext seal a compaction re-wraps.
    pub opened: Opened,
}

impl Edition {
    pub fn eid_hex(&self) -> String {
        to_hex(&self.entity_id)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EditionError {
    #[error("not a control edition")]
    NotAnEdition,
    #[error("control editions must ride a plaintext seal")]
    SealKind,
    #[error("duplicate machinery tag {0}")]
    Duplicate(&'static str),
    #[error("missing or malformed {0}")]
    Field(&'static str),
}

/// Parse an opened control event into an edition. Authorization is the fold's job.
pub fn parse_edition(opened: Opened) -> Result<Edition, EditionError> {
    let r: &Rumor = &opened.rumor;
    if r.kind != kinds::CONTROL {
        return Err(EditionError::NotAnEdition);
    }
    if opened.seal_kind() != kinds::SEAL_PLAINTEXT {
        return Err(EditionError::SealKind);
    }
    for name in ["vsk", "eid", "ev", "ep", "vac"] {
        if r.tags_named(name).count() > 1 {
            return Err(EditionError::Duplicate(name));
        }
    }
    let vsk = r.tag_value("vsk").ok_or(EditionError::Field("vsk"))?.to_owned();
    let entity_id = r.tag_value("eid").and_then(hex32).ok_or(EditionError::Field("eid"))?;
    let version = r.tag_value("ev").and_then(parse_tag_decimal).ok_or(EditionError::Field("ev"))?;
    let prev = match r.tag_value("ep") {
        Some(ep) => Some(hex32(ep).ok_or(EditionError::Field("ep"))?),
        None => None,
    };
    let self_hash = edition_hash(&entity_id, version, prev.as_ref(), r.content.as_bytes());
    let rumor_id = hex32(&r.id).ok_or(EditionError::Field("id"))?;
    Ok(Edition {
        author: r.pubkey.clone(),
        vsk,
        entity_id,
        version,
        prev,
        content: r.content.clone(),
        self_hash,
        created_at: r.created_at,
        rumor_id,
        authority: Citation::from_tags(&r.tags),
        opened,
    })
}

/// Build an unsigned edition rumor.
pub fn build_edition_rumor(
    vsk: &str,
    entity_id: &Bytes32,
    version: u64,
    prev: Option<&Bytes32>,
    content: String,
    actor: &str,
    authority: Option<&Citation>,
) -> Rumor {
    let mut tags = vec![
        vec!["vsk".to_string(), vsk.to_string()],
        vec!["eid".to_string(), to_hex(entity_id)],
        vec!["ev".to_string(), version.to_string()],
    ];
    if let Some(p) = prev {
        tags.push(vec!["ep".into(), to_hex(p)]);
    }
    if let Some(a) = authority {
        tags.push(a.to_tag());
    }
    Rumor::new(kinds::CONTROL, content, tags, actor, None, None)
}

/// A per-entity head, for chaining the next edition and floor-checking folds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Head {
    pub version: u64,
    #[serde(with = "hex_bytes32")]
    pub hash: Bytes32,
}

pub(crate) mod hex_bytes32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        crate::hex32(&s).ok_or_else(|| serde::de::Error::custom("expected 64 hex chars"))
    }
}

pub(crate) struct FoldResult {
    pub head: Option<usize>,
    pub gap: bool,
}

/// Fold ONE entity's editions into its chain-checked head (CORD-04 §1).
/// `floor` is the highest version already accepted (0 = none). Every sibling of a
/// version is kept, since the rumor-id tiebreak is publisher-chosen: the `prev`
/// link decides which one continues the chain.
pub(crate) fn fold_chain(editions: &[&Edition], floor: u64, floor_hash: Option<&Bytes32>) -> FoldResult {
    use std::collections::BTreeMap;
    let mut by_version: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (i, e) in editions.iter().enumerate() {
        if e.version >= floor {
            by_version.entry(e.version).or_default().push(i);
        }
    }
    for list in by_version.values_mut() {
        list.sort_by(|a, b| editions[*a].rumor_id.cmp(&editions[*b].rumor_id));
    }
    let versions: Vec<u64> = by_version.keys().copied().collect();
    let Some(&first) = versions.first() else {
        return FoldResult { head: None, gap: false };
    };
    let base = &by_version[&first];
    let anchor = if floor == 0 {
        if first == 1 { base.iter().copied().find(|&i| editions[i].prev.is_none()) } else { None }
    } else if let Some(fh) = floor_hash {
        if first == floor {
            base.iter().copied().find(|&i| &editions[i].self_hash == fh)
        } else if first == floor + 1 {
            base.iter().copied().find(|&i| editions[i].prev.as_ref() == Some(fh))
        } else {
            None
        }
    } else {
        None
    };
    let mut gap = anchor.is_none();
    let mut head = anchor.unwrap_or(base[0]);
    for w in versions.windows(2) {
        if w[1] != w[0] + 1 {
            gap = true;
            break;
        }
        let next = by_version[&w[1]].iter().copied().find(|&i| editions[i].prev.as_ref() == Some(&editions[head].self_hash));
        match next {
            Some(n) => head = n,
            None => {
                gap = true;
                break;
            }
        }
    }
    FoldResult { head: Some(head), gap }
}

/// The head a bootstrapping client accepts after a compaction: the winner at the
/// highest version, ignoring contiguity.
pub(crate) fn bootstrap_head(editions: &[&Edition], floor: u64) -> Option<usize> {
    let mut best: Option<usize> = None;
    for (i, e) in editions.iter().enumerate() {
        if e.version < floor {
            continue;
        }
        best = match best {
            None => Some(i),
            Some(b) => {
                let cur = editions[b];
                if e.version > cur.version || (e.version == cur.version && e.rumor_id < cur.rumor_id) { Some(i) } else { Some(b) }
            }
        };
    }
    best
}
