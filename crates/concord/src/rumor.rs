//! Unsigned rumors: the innermost events of every Concord envelope.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::parse_tag_decimal;

/// An unsigned Nostr event. Tags are kept as raw string arrays: Concord tags are
/// not standard NIP tags and must round-trip exactly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rumor {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u16,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("malformed ms tag")]
pub struct BadMs;

impl Rumor {
    /// Build a rumor. `ms` (epoch milliseconds) sets `created_at` to its seconds and
    /// adds the `["ms", 0..999]` remainder tag (CORD-02 §4); `None` stamps `created_at`
    /// directly with no `ms` tag (control editions).
    pub fn new(kind: u16, content: impl Into<String>, mut tags: Vec<Vec<String>>, pubkey: &str, ms: Option<u64>, created_at: Option<u64>) -> Self {
        let created_at = match ms {
            Some(ms) => {
                tags.push(vec!["ms".into(), (ms % 1000).to_string()]);
                ms / 1000
            }
            None => created_at.unwrap_or_else(crate::now_secs),
        };
        let mut rumor = Rumor { id: String::new(), pubkey: pubkey.to_owned(), created_at, kind, tags, content: content.into() };
        rumor.id = rumor.compute_id();
        rumor
    }

    /// The NIP-01 event hash over this rumor's fields.
    pub fn compute_id(&self) -> String {
        let canonical = serde_json::to_string(&(0, &self.pubkey, self.created_at, self.kind, &self.tags, &self.content))
            .expect("rumor fields always serialize");
        hex::encode(Sha256::digest(canonical.as_bytes()))
    }

    pub fn id_is_valid(&self) -> bool {
        self.id == self.compute_id()
    }

    /// The first tag named `name`.
    pub fn tag(&self, name: &str) -> Option<&[String]> {
        find_tag(&self.tags, name)
    }

    /// The value (index 1) of the first tag named `name`.
    pub fn tag_value(&self, name: &str) -> Option<&str> {
        tag_value(&self.tags, name)
    }

    /// Every tag named `name`.
    pub fn tags_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [String]> + 'a {
        self.tags.iter().filter(move |t| t.first().is_some_and(|n| n == name)).map(|t| t.as_slice())
    }

    /// The ordering timestamp in milliseconds: `created_at * 1000 + ms`. A missing
    /// tag reads as 0; a malformed one is an error, never clamped.
    pub fn time_ms(&self) -> Result<u64, BadMs> {
        resolve_ms(self.created_at, &self.tags)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("rumors always serialize")
    }
}

pub fn find_tag<'a>(tags: &'a [Vec<String>], name: &str) -> Option<&'a [String]> {
    tags.iter().find(|t| t.first().is_some_and(|n| n == name)).map(|t| t.as_slice())
}

pub fn tag_value<'a>(tags: &'a [Vec<String>], name: &str) -> Option<&'a str> {
    find_tag(tags, name).and_then(|t| t.get(1)).map(String::as_str)
}

pub fn resolve_ms(created_at: u64, tags: &[Vec<String>]) -> Result<u64, BadMs> {
    let Some(tag) = find_tag(tags, "ms") else {
        return Ok(created_at * 1000);
    };
    let raw = tag.get(1).ok_or(BadMs)?;
    let n = parse_tag_decimal(raw).filter(|n| *n <= 999 && raw.len() <= 3).ok_or(BadMs)?;
    Ok(created_at * 1000 + n)
}

/// Shorthand for building tags.
pub fn tag<I, S>(parts: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    parts.into_iter().map(Into::into).collect()
}
