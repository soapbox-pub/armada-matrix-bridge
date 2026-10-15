//! Chat Plane rumors — CORD-03 §3 and Armada's conventions on top. Every chat
//! rumor commits `["channel", id]` and `["epoch", n]`.

use nostr::nips::nip19::{FromBech32, Nip19Event};
use nostr::prelude::EventId;

use crate::kinds;
use crate::rumor::{Rumor, tag};
use crate::stream::channel_binding_tags;

/// Where a chat rumor goes: a channel id at an epoch.
#[derive(Clone, Debug)]
pub struct Binding<'a> {
    pub channel_id_hex: &'a str,
    pub epoch: u64,
}

impl Binding<'_> {
    fn tags(&self) -> Vec<Vec<String>> {
        channel_binding_tags(self.channel_id_hex, self.epoch)
    }
}

/// A reference to another rumor, for replies, reactions, edits and deletes.
#[derive(Clone, Debug)]
pub struct Target<'a> {
    pub id: &'a str,
    pub kind: u16,
    pub author: &'a str,
    /// The target's own tags (a thread reply inherits its parent's root tags).
    pub tags: &'a [Vec<String>],
}

/// NIP-22 tags for a kind-1111 thread reply: uppercase pin the thread root
/// (inherited when the parent is itself a reply), lowercase the parent.
pub fn comment_tags(parent: &Target) -> Vec<Vec<String>> {
    let mut tags: Vec<Vec<String>> =
        parent.tags.iter().filter(|t| matches!(t.first().map(String::as_str), Some("K" | "E" | "P"))).cloned().collect();
    if tags.is_empty() {
        tags.push(tag(["K", &parent.kind.to_string()]));
        tags.push(tag(["E", parent.id, "", parent.author]));
        tags.push(tag(["P", parent.author]));
    }
    tags.push(tag(["k", &parent.kind.to_string()]));
    tags.push(tag(["e", parent.id, "", parent.author]));
    tags.push(tag(["p", parent.author]));
    tags
}

/// NIP-40 deadline for a durable chat rumor under the community timer (CORD-08).
/// Deletes and timer notices never expire.
pub fn expiration_for(kind: u16, ms: u64, timer_secs: Option<u64>) -> Option<u64> {
    let timer = timer_secs.filter(|t| *t > 0)?;
    if matches!(kind, kinds::DELETE | kinds::TIMER_NOTICE | kinds::TYPING | kinds::VOICE_PRESENCE) {
        return None;
    }
    Some(ms / 1000 + timer)
}

fn finish(kind: u16, content: String, mut tags: Vec<Vec<String>>, author: &str, ms: u64, expiration: Option<u64>) -> Rumor {
    // A quoted author is often also mentioned; one `p` each is enough.
    let mut seen = std::collections::HashSet::new();
    tags.retain(|t| t.first().map(String::as_str) != Some("p") || seen.insert(t.get(1).cloned()));
    if let Some(exp) = expiration {
        tags.push(tag(["expiration", &exp.to_string()]));
    }
    Rumor::new(kind, content, tags, author, Some(ms), None)
}

/// A kind-9 message, or a kind-1111 thread reply when `thread_parent` is set.
/// `quote` makes it an inline reply (NIP-C7 `q`).
#[allow(clippy::too_many_arguments)]
pub fn message(
    b: &Binding,
    author: &str,
    content: String,
    thread_parent: Option<&Target>,
    quote: Option<&Target>,
    extra: Vec<Vec<String>>,
    ms: u64,
    timer_secs: Option<u64>,
) -> Rumor {
    let mut tags = b.tags();
    let kind = match thread_parent {
        Some(parent) => {
            tags.extend(comment_tags(parent));
            kinds::COMMENT
        }
        None => kinds::MESSAGE,
    };
    if let Some(q) = quote {
        tags.push(tag(["q", q.id, "", q.author]));
        tags.push(tag(["p", q.author]));
    }
    tags.extend(extra);
    finish(kind, content, tags, author, ms, expiration_for(kind, ms, timer_secs))
}

pub fn reaction(b: &Binding, author: &str, target: &Target, content: &str, extra: Vec<Vec<String>>, ms: u64, timer_secs: Option<u64>) -> Rumor {
    let mut tags = b.tags();
    tags.push(tag(["e", target.id]));
    tags.push(tag(["p", target.author]));
    tags.push(tag(["k", &target.kind.to_string()]));
    tags.extend(extra);
    finish(kinds::REACTION, content.to_owned(), tags, author, ms, expiration_for(kinds::REACTION, ms, timer_secs))
}

/// An edit keeps the original's expiration (Armada `a89f49a0`).
pub fn edit(b: &Binding, author: &str, target_id: &str, content: String, extra: Vec<Vec<String>>, ms: u64, original_expiration: Option<u64>) -> Rumor {
    let mut tags = b.tags();
    tags.push(tag(["e", target_id]));
    tags.extend(extra);
    finish(kinds::EDIT, content, tags, author, ms, original_expiration)
}

pub fn delete(b: &Binding, author: &str, target_id: &str, target_kind: u16, ms: u64) -> Rumor {
    let mut tags = b.tags();
    tags.push(tag(["e", target_id]));
    tags.push(tag(["k", &target_kind.to_string()]));
    finish(kinds::DELETE, String::new(), tags, author, ms, None)
}

pub fn typing(b: &Binding, author: &str, ms: u64) -> Rumor {
    finish(kinds::TYPING, String::new(), b.tags(), author, ms, None)
}

// ── Reading ─────────────────────────────────────────────────────────────────

/// The `e` target of a reaction, edit, or delete.
pub fn e_target(r: &Rumor) -> Option<&str> {
    r.tag_value("e")
}

/// The thread root (`E`) of a kind-1111 reply.
pub fn thread_root(r: &Rumor) -> Option<&str> {
    (r.kind == kinds::COMMENT).then(|| r.tag_value("E")).flatten()
}

/// The immediate parent (`e`) of a kind-1111 reply.
pub fn thread_parent(r: &Rumor) -> Option<&str> {
    (r.kind == kinds::COMMENT).then(|| r.tag_value("e")).flatten()
}

/// The NIP-C7 inline-reply parent of a kind-9 message: its first `q` whose event
/// the content does not itself embed (embedded `q`s are quotes, not parents).
pub fn inline_reply_parent(r: &Rumor) -> Option<&str> {
    if r.kind != kinds::MESSAGE {
        return None;
    }
    let mut embedded: Option<Vec<String>> = None;
    for t in r.tags_named("q") {
        let Some(id) = t.get(1).filter(|v| crate::is_hex64(v)) else { continue };
        let embedded = embedded.get_or_insert_with(|| referenced_event_ids(&r.content));
        if !embedded.iter().any(|e| e == id) {
            return Some(id);
        }
    }
    None
}

fn referenced_event_ids(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    for word in content.split(|c: char| !c.is_ascii_alphanumeric()) {
        if word.starts_with("note1") {
            if let Ok(id) = EventId::from_bech32(word) {
                out.push(id.to_hex());
            }
        } else if word.starts_with("nevent1")
            && let Ok(ev) = Nip19Event::from_bech32(word)
        {
            out.push(ev.event_id.to_hex());
        }
    }
    out
}

/// Whether a rumor kind is something a timeline shows as a row.
pub fn is_visible_kind(kind: u16) -> bool {
    matches!(kind, kinds::MESSAGE | kinds::COMMENT | kinds::POLL)
}

/// Whether a chat rumor has expired by its own signed NIP-40 tag (CORD-08 §3).
pub fn is_expired(r: &Rumor, now_secs: u64) -> bool {
    r.tag_value("expiration").and_then(crate::parse_tag_decimal).is_some_and(|exp| exp <= now_secs)
}
