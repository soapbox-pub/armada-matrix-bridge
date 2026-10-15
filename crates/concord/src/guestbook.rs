//! The Guestbook Plane — CORD-02 §5: self-signed Joins and Leaves, authorized
//! Kicks, and refounder snapshots, coalesced flat to one state per npub.

use std::collections::{HashMap, HashSet};

use crate::edition::Citation;
use crate::kinds;
use crate::rumor::{Rumor, tag};
use crate::stream::Opened;

/// Entries dated further than this ahead of the local clock are dropped.
pub const MAX_FUTURE_MS: u64 = 60 * 60 * 1000;

pub fn join(author: &str, ms: u64, invite: Option<(&str, &str)>) -> Rumor {
    let tags = invite.map(|(creator, label)| vec![tag(["invite", creator, label])]).unwrap_or_default();
    Rumor::new(kinds::JOIN_LEAVE, "join", tags, author, Some(ms), None)
}

pub fn leave(author: &str, ms: u64) -> Rumor {
    Rumor::new(kinds::JOIN_LEAVE, "leave", vec![], author, Some(ms), None)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberState {
    Join,
    Leave,
    Kick,
}

#[derive(Clone, Debug)]
pub struct Coalesced {
    pub state: MemberState,
    pub ms: u64,
    pub rumor_id: String,
    pub from_snapshot: bool,
}

/// Coalesce opened guestbook events: latest ms per npub wins, ties to the lower
/// rumor id, firsthand beats a snapshot at the same instant. Kicks need
/// `can_kick(actor, target, citation)`; snapshots count only from `snapshot_authorities`.
pub fn coalesce(
    opened: &[Opened],
    now_ms: u64,
    banned: &HashSet<String>,
    snapshot_authorities: &HashSet<String>,
    can_kick: impl Fn(&str, &str, Option<&Citation>) -> bool,
) -> HashMap<String, Coalesced> {
    let mut by_member: HashMap<String, Coalesced> = HashMap::new();
    let mut apply = |pk: String, c: Coalesced| {
        let replace = match by_member.get(&pk) {
            None => true,
            Some(prev) if c.ms != prev.ms => c.ms > prev.ms,
            Some(prev) if prev.from_snapshot != c.from_snapshot => prev.from_snapshot,
            Some(prev) => c.rumor_id < prev.rumor_id,
        };
        if replace {
            by_member.insert(pk, c);
        }
    };
    for ev in opened {
        if ev.ms > now_ms + MAX_FUTURE_MS || ev.seal_kind() != kinds::SEAL_ENCRYPTED || banned.contains(ev.author()) {
            continue;
        }
        let r = &ev.rumor;
        match r.kind {
            kinds::JOIN_LEAVE => {
                let state = match r.content.as_str() {
                    "join" => MemberState::Join,
                    "leave" => MemberState::Leave,
                    _ => continue,
                };
                apply(r.pubkey.clone(), Coalesced { state, ms: ev.ms, rumor_id: r.id.clone(), from_snapshot: false });
            }
            kinds::KICK => {
                let Some(target) = r.tag_value("p") else { continue };
                if !can_kick(&r.pubkey, target, Citation::from_tags(&r.tags).as_ref()) {
                    continue;
                }
                apply(target.to_owned(), Coalesced { state: MemberState::Kick, ms: ev.ms, rumor_id: r.id.clone(), from_snapshot: false });
            }
            kinds::SNAPSHOT => {
                if !snapshot_authorities.contains(&r.pubkey) {
                    continue;
                }
                let Ok(members) = serde_json::from_str::<Vec<serde_json::Value>>(&r.content) else { continue };
                for pk in members.iter().filter_map(|v| v.as_str()).filter(|s| crate::is_hex64(s)) {
                    apply(pk.to_lowercase(), Coalesced { state: MemberState::Join, ms: ev.ms, rumor_id: r.id.clone(), from_snapshot: true });
                }
            }
            _ => {}
        }
    }
    by_member
}
