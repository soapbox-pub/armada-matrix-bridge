//! The Control Plane fold — CORD-04. Replays opened editions into current state:
//! the owner-rooted Roster first (a delegation fixpoint), then every gated entity
//! (metadata, channels, banlist, invite registries, pins, signals) judged against
//! it. A port of Armada's `control.ts`; the comments there carry the reasoning.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::Value;

use crate::derive::{banlist_locator, grant_locator, invite_links_locator, signal_locator};
use crate::edition::{Citation, Edition, Head, bootstrap_head, build_edition_rumor, fold_chain};
use crate::kinds::{self, SIGNAL_PAUSE};
use crate::roles::{MAX_ROLES_PER_COMMUNITY, MemberGrant, NAME_MAX_BYTES, Role, Roster, perm};
use crate::rumor::Rumor;
use crate::stream::Opened;
use crate::{Bytes32, hex32, is_hex64, to_hex};

pub const DESCRIPTION_MAX_BYTES: usize = 10_000;
pub const MAX_COMMUNITY_RELAYS: usize = 5;
const MAX_PAUSE_UNTIL_SECS: u64 = 30 * 24 * 60 * 60;
/// Implemented signal ids and the permission each needs; others stay invisible.
const SIGNAL_GATES: &[(&str, u64)] = &[(SIGNAL_PAUSE, perm::MANAGE_CHANNELS)];

/// An encrypted-blob pointer (icon / banner), CORD-02 §6.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ImagePointer {
    pub url: String,
    pub key: String,
    pub nonce: String,
    pub hash: String,
}

impl ImagePointer {
    fn from_value(v: Option<&Value>) -> Option<Self> {
        serde_json::from_value(v?.clone()).ok()
    }
}

/// Community metadata (vsk 0). `raw` keeps every field for round-tripping.
#[derive(Clone, Debug)]
pub struct CommunityMetadata {
    pub name: String,
    pub description: Option<String>,
    pub relays: Vec<String>,
    pub icon: Option<ImagePointer>,
    pub banner: Option<ImagePointer>,
    /// The disappearing-messages timer in seconds (CORD-08); `None` = off.
    pub message_expiration: Option<u64>,
    pub raw: Value,
}

/// Channel metadata (vsk 2), folded.
#[derive(Clone, Debug)]
pub struct FoldedChannel {
    pub channel_id_hex: String,
    pub name: String,
    pub private: bool,
    pub deleted: bool,
    /// `"forum"` channels open thread-first (CORD-03 §2 `view`).
    pub forum: bool,
    /// Armada sidebar extensions (CORD.md).
    pub category: Option<String>,
    pub position: Option<f64>,
    pub raw: Value,
}

#[derive(Clone, Debug)]
pub struct FoldedSignal {
    pub content: Value,
    pub author: String,
    pub at: u64,
}

/// The Control Plane replayed into current state.
#[derive(Clone, Debug, Default)]
pub struct FoldedControl {
    pub roster: Roster,
    pub owner: String,
    pub metadata: Option<CommunityMetadata>,
    pub channels: BTreeMap<String, FoldedChannel>,
    pub banned: HashSet<String>,
    /// npub → `created_at` (seconds) of the newest authorized banlist edition naming them.
    pub banned_at: HashMap<String, u64>,
    pub live_invite_links: HashSet<String>,
    pub registries_by_creator: HashMap<String, Vec<String>>,
    /// Pin Lists by `pins_locator` eid: raw head content (decoding needs a channel key).
    pub pin_lists: HashMap<String, (String, String)>,
    pub signals: HashMap<String, FoldedSignal>,
    pub heads: HashMap<String, Head>,
    pub head_editions: HashMap<String, Edition>,
    /// Floored entities the served set couldn't account for (data availability only).
    pub incomplete: Vec<String>,
}

impl FoldedControl {
    /// Whether the CORD-04 §5 sync floor is met for an authority action outside
    /// the roster fold (deletes, kicks, rekeys). Completeness, not authorization.
    pub fn citation_satisfied(&self, community_id: &Bytes32, actor: &str, citation: Option<&Citation>) -> bool {
        citation_satisfied(&self.heads, &self.owner, community_id, actor, citation)
    }

    pub fn is_public(&self) -> bool {
        self.registries_by_creator.values().any(|s| !s.is_empty())
    }

    /// The active pause (CORD-04 §8) at `now` (unix seconds).
    pub fn active_pause(&self, now: u64) -> Option<(u64, Option<u64>)> {
        let head = self.signals.get(SIGNAL_PAUSE)?;
        if head.content.get("paused") != Some(&Value::Bool(true)) {
            return None;
        }
        let until = head.content.get("until").and_then(Value::as_u64);
        if until.is_some_and(|u| now >= u) {
            return None;
        }
        Some((head.at, until))
    }
}

pub fn citation_satisfied(heads: &HashMap<String, Head>, owner: &str, community_id: &Bytes32, actor: &str, citation: Option<&Citation>) -> bool {
    if actor == owner {
        return true;
    }
    let Some(c) = citation else { return false };
    let Some(actor_bytes) = hex32(actor) else { return false };
    let eid = grant_locator(community_id, &actor_bytes);
    if c.entity_id != eid {
        return false;
    }
    let Some(head) = heads.get(&to_hex(&eid)) else { return false };
    if head.version > c.version {
        return true;
    }
    head.version == c.version && head.hash == c.edition_hash
}

fn utf8_len_ok(s: &str, max: usize) -> bool {
    s.len() <= max
}

/// Dedupe and truncate a relay set to the recommended cap.
pub fn cap_relays(relays: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for r in relays {
        if out.len() >= MAX_COMMUNITY_RELAYS {
            break;
        }
        if !r.is_empty() && !out.contains(&r) {
            out.push(r);
        }
    }
    out
}

/// Order one entity's editions into head candidates: the chain-verified head
/// first, then the rest version-descending (see Armada's `headCandidates`).
fn head_candidates<'a>(editions: &[&'a Edition], floor: Option<&Head>, snapshot: bool, gapped_out: &mut bool) -> Vec<&'a Edition> {
    let mut ordered: Vec<&Edition> = Vec::new();
    let mut seen: HashSet<Bytes32> = HashSet::new();
    let mut gapped = false;
    if snapshot {
        match bootstrap_head(editions, floor.map_or(0, |f| f.version)) {
            Some(idx) => {
                ordered.push(editions[idx]);
                seen.insert(editions[idx].rumor_id);
            }
            None if floor.is_some() => gapped = true,
            None => {}
        }
    } else {
        let r = fold_chain(editions, floor.map_or(0, |f| f.version), floor.map(|f| &f.hash));
        gapped = floor.is_some() && (r.gap || r.head.is_none());
        if let (Some(h), false) = (r.head, gapped) {
            ordered.push(editions[h]);
            seen.insert(editions[h].rumor_id);
        }
    }
    *gapped_out = gapped;
    let mut rest: Vec<&Edition> = editions
        .iter()
        .copied()
        .filter(|e| {
            if !seen.insert(e.rumor_id) {
                return false;
            }
            if let Some(f) = floor {
                if e.version < f.version {
                    return false;
                }
                if gapped && (e.version > f.version || e.self_hash != f.hash) {
                    return false;
                }
            }
            true
        })
        .collect();
    rest.sort_by(|a, b| b.version.cmp(&a.version).then(a.rumor_id.cmp(&b.rumor_id)));
    ordered.extend(rest);
    ordered
}

fn settle(heads: &mut HashMap<String, Head>, head_editions: &mut HashMap<String, Edition>, e: &Edition) {
    heads.insert(e.eid_hex(), Head { version: e.version, hash: e.self_hash });
    head_editions.insert(e.eid_hex(), e.clone());
}

/// Pick the first candidate passing `gate`; equal-version siblings are settled by
/// authority (`rank_of`) rather than the grindable rumor id.
fn pick_head<'a>(
    candidates: &[&'a Edition],
    heads: &mut HashMap<String, Head>,
    head_editions: &mut HashMap<String, Edition>,
    mut gate: impl FnMut(&Edition) -> bool,
    rank_of: impl Fn(&str) -> i64,
) -> Option<&'a Edition> {
    let mut head: Option<&Edition> = None;
    for &p in candidates {
        if !gate(p) {
            continue;
        }
        match head {
            None => head = Some(p),
            Some(h) => {
                if p.version != h.version {
                    break;
                }
                if rank_of(&p.author) < rank_of(&h.author) {
                    head = Some(p);
                }
            }
        }
    }
    let head = head?;
    settle(heads, head_editions, head);
    Some(head)
}

/// Group candidates by version, ascending.
fn version_groups<T, F: Fn(&T) -> u64>(items: &[T], version: F) -> Vec<Vec<&T>> {
    let mut sorted: Vec<&T> = items.iter().collect();
    sorted.sort_by_key(|t| version(t));
    let mut groups: Vec<Vec<&T>> = Vec::new();
    for t in sorted {
        match groups.last_mut() {
            Some(g) if version(g[0]) == version(t) => g.push(t),
            _ => groups.push(vec![t]),
        }
    }
    groups
}

struct RoleCand<'a> {
    role: Role,
    e: &'a Edition,
}

struct GrantCand<'a> {
    grant: MemberGrant,
    e: &'a Edition,
}

fn rank(roster: &Roster, owner: &str, author: &str) -> i64 {
    if author == owner { -1 } else { roster.highest_position(author).map_or(i64::MAX, i64::from) }
}

/// The delegation fixpoint (CORD-04 §2): from the owner outward, admit role and
/// grant entities whose signer is authorized, until stable.
fn authorize_delegation(
    role_cands: &BTreeMap<String, Vec<RoleCand>>,
    grant_cands: &BTreeMap<String, Vec<GrantCand>>,
    community_id: &Bytes32,
    owner: &str,
    heads: &mut HashMap<String, Head>,
    head_editions: &mut HashMap<String, Edition>,
) -> Roster {
    let mut roster = Roster::default();
    let mut settled_roles: HashSet<&str> = HashSet::new();
    let mut settled_grants: HashSet<&str> = HashSet::new();
    let mut grant_eid_of_member: HashMap<&str, &str> = HashMap::new();
    for (eid, cands) in grant_cands {
        if let Some(c) = cands.first() {
            grant_eid_of_member.insert(c.grant.member.as_str(), eid.as_str());
        }
    }

    let mut roles_frozen = false;
    let mut ranks_frozen = false;
    let mut changed = true;

    while changed {
        changed = false;

        let rank_pending = |author: &str, self_eid: Option<&str>, settled_grants: &HashSet<&str>| -> bool {
            if author == owner {
                return false;
            }
            match grant_eid_of_member.get(author) {
                Some(aeid) => Some(*aeid) != self_eid && !settled_grants.contains(aeid),
                None => false,
            }
        };

        for (eid, cands) in role_cands {
            if settled_roles.contains(eid.as_str()) {
                continue;
            }
            if !ranks_frozen && cands.iter().any(|c| rank_pending(&c.e.author, None, &settled_grants)) {
                continue;
            }
            let mut admissible: HashSet<Bytes32> = HashSet::new();
            let mut standing: Option<u32> = None;
            for group in version_groups(cands, |c| c.e.version) {
                let mut group = group;
                group.sort_by(|a, b| rank(&roster, owner, &a.e.author).cmp(&rank(&roster, owner, &b.e.author)).then(a.e.rumor_id.cmp(&b.e.rumor_id)));
                for c in group {
                    let author = c.e.author.as_str();
                    let mint_ok = author == owner || roster.can_act_on_position(author, owner, c.role.position, perm::MANAGE_ROLES);
                    let replace_ok = author == owner || standing.is_none_or(|s| roster.outranks(author, owner, s));
                    if !mint_ok || !replace_ok || !citation_satisfied(heads, owner, community_id, author, c.e.authority.as_ref()) {
                        continue;
                    }
                    admissible.insert(c.e.rumor_id);
                    standing = Some(c.role.position);
                    break;
                }
            }
            let Some(pick) = cands.iter().find(|c| admissible.contains(&c.e.rumor_id)) else { continue };
            roster.roles.push(pick.role.clone());
            settled_roles.insert(eid.as_str());
            settle(heads, head_editions, pick.e);
            changed = true;
        }

        for (eid, cands) in grant_cands {
            if settled_grants.contains(eid.as_str()) {
                continue;
            }
            let role_pending = |rid: &str| role_cands.contains_key(rid) && !settled_roles.contains(rid);
            if !roles_frozen && cands.iter().any(|c| c.grant.role_ids.iter().any(|r| role_pending(r))) {
                continue;
            }
            if !ranks_frozen && cands.iter().any(|c| rank_pending(&c.e.author, Some(eid.as_str()), &settled_grants)) {
                continue;
            }
            let mut admissible: HashSet<Bytes32> = HashSet::new();
            let mut standing: Option<u32> = None;
            for group in version_groups(cands, |c| c.e.version) {
                let mut group = group;
                group.sort_by(|a, b| rank(&roster, owner, &a.e.author).cmp(&rank(&roster, owner, &b.e.author)).then(a.e.rumor_id.cmp(&b.e.rumor_id)));
                for c in group {
                    let author = c.e.author.as_str();
                    let positions: Vec<u32> = c.grant.role_ids.iter().filter_map(|rid| roster.role(rid).map(|r| r.position)).collect();
                    let all_known = positions.len() == c.grant.role_ids.len();
                    let ok = author == owner
                        || (all_known
                            && roster.has(author, perm::MANAGE_ROLES)
                            && positions.iter().all(|p| roster.outranks(author, owner, *p))
                            && standing.is_none_or(|s| roster.outranks(author, owner, s)));
                    if !ok || !citation_satisfied(heads, owner, community_id, author, c.e.authority.as_ref()) {
                        continue;
                    }
                    admissible.insert(c.e.rumor_id);
                    standing = positions.iter().copied().min();
                    break;
                }
            }
            let Some(pick) = cands.iter().find(|c| admissible.contains(&c.e.rumor_id)) else { continue };
            roster.grants.push(pick.grant.clone());
            settled_grants.insert(eid.as_str());
            settle(heads, head_editions, pick.e);
            changed = true;
        }

        if !changed && !roles_frozen {
            roles_frozen = true;
            changed = true;
        } else if !changed && !ranks_frozen {
            ranks_frozen = true;
            changed = true;
        }
    }

    if roster.roles.len() > MAX_ROLES_PER_COMMUNITY {
        roster.roles.sort_by(|a, b| a.role_id.cmp(&b.role_id));
        roster.roles.truncate(MAX_ROLES_PER_COMMUNITY);
    }
    roster
}

fn parse_metadata(content: &str) -> Option<Value> {
    let v: Value = serde_json::from_str(content).ok()?;
    let name = v.get("name")?.as_str()?;
    if !utf8_len_ok(name, NAME_MAX_BYTES) {
        return None;
    }
    match v.get("description") {
        None | Some(Value::Null) => {}
        Some(Value::String(d)) if utf8_len_ok(d, DESCRIPTION_MAX_BYTES) => {}
        _ => return None,
    }
    Some(v)
}

fn channel_meta_ok(content: &str) -> bool {
    serde_json::from_str::<Value>(content)
        .ok()
        .and_then(|v| v.get("name").and_then(Value::as_str).map(|n| !n.is_empty() && utf8_len_ok(n, NAME_MAX_BYTES)))
        .unwrap_or(false)
}

fn folded_channel(eid: &str, raw: Value, ever_deleted: bool) -> FoldedChannel {
    let custom = raw.get("custom");
    let category = custom
        .and_then(|c| c.get("armada.category"))
        .and_then(|c| c.get("name"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|n| !n.is_empty() && n.len() <= NAME_MAX_BYTES)
        .map(str::to_owned);
    let position = custom.and_then(|c| c.get("armada.order")).and_then(|o| o.get("position")).and_then(Value::as_f64).filter(|p| p.is_finite());
    FoldedChannel {
        channel_id_hex: eid.to_owned(),
        name: raw.get("name").and_then(Value::as_str).unwrap_or_default().to_owned(),
        private: raw.get("private") == Some(&Value::Bool(true)),
        deleted: raw.get("deleted") == Some(&Value::Bool(true)) || ever_deleted,
        forum: raw.get("view").and_then(Value::as_str) == Some("forum"),
        category,
        position,
        raw,
    }
}

fn parse_hex_list(content: &str) -> Option<Vec<String>> {
    let v: Value = serde_json::from_str(content).ok()?;
    let list = v.as_array()?;
    Some(list.iter().filter_map(Value::as_str).filter(|s| is_hex64(s)).map(str::to_lowercase).collect())
}

fn validate_signal(signal_id: &str, content: &str, created_at: u64) -> bool {
    let Ok(v) = serde_json::from_str::<Value>(content) else { return false };
    if !v.is_object() {
        return false;
    }
    if signal_id == SIGNAL_PAUSE {
        if !v.get("paused").is_some_and(Value::is_boolean) {
            return false;
        }
        if let Some(until) = v.get("until") {
            match until.as_u64() {
                Some(u) if u > 0 && u <= created_at + MAX_PAUSE_UNTIL_SECS => {}
                _ => return false,
            }
        }
        return true;
    }
    false
}

/// Replay opened control editions into current state. `prior_heads` floors a
/// tracking client's fold; `snapshot_ids` (rumor ids that arrived under the
/// current post-Refounding epoch) switch those entities to bootstrap folding.
pub fn fold_control(
    editions: &[Edition],
    community_id: &Bytes32,
    owner: &str,
    prior_heads: Option<&HashMap<String, Head>>,
    snapshot_ids: Option<&HashSet<Bytes32>>,
) -> FoldedControl {
    let refs: Vec<&Edition> = editions.iter().collect();
    let first = fold_once(&refs, community_id, owner, prior_heads, snapshot_ids);
    // The owner is supreme: never bannable.
    let banned: HashSet<String> = first.banned.iter().filter(|pk| pk.as_str() != owner).cloned().collect();
    if !banned.is_empty() && editions.iter().any(|e| banned.contains(&e.author)) {
        let kept: Vec<&Edition> = editions.iter().filter(|e| !banned.contains(&e.author)).collect();
        let mut second = fold_once(&kept, community_id, owner, prior_heads, snapshot_ids);
        second.banned = banned;
        second.banned_at = first.banned_at;
        second.incomplete = first.incomplete;
        return second;
    }
    FoldedControl { banned, ..first }
}

fn fold_once(
    editions: &[&Edition],
    community_id: &Bytes32,
    owner: &str,
    prior_heads: Option<&HashMap<String, Head>>,
    snapshot_ids: Option<&HashSet<Bytes32>>,
) -> FoldedControl {
    let cid_hex = to_hex(community_id);
    let mut by_vsk: HashMap<&str, BTreeMap<String, Vec<&Edition>>> = HashMap::new();
    for &e in editions {
        by_vsk.entry(e.vsk.as_str()).or_default().entry(e.eid_hex()).or_default().push(e);
    }
    let mut heads: HashMap<String, Head> = HashMap::new();
    let mut head_editions: HashMap<String, Edition> = HashMap::new();
    let mut gap_held: HashSet<String> = HashSet::new();

    let candidates_of = |vsk: &str, gap_held: &mut HashSet<String>| -> BTreeMap<String, Vec<&Edition>> {
        let mut out = BTreeMap::new();
        if let Some(m) = by_vsk.get(vsk) {
            for (eid, list) in m {
                let snapshot = snapshot_ids.is_some_and(|ids| list.iter().any(|e| ids.contains(&e.rumor_id)));
                let mut gapped = false;
                let cands = head_candidates(list, prior_heads.and_then(|h| h.get(eid)), snapshot, &mut gapped);
                if gapped {
                    gap_held.insert(eid.clone());
                }
                out.insert(eid.clone(), cands);
            }
        }
        out
    };

    // Roster.
    let mut role_cands: BTreeMap<String, Vec<RoleCand>> = BTreeMap::new();
    for (eid, cands) in candidates_of(kinds::VSK_ROLE, &mut gap_held) {
        let parsed: Vec<RoleCand> = cands
            .into_iter()
            .filter_map(|e| Role::from_json(&e.content).filter(|r| r.role_id == eid).map(|role| RoleCand { role, e }))
            .collect();
        if !parsed.is_empty() {
            role_cands.insert(eid, parsed);
        }
    }
    let mut grant_cands: BTreeMap<String, Vec<GrantCand>> = BTreeMap::new();
    for (eid, cands) in candidates_of(kinds::VSK_GRANT, &mut gap_held) {
        let parsed: Vec<GrantCand> = cands
            .into_iter()
            .filter_map(|e| {
                let grant = MemberGrant::from_json(&e.content)?;
                let member = hex32(&grant.member)?;
                (to_hex(&grant_locator(community_id, &member)) == eid).then_some(GrantCand { grant, e })
            })
            .collect();
        if !parsed.is_empty() {
            grant_cands.insert(eid, parsed);
        }
    }
    let roster = authorize_delegation(&role_cands, &grant_cands, community_id, owner, &mut heads, &mut head_editions);
    let rank_of = |author: &str| rank(&roster, owner, author);
    // Citations name Grant heads, which the roster pass has now settled for good.
    let grant_heads = heads.clone();
    let cited = |p: &Edition| citation_satisfied(&grant_heads, owner, community_id, &p.author, p.authority.as_ref());

    // Metadata.
    let mut metadata = None;
    {
        let cands = candidates_of(kinds::VSK_METADATA, &mut gap_held).remove(&cid_hex).unwrap_or_default();
        let head = pick_head(
            &cands,
            &mut heads,
            &mut head_editions,
            |p| {
                roster.is_authorized(&p.author, owner, perm::MANAGE_METADATA)
                    && cited(p)
                    && parse_metadata(&p.content).is_some()
            },
            rank_of,
        );
        if let Some(head) = head {
            let raw = parse_metadata(&head.content).expect("gated");
            let relays = raw
                .get("relays")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect::<Vec<_>>())
                .unwrap_or_default();
            metadata = Some(CommunityMetadata {
                name: raw["name"].as_str().unwrap_or_default().to_owned(),
                description: raw.get("description").and_then(Value::as_str).map(str::to_owned),
                relays: cap_relays(relays),
                icon: ImagePointer::from_value(raw.get("icon")),
                banner: ImagePointer::from_value(raw.get("banner")),
                message_expiration: raw.get("message_expiration").and_then(Value::as_u64).filter(|s| *s > 0),
                raw,
            });
        }
    }
    // Channels, gated by MANAGE_CHANNELS. Deletion is terminal.
    let mut channels = BTreeMap::new();
    for (eid, cands) in candidates_of(kinds::VSK_CHANNEL, &mut gap_held) {
        let gate = |p: &Edition| {
            roster.is_authorized(&p.author, owner, perm::MANAGE_CHANNELS)
                && cited(p)
                && channel_meta_ok(&p.content)
        };
        let Some(head) = pick_head(&cands, &mut heads, &mut head_editions, gate, rank_of) else { continue };
        let raw: Value = serde_json::from_str(&head.content).unwrap_or(Value::Null);
        let ever_deleted = cands.iter().any(|p| {
            gate(p) && serde_json::from_str::<Value>(&p.content).ok().and_then(|v| v.get("deleted").cloned()) == Some(Value::Bool(true))
        });
        channels.insert(eid.clone(), folded_channel(&eid, raw, ever_deleted));
    }

    // Banlist (vsk 4): BAN and strict outrank per named member.
    let mut banned = HashSet::new();
    let mut banned_at: HashMap<String, u64> = HashMap::new();
    {
        let eid = to_hex(&banlist_locator(community_id));
        let cands = candidates_of(kinds::VSK_BANLIST, &mut gap_held).remove(&eid).unwrap_or_default();
        let entitled = |author: &str, pk: &str| roster.can_act_on_member(author, owner, pk, perm::BAN);
        let well_formed = |p: &Edition| {
            roster.is_authorized(&p.author, owner, perm::BAN)
                && cited(p)
                && parse_hex_list(&p.content).is_some()
        };
        let mut standing_at: HashMap<Bytes32, HashSet<String>> = HashMap::new();
        let mut admissible: HashSet<Bytes32> = HashSet::new();
        let mut standing: HashSet<String> = HashSet::new();
        for group in version_groups(&cands, |e| e.version) {
            let mut group = group;
            group.sort_by(|a, b| rank_of(&a.author).cmp(&rank_of(&b.author)).then(a.rumor_id.cmp(&b.rumor_id)));
            for p in group {
                if !well_formed(p) || standing.contains(&p.author) {
                    continue;
                }
                let mut named: HashSet<String> = parse_hex_list(&p.content).unwrap().into_iter().filter(|pk| entitled(&p.author, pk)).collect();
                for pk in &standing {
                    if !entitled(&p.author, pk) {
                        named.insert(pk.clone());
                    }
                }
                standing = named.clone();
                standing_at.insert(p.rumor_id, named);
                admissible.insert(p.rumor_id);
                break;
            }
        }
        if let Some(head) = pick_head(&cands, &mut heads, &mut head_editions, |p| admissible.contains(&p.rumor_id), rank_of) {
            banned.extend(standing_at.get(&head.rumor_id).cloned().unwrap_or_default());
        }
        for p in &cands {
            if !admissible.contains(&p.rumor_id) {
                continue;
            }
            for pk in parse_hex_list(&p.content).unwrap_or_default() {
                if !entitled(&p.author, &pk) {
                    continue;
                }
                let e = banned_at.entry(pk).or_insert(p.created_at);
                *e = (*e).max(p.created_at);
            }
        }
    }

    // Invite registries (vsk 8): each creator's own list, while they hold CREATE_INVITE.
    let mut live_invite_links = HashSet::new();
    let mut registries_by_creator = HashMap::new();
    for (eid, cands) in candidates_of(kinds::VSK_INVITE_REGISTRY, &mut gap_held) {
        let gate = |p: &Edition| {
            hex32(&p.author).is_some_and(|a| to_hex(&invite_links_locator(community_id, &a)) == eid)
                && roster.is_authorized(&p.author, owner, perm::CREATE_INVITE)
                && cited(p)
                && serde_json::from_str::<Value>(&p.content).is_ok_and(|v| v.is_array())
        };
        let Some(head) = pick_head(&cands, &mut heads, &mut head_editions, gate, rank_of) else { continue };
        let list = parse_hex_list(&head.content).unwrap_or_default();
        live_invite_links.extend(list.iter().cloned());
        registries_by_creator.insert(head.author.clone(), list);
    }

    // Pin Lists (vsk 11), gated by PIN_MESSAGES; content carried verbatim.
    let mut pin_lists = HashMap::new();
    for (eid, cands) in candidates_of(kinds::VSK_PINS, &mut gap_held) {
        let gate = |p: &Edition| {
            roster.is_authorized(&p.author, owner, perm::PIN_MESSAGES)
                && cited(p)
        };
        if let Some(head) = pick_head(&cands, &mut heads, &mut head_editions, gate, rank_of) {
            pin_lists.insert(eid, (head.content.clone(), head.author.clone()));
        }
    }

    // Community Signals (vsk 12): only implemented signal ids have a coordinate.
    let mut signals = HashMap::new();
    let signal_cands = candidates_of(kinds::VSK_SIGNALS, &mut gap_held);
    for &(signal_id, gate_bits) in SIGNAL_GATES {
        let cands = signal_cands.get(&to_hex(&signal_locator(community_id, signal_id))).cloned().unwrap_or_default();
        let gate = |p: &Edition| {
            roster.is_authorized(&p.author, owner, gate_bits)
                && cited(p)
                && validate_signal(signal_id, &p.content, p.created_at)
        };
        if let Some(head) = pick_head(&cands, &mut heads, &mut head_editions, gate, rank_of) {
            signals.insert(
                signal_id.to_owned(),
                FoldedSignal { content: serde_json::from_str(&head.content).unwrap_or(Value::Null), author: head.author.clone(), at: head.created_at },
            );
        }
    }

    let served: HashSet<String> = by_vsk.values().flat_map(|m| m.keys().cloned()).collect();
    let mut incomplete: Vec<String> = gap_held.iter().cloned().collect();
    if let Some(prior) = prior_heads {
        for eid in prior.keys() {
            if !served.contains(eid) && !gap_held.contains(eid) {
                incomplete.push(eid.clone());
            }
        }
    }
    incomplete.sort();

    FoldedControl {
        roster,
        owner: owner.to_owned(),
        metadata,
        channels,
        banned,
        banned_at,
        live_invite_links,
        registries_by_creator,
        pin_lists,
        signals,
        heads,
        head_editions,
        incomplete,
    }
}

// ── Builders ────────────────────────────────────────────────────────────────

pub fn build_metadata_edition(community_id: &Bytes32, metadata: &Value, actor: &str, version: u64, prev: Option<&Bytes32>, authority: Option<&Citation>) -> Rumor {
    build_edition_rumor(kinds::VSK_METADATA, community_id, version, prev, metadata.to_string(), actor, authority)
}

pub fn build_channel_edition(channel_id: &Bytes32, metadata: &Value, actor: &str, version: u64, prev: Option<&Bytes32>, authority: Option<&Citation>) -> Rumor {
    build_edition_rumor(kinds::VSK_CHANNEL, channel_id, version, prev, metadata.to_string(), actor, authority)
}

// ── Dissolution (CORD-02 §9) ────────────────────────────────────────────────

/// Whether an opened dissolved-address event is the owner's tombstone FOR THIS
/// community. The `eid` binding is mandatory; an all-zero `eid` is refused.
pub fn is_dissolved_opened(opened: &Opened, owner: &str, community_id: &Bytes32) -> bool {
    opened.author() == owner
        && opened.seal_kind() == kinds::SEAL_PLAINTEXT
        && opened.rumor.kind == kinds::CONTROL
        && opened.rumor.tag_value("vsk") == Some(kinds::VSK_DISSOLVED)
        && opened.rumor.tag_value("eid") == Some(to_hex(community_id).as_str())
}
