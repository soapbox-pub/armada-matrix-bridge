//! One Armada community: its keys, its folded Control Plane, its subscriptions,
//! and its Matrix portals. Owned by a single actor task; everything that touches
//! the community goes through its mailbox.

use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use concord::community::{ChannelView, Membership, RekeyOutcome};
use concord::control::{FoldedControl, fold_control};
use concord::direct_invite::DirectInvite;
use concord::edition::{Edition, parse_edition};
use concord::kinds::{self, Plane};
use concord::rumor::Rumor;
use concord::stream::{Opened, StreamKey, WrapOptions, open_plane_wrap, seal_and_wrap};
use concord::Bytes32;
use nostr::prelude::{Event, Filter, Keys, Kind, PublicKey, Timestamp};
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};

use super::{Bridge, now_ms};
use crate::db::{CommunityRow, PortalRow};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PlaneSub {
    Control,
    Guestbook,
    Rekey,
    Chat,
    /// Ephemeral chat traffic (typing), live only.
    Live,
    Dissolved,
}

impl PlaneSub {
    pub fn name(self) -> &'static str {
        match self {
            PlaneSub::Control => "control",
            PlaneSub::Guestbook => "guestbook",
            PlaneSub::Rekey => "rekey",
            PlaneSub::Chat => "chat",
            PlaneSub::Live => "live",
            PlaneSub::Dissolved => "dissolved",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "control" => PlaneSub::Control,
            "guestbook" => PlaneSub::Guestbook,
            "rekey" => PlaneSub::Rekey,
            "chat" => PlaneSub::Chat,
            "live" => PlaneSub::Live,
            "dissolved" => PlaneSub::Dissolved,
            _ => return None,
        })
    }
}

pub enum Command {
    Status,
    /// Unbridge from the Matrix side.
    Unbridge { by: String },
    /// Invite a Matrix user into the community's space.
    Invite { mxid: String },
}

pub enum Msg {
    Wrap { plane: PlaneSub, relay: String, event: Box<Event> },
    Matrix(Box<Value>),
    Typing { room: String, user: String },
    DirectInvite(Box<DirectInvite>),
    Command(Command, oneshot::Sender<String>),
    Tick,
}

#[derive(Clone)]
pub struct CommunityHandle {
    pub id: String,
    pub tx: mpsc::UnboundedSender<Msg>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Pending,
    Active,
    Revoked,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pending => "pending",
            Status::Active => "active",
            Status::Revoked => "revoked",
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "active" => Status::Active,
            "revoked" => Status::Revoked,
            _ => Status::Pending,
        }
    }
}

/// Where a chat stream address leads.
#[derive(Clone)]
pub struct StreamRoute {
    pub channel_id: String,
    pub epoch: u64,
    pub retired_at: Option<u64>,
    pub key: StreamKey,
}

pub struct Community {
    pub b: Arc<Bridge>,
    pub id: String,
    pub id_bytes: Bytes32,
    pub m: Membership,
    pub status: Status,
    pub approval_code: Option<String>,
    pub requested_by: String,
    pub management_room: Option<String>,
    pub space: Option<String>,
    pub folded: FoldedControl,
    editions: Vec<Edition>,
    edition_ids: HashSet<String>,
    pub channels: Vec<ChannelView>,
    pub routes: HashMap<String, StreamRoute>,
    /// channel id → portal.
    pub portals: HashMap<String, PortalRow>,
    /// channel id → an Armada admin's include/exclude decision.
    pub settings: HashMap<String, bool>,
    pub dissolved: bool,
    pub seen: lru::LruCache<String, ()>,
    pub typing_sent: HashMap<String, std::time::Instant>,
    /// Custom emoji image URL → mxc.
    pub emoji: HashMap<String, String>,
    subscribed: HashMap<PlaneSub, Vec<String>>,
    /// Newest chat wrap seen, for catching up after downtime.
    chat_cursor: Option<u64>,
}

impl Community {
    pub fn name(&self) -> String {
        self.folded.metadata.as_ref().map(|m| m.name.clone()).unwrap_or_else(|| self.m.name.clone())
    }

    /// The fold is the authority for relays; the invite's copy bootstraps.
    pub fn relays(&self) -> Vec<String> {
        let from_fold = self.folded.metadata.as_ref().map(|m| m.relays.clone()).filter(|r| !r.is_empty());
        from_fold.unwrap_or_else(|| self.m.relays.clone()).iter().filter_map(|r| relay_pool::normalize_relay_url(r)).collect()
    }

    pub fn channel(&self, id: &str) -> Option<&ChannelView> {
        self.channels.iter().find(|c| c.id_hex == id)
    }

    pub fn timer_secs(&self) -> Option<u64> {
        self.folded.metadata.as_ref().and_then(|m| m.message_expiration)
    }

    /// Whether a channel's messages cross to Matrix: public channels unless an
    /// Armada admin excluded them; private ones only when one included them.
    pub fn channel_enabled(&self, channel: &ChannelView) -> bool {
        self.settings.get(&channel.id_hex).copied().unwrap_or(!channel.private)
    }

    pub fn portal_for_room(&self, room: &str) -> Option<&PortalRow> {
        self.portals.values().find(|p| p.room_id == room)
    }

    // ── Loading and folding ─────────────────────────────────────────────────

    fn open_control(&self, wrap: &Event) -> Option<Opened> {
        let pk = wrap.pubkey;
        let stream = self.m.control_streams().into_iter().find(|s| s.pk == pk)?;
        open_plane_wrap(wrap, &stream, Plane::Control).ok()
    }

    fn add_edition(&mut self, opened: Opened) -> bool {
        let key = format!("{}:{}", opened.rumor.id, opened.stream_pk);
        if !self.edition_ids.insert(key) {
            return false;
        }
        match parse_edition(opened) {
            Ok(e) => {
                self.editions.push(e);
                true
            }
            Err(_) => false,
        }
    }

    async fn load(&mut self) -> Result<()> {
        for wrap in self.b.db.wraps(&self.id, "control").await? {
            if let Some(opened) = self.open_control(&wrap) {
                self.add_edition(opened);
            }
        }
        self.settings = self.b.db.channel_settings(&self.id).await?.into_iter().collect();
        self.refold();
        self.try_rekeys().await;
        self.check_dissolved().await;
        Ok(())
    }

    /// Re-fold the Control Plane and recompute everything derived from it.
    pub fn refold(&mut self) {
        // Editions that arrived at the current post-Refounding address fold by
        // bootstrap: compaction re-wraps heads whose `prev` is not served there.
        let current_pk = self.m.current_control_stream().pk_hex();
        let snapshot: HashSet<Bytes32> = if self.m.root_epoch > 0 {
            self.editions.iter().filter(|e| e.opened.stream_pk == current_pk).map(|e| e.rumor_id).collect()
        } else {
            HashSet::new()
        };
        self.folded = fold_control(&self.editions, &self.id_bytes, &self.m.owner, None, (!snapshot.is_empty()).then_some(&snapshot));
        self.channels = self.m.channels(Some(&self.folded));
        self.routes.clear();
        for ch in &self.channels {
            for s in &ch.streams {
                self.routes.insert(
                    s.key.pk_hex(),
                    StreamRoute { channel_id: ch.id_hex.clone(), epoch: s.epoch, retired_at: s.retired_at, key: (&s.key).into() },
                );
            }
        }
        if let Some(meta) = &self.folded.metadata
            && !meta.relays.is_empty()
        {
            self.m.relays = meta.relays.clone();
        }
    }

    /// (Re)subscribe every plane; only planes whose address set changed are re-sent.
    pub fn subscribe(&mut self) {
        let relays = self.relays();
        let mut auth: Vec<Keys> = Vec::new();
        let mut want: Vec<(PlaneSub, Vec<String>, Vec<Filter>)> = Vec::new();
        let wrap = Kind::Custom(kinds::WRAP);
        let authors = |pks: &[String]| -> Vec<PublicKey> { pks.iter().filter_map(|p| PublicKey::from_hex(p).ok()).collect() };

        let control: Vec<String> = self.m.control_streams().iter().map(|s| s.pk_hex()).collect();
        auth.extend(self.m.control_streams().into_iter().filter_map(|s| s.sk.map(Keys::new)));
        want.push((PlaneSub::Control, control.clone(), vec![Filter::new().kind(wrap).authors(authors(&control))]));

        let guestbook: Vec<String> = self.m.guestbook_streams().iter().map(|s| s.pk_hex()).collect();
        auth.extend(self.m.guestbook_streams().into_iter().filter_map(|s| s.sk.map(Keys::new)));
        want.push((PlaneSub::Guestbook, guestbook.clone(), vec![Filter::new().kind(wrap).authors(authors(&guestbook))]));

        let mut rekey = vec![self.m.next_base_rekey_address()];
        rekey.extend(self.m.channel_rekey_addresses().into_iter().map(|(g, _, _)| g));
        let rekey_pks: Vec<String> = rekey.iter().map(|g| g.pk_hex()).collect();
        auth.extend(rekey.iter().map(|g| g.keys.clone()));
        want.push((PlaneSub::Rekey, rekey_pks.clone(), vec![Filter::new().kind(wrap).authors(authors(&rekey_pks))]));

        let dissolved = concord::derive::dissolved_group_key(&self.id_bytes);
        auth.push(dissolved.keys.clone());
        want.push((PlaneSub::Dissolved, vec![dissolved.pk_hex()], vec![Filter::new().kind(wrap).author(dissolved.pubkey())]));

        let chat: Vec<String> = self.routes.keys().cloned().collect();
        auth.extend(self.routes.values().filter_map(|r| r.key.sk.clone().map(Keys::new)));
        let since = self.chat_since();
        let mut chat_filter = Filter::new().kind(wrap).authors(authors(&chat));
        if let Some(since) = since {
            chat_filter = chat_filter.since(Timestamp::from(since));
        } else {
            // A fresh community starts live; backfill is explicit.
            chat_filter = chat_filter.since(Timestamp::from(now_ms() / 1000 - 60));
        }
        want.push((PlaneSub::Chat, chat.clone(), vec![chat_filter]));

        let current: Vec<String> = self.channels.iter().map(|c| c.current().key.pk_hex()).collect();
        let live = Filter::new().kind(Kind::Custom(kinds::WRAP_EPHEMERAL)).authors(authors(&current)).since(Timestamp::now());
        want.push((PlaneSub::Live, current.clone(), vec![live]));

        self.b.pool.register_auth_keys(&relays, auth);
        for (plane, mut pks, filters) in want {
            pks.sort();
            pks.push(relays.join(","));
            if self.subscribed.get(&plane) == Some(&pks) {
                continue;
            }
            self.subscribed.insert(plane, pks);
            self.b.pool.subscribe(&format!("{}:{}", self.id, plane.name()), &relays, filters);
        }
    }

    fn chat_since(&self) -> Option<u64> {
        self.chat_cursor.map(|c| c.saturating_sub(60))
    }

    // ── Publishing ──────────────────────────────────────────────────────────

    /// Seal `rumor` as `author`, wrap it at `stream`, and publish to the community's
    /// relays. Succeeds if any relay accepts.
    pub async fn publish(&self, rumor: &Rumor, plane: Plane, stream: &StreamKey, author: &Keys, opts: WrapOptions) -> Result<Event> {
        let wrap = seal_and_wrap(rumor, plane, stream, author, opts)?;
        let res = self.b.pool.publish(&self.relays(), &wrap, Duration::from_secs(10)).await;
        anyhow::ensure!(!res.accepted.is_empty(), "no relay accepted the event: {:?}", res.rejected);
        Ok(wrap)
    }

    /// Post a message into a channel as the bridge bot.
    pub async fn post_as_bot(&self, channel_id: &str, text: &str, quote: Option<&Rumor>) -> Result<()> {
        let channel = self.channel(channel_id).context("channel not readable")?;
        let current = channel.current();
        let binding = concord::chat::Binding { channel_id_hex: channel_id, epoch: current.epoch };
        let target = quote.map(|q| concord::chat::Target { id: &q.id, kind: q.kind, author: &q.pubkey, tags: &q.tags });
        let rumor = concord::chat::message(
            &binding,
            &self.b.bot_hex(),
            text.to_owned(),
            None,
            target.as_ref(),
            vec![vec!["bot".into(), self.b.bot_hex()]],
            now_ms(),
            self.timer_secs(),
        );
        let opts = WrapOptions { expiration: rumor.tag_value("expiration").and_then(|e| e.parse().ok()), ..Default::default() };
        self.publish(&rumor, Plane::Chat, &(&current.key).into(), &self.b.bot, opts).await?;
        Ok(())
    }

    /// The bot's Guestbook Join at the current epoch.
    pub async fn publish_bot_join(&self, invite: Option<(&str, &str)>) -> Result<()> {
        let rumor = concord::guestbook::join(&self.b.bot_hex(), now_ms(), invite);
        self.publish(&rumor, Plane::Guestbook, &self.m.current_guestbook_stream(), &self.b.bot, WrapOptions::default()).await?;
        Ok(())
    }

    pub async fn save(&self) {
        if let Err(e) = self.b.db.save_membership(&self.m).await {
            tracing::error!(community = %self.id, error = %e, "failed to persist community keys");
        }
    }

    // ── Planes ──────────────────────────────────────────────────────────────

    async fn on_control(&mut self, event: Event) -> Result<()> {
        if !self.b.db.store_wrap(&self.id, "control", &event).await? {
            return Ok(());
        }
        let Some(opened) = self.open_control(&event) else { return Ok(()) };
        if self.add_edition(opened) {
            self.on_control_changed().await;
        }
        Ok(())
    }

    async fn on_control_changed(&mut self) {
        let was_banned = self.folded.banned.contains(&self.b.bot_hex());
        self.refold();
        self.subscribe();
        if !was_banned && self.folded.banned.contains(&self.b.bot_hex()) {
            self.revoke("The bridge was banned from this community on Armada.").await;
            return;
        }
        if self.status == Status::Active
            && let Err(e) = super::portals::reconcile(self).await
        {
            tracing::warn!(community = %self.id, error = %e, "failed to reconcile portals");
        }
    }

    async fn on_guestbook(&mut self, event: Event) -> Result<()> {
        if !self.b.db.store_wrap(&self.id, "guestbook", &event).await? {
            return Ok(());
        }
        let Some(stream) = self.m.guestbook_streams().into_iter().find(|s| s.pk == event.pubkey) else { return Ok(()) };
        let Ok(opened) = open_plane_wrap(&event, &stream, Plane::Guestbook) else { return Ok(()) };
        if opened.rumor.kind != kinds::KICK {
            return Ok(());
        }
        let Some(target) = opened.rumor.tag_value("p").map(str::to_owned) else { return Ok(()) };
        let citation = concord::edition::Citation::from_tags(&opened.rumor.tags);
        let f = &self.folded;
        let authorized = f.roster.can_act_on_member(opened.author(), &f.owner, &target, concord::roles::perm::KICK)
            && f.citation_satisfied(&self.id_bytes, opened.author(), citation.as_ref());
        if !authorized {
            return Ok(());
        }
        if target == self.b.bot_hex() {
            self.revoke("The bridge was kicked from this community on Armada.").await;
        } else if let Ok(pk) = PublicKey::from_hex(&target) {
            super::ghosts::remove_from_portals(self, &pk, "Kicked on Armada").await;
        }
        Ok(())
    }

    /// Re-read the rekey addresses we hold wraps for and adopt any rotation.
    async fn try_rekeys(&mut self) {
        let Ok(wraps) = self.b.db.wraps(&self.id, "rekey").await else { return };
        loop {
            let base = self.m.next_base_rekey_address();
            let base_key: StreamKey = (&base).into();
            let channel_addrs = self.m.channel_rekey_addresses();
            let mut base_parsed = vec![];
            let mut channel_parsed = vec![];
            for w in &wraps {
                if w.pubkey == base.pubkey() {
                    if let Ok(o) = open_plane_wrap(w, &base_key, Plane::Rekey)
                        && let Ok(p) = concord::rekey::parse_rekey(&o)
                    {
                        base_parsed.push(p);
                    }
                } else if let Some((g, _, _)) = channel_addrs.iter().find(|(g, _, _)| g.pubkey() == w.pubkey)
                    && let Ok(o) = open_plane_wrap(w, &g.into(), Plane::Rekey)
                    && let Ok(p) = concord::rekey::parse_rekey(&o)
                {
                    channel_parsed.push(p);
                }
            }
            let mut changed = false;
            if !base_parsed.is_empty() && !self.dissolved {
                let rotations = concord::rekey::group_rotations(base_parsed);
                match self.m.apply_base_rotations(&rotations, &self.folded, &self.b.bot) {
                    RekeyOutcome::AdoptedRoot(epoch) => {
                        tracing::info!(community = %self.id, epoch, "adopted a Refounding");
                        changed = true;
                    }
                    RekeyOutcome::Excluded(epoch) => {
                        tracing::warn!(community = %self.id, epoch, "a Refounding excluded the bridge");
                        self.save().await;
                        self.revoke("A key rotation on Armada removed the bridge from this community.").await;
                        return;
                    }
                    RekeyOutcome::Nothing => {}
                }
            }
            if !channel_parsed.is_empty() {
                let rotations = concord::rekey::group_rotations(channel_parsed);
                for (channel, outcome) in self.m.apply_channel_rotations(&rotations, &self.folded, &self.b.bot) {
                    tracing::info!(community = %self.id, %channel, ?outcome, "private channel rotated");
                    changed = true;
                }
            }
            if !changed {
                break;
            }
            self.save().await;
            self.refold();
            // A new epoch has an empty Guestbook until a snapshot or Join lands.
            if let Err(e) = self.publish_bot_join(None).await {
                tracing::warn!(community = %self.id, error = %e, "could not publish the bot's Join at the new epoch");
            }
        }
        self.subscribe();
    }

    async fn on_rekey(&mut self, event: Event) -> Result<()> {
        if self.b.db.store_wrap(&self.id, "rekey", &event).await? {
            self.try_rekeys().await;
            if self.status == Status::Active {
                let _ = super::portals::reconcile(self).await;
            }
        }
        Ok(())
    }

    async fn check_dissolved(&mut self) {
        let Ok(wraps) = self.b.db.wraps(&self.id, "dissolved").await else { return };
        let key: StreamKey = concord::derive::dissolved_group_key(&self.id_bytes).into();
        let dead = wraps.iter().any(|w| {
            open_plane_wrap(w, &key, Plane::Control).is_ok_and(|o| concord::control::is_dissolved_opened(&o, &self.m.owner, &self.id_bytes))
        });
        if dead && !self.dissolved {
            self.dissolved = true;
            self.revoke("This community was dissolved by its owner on Armada.").await;
        }
    }

    async fn on_dissolved(&mut self, event: Event) -> Result<()> {
        if self.b.db.store_wrap(&self.id, "dissolved", &event).await? {
            self.check_dissolved().await;
        }
        Ok(())
    }

    async fn on_direct_invite(&mut self, invite: DirectInvite) {
        let adopted = self.m.adopt_catch_up(&invite.bundle);
        if adopted.is_empty() {
            return;
        }
        tracing::info!(community = %self.id, channels = ?adopted, "adopted private channel keys from a Direct Invite");
        self.save().await;
        self.refold();
        self.subscribe();
        if self.status == Status::Active {
            let _ = super::portals::reconcile(self).await;
        }
    }

    // ── Lifecycle ───────────────────────────────────────────────────────────

    /// Stop bridging: tell Matrix why and mark the community revoked. Portal rooms
    /// stay as an archive.
    pub async fn revoke(&mut self, why: &str) {
        if self.status == Status::Revoked {
            return;
        }
        self.status = Status::Revoked;
        let _ = self.b.db.set_status(&self.id, "revoked", None).await;
        for portal in self.portals.values() {
            self.b.notice(&portal.room_id, &format!("{why} Messages are no longer bridged.")).await;
        }
        if let Some(room) = &self.management_room {
            self.b.notice(room, &format!("**{}**: {why}", self.name())).await;
        }
        for plane in [PlaneSub::Chat, PlaneSub::Live, PlaneSub::Guestbook, PlaneSub::Rekey] {
            self.b.pool.unsubscribe(&format!("{}:{}", self.id, plane.name()));
        }
    }

    pub fn status_text(&self) -> String {
        let bridged: Vec<String> = self
            .channels
            .iter()
            .filter(|c| self.portals.get(&c.id_hex).is_some_and(|p| p.enabled))
            .map(|c| format!("#{}", c.name))
            .collect();
        let mut s = format!("**{}** ({}…) — {}", self.name(), &self.id[..12], self.status.as_str());
        match self.status {
            Status::Pending => {
                if let Some(code) = &self.approval_code {
                    s.push_str(&format!(", waiting for an Armada admin to post `/bridge approve {code}`"));
                }
            }
            Status::Active => s.push_str(&format!(", bridging {}", if bridged.is_empty() { "no channels".into() } else { bridged.join(", ") })),
            Status::Revoked => {}
        }
        s
    }

    async fn command(&mut self, cmd: Command) -> String {
        match cmd {
            Command::Status => self.status_text(),
            Command::Unbridge { by } => {
                self.revoke(&format!("{by} unbridged this community.")).await;
                // Say goodbye on Armada so members know the bridge is gone.
                let leave = concord::guestbook::leave(&self.b.bot_hex(), now_ms());
                let _ = self.publish(&leave, Plane::Guestbook, &self.m.current_guestbook_stream(), &self.b.bot, WrapOptions::default()).await;
                format!("Unbridged **{}**.", self.name())
            }
            Command::Invite { mxid } => match &self.space {
                Some(space) => match super::portals::invite_user(self, space, &mxid).await {
                    Ok(()) => format!("Invited {mxid} to **{}**.", self.name()),
                    Err(e) => format!("Couldn't invite {mxid}: {e}"),
                },
                None => "This community has no Matrix space yet (it isn't approved).".into(),
            },
        }
    }

    pub async fn run(mut self, mut rx: mpsc::UnboundedReceiver<Msg>) {
        while let Some(msg) = rx.recv().await {
            let res = match msg {
                Msg::Wrap { plane, relay, event } => self.on_wrap(plane, relay, *event).await,
                Msg::Matrix(event) => {
                    if self.status == Status::Active {
                        super::to_armada::handle(&mut self, *event).await
                    } else {
                        Ok(())
                    }
                }
                Msg::Typing { room, user } => {
                    if self.status == Status::Active {
                        super::to_armada::typing(&mut self, &room, &user).await
                    } else {
                        Ok(())
                    }
                }
                Msg::DirectInvite(invite) => {
                    self.on_direct_invite(*invite).await;
                    Ok(())
                }
                Msg::Command(cmd, reply) => {
                    let _ = reply.send(self.command(cmd).await);
                    Ok(())
                }
                Msg::Tick => {
                    // Also heals a reconcile that failed partway (e.g. a homeserver error).
                    if self.status == Status::Active && let Err(e) = super::portals::reconcile(&mut self).await {
                        tracing::warn!(community = %self.id, error = %format!("{e:#}"), "reconcile failed");
                    }
                    super::to_matrix::expire(&mut self).await
                }
            };
            if let Err(e) = res {
                tracing::warn!(community = %self.id, error = %format!("{e:#}"), "community task error");
            }
        }
    }

    async fn on_wrap(&mut self, plane: PlaneSub, relay: String, event: Event) -> Result<()> {
        match plane {
            PlaneSub::Control => self.on_control(event).await,
            PlaneSub::Guestbook => self.on_guestbook(event).await,
            PlaneSub::Rekey => self.on_rekey(event).await,
            PlaneSub::Dissolved => self.on_dissolved(event).await,
            PlaneSub::Chat => {
                let created = event.created_at.as_secs();
                let res = super::to_matrix::handle(self, event).await;
                if created > self.chat_cursor.unwrap_or(0) {
                    self.chat_cursor = Some(created);
                    let _ = self.b.db.bump_cursor(&format!("{}:chat", self.id), &relay, created).await;
                }
                res
            }
            PlaneSub::Live => super::to_matrix::live(self, event).await,
        }
    }
}

fn new_community(b: Arc<Bridge>, row: &CommunityRow, m: Membership) -> Community {
    Community {
        id_bytes: m.id(),
        id: m.community_id.clone(),
        m,
        status: Status::parse(&row.status),
        approval_code: row.approval_code.clone(),
        requested_by: row.requested_by.clone(),
        management_room: row.management_room.clone(),
        space: row.space_room_id.clone(),
        folded: FoldedControl::default(),
        editions: vec![],
        edition_ids: HashSet::new(),
        channels: vec![],
        routes: HashMap::new(),
        portals: HashMap::new(),
        settings: HashMap::new(),
        dissolved: false,
        seen: lru::LruCache::new(NonZeroUsize::new(20_000).unwrap()),
        typing_sent: HashMap::new(),
        emoji: HashMap::new(),
        subscribed: HashMap::new(),
        chat_cursor: None,
        b,
    }
}

/// Start the actor for a stored community.
pub async fn spawn(b: Arc<Bridge>, row: CommunityRow, m: Membership, portals: Vec<PortalRow>) {
    let mut c = new_community(b.clone(), &row, m);
    c.chat_cursor = b.db.cursor(&format!("{}:chat", c.id)).await.ok().flatten();
    for p in portals {
        b.register_room(&p.room_id, &c.id).await;
        c.portals.insert(p.channel_id.clone(), p);
    }
    if let Some(space) = &c.space {
        b.register_room(space, &c.id).await;
    }
    if let Err(e) = c.load().await {
        tracing::error!(community = %c.id, error = %e, "failed to load community");
    }
    c.subscribe();
    if c.status == Status::Active
        && let Err(e) = super::portals::reconcile(&mut c).await
    {
        tracing::warn!(community = %c.id, error = %format!("{e:#}"), "reconcile failed");
    }
    let (tx, rx) = mpsc::unbounded_channel();
    b.insert_handle(&c.id, CommunityHandle { id: c.id.clone(), tx }).await;
    tracing::info!(community = %c.id, name = %c.name(), status = c.status.as_str(), "community loaded");
    tokio::spawn(c.run(rx));
}

/// Join a community from an invite bundle and wait for Armada-side approval.
pub async fn join(b: Arc<Bridge>, bundle: &concord::invite::InviteBundle, requested_by: &str, management_room: &str) -> Result<String> {
    let m = Membership::from_bundle(bundle, now_ms());
    let code = hex::encode(rand::random::<[u8; 4]>());
    b.db.insert_community(&m, &code, requested_by, Some(management_room)).await?;
    let row = b.db.community(&m.community_id).await?.context("community vanished")?;
    let c = new_community(b.clone(), &row, m);
    let attribution = bundle.creator_npub.as_deref().map(|creator| (creator, bundle.label.as_deref().unwrap_or("")));
    c.publish_bot_join(attribution).await.context("publishing the bridge's Join")?;
    spawn(b, row, c.m, vec![]).await;
    Ok(code)
}
