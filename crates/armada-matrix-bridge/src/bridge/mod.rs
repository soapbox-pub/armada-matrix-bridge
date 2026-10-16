//! The bridge: shared services, startup, and routing. Each Armada community is
//! owned by one actor task ([`community`]) that handles both its Nostr traffic and
//! its Matrix rooms in a single order, so the two directions never race.

pub mod commands;
pub mod community;
pub mod crypto;
pub mod format;
pub mod ghosts;
pub mod media;
pub mod portals;
pub mod to_armada;
pub mod to_matrix;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use nostr::nips::nip19::ToBech32;
use nostr::prelude::{Event, Filter, Keys, Kind, PublicKey};
use relay_pool::{Pool, PoolEvent};
use serde_json::{Value, json};
use tokio::sync::{RwLock, mpsc, oneshot};

use crate::config::{Config, Permission};
use crate::db::Db;
use crate::keys::KeyRing;
use crate::matrix::appservice::Transaction;
use crate::matrix::{As, Client};
use community::{CommunityHandle, Msg};

pub const INBOX_SUB: &str = "inbox";

pub struct Bridge {
    pub config: Config,
    pub keys: KeyRing,
    /// The bridge's own Armada identity.
    pub bot: Keys,
    pub bot_mxid: String,
    pub db: Db,
    pub mx: Client,
    pub pool: Pool,
    pub http: reqwest::Client,
    communities: RwLock<HashMap<String, CommunityHandle>>,
    /// Matrix room → owning community.
    rooms: RwLock<HashMap<String, String>>,
    /// Who was typing in each portal room, to send only new typers to Armada.
    typing: tokio::sync::Mutex<HashMap<String, HashSet<String>>>,
    pub crypto: Option<crate::matrix::e2ee::Crypto>,
    encrypted_rooms: RwLock<HashSet<String>>,
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

impl Bridge {
    pub fn new(config: Config, keys: KeyRing, bot: Keys, db: Db, mx: Client, pool: Pool) -> Arc<Bridge> {
        let crypto = config
            .encryption
            .enabled
            .then(|| crate::matrix::e2ee::Crypto::new(mx.clone(), config.encryption.store_dir.clone(), keys.crypto_passphrase()));
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent(concat!("armada-matrix-bridge/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("reqwest client");
        Arc::new(Bridge {
            bot_mxid: config.bot_mxid(),
            config,
            keys,
            bot,
            db,
            mx,
            pool,
            http,
            communities: RwLock::default(),
            rooms: RwLock::default(),
            typing: Default::default(),
            crypto,
            encrypted_rooms: RwLock::default(),
        })
    }

    pub fn bot_hex(&self) -> String {
        self.bot.public_key().to_hex()
    }

    pub fn bot_npub(&self) -> String {
        self.bot.public_key().to_bech32().unwrap_or_default()
    }

    /// The Matrix user an Armada member appears as.
    pub fn ghost_mxid(&self, pk: &PublicKey) -> String {
        format!("@{}{}:{}", self.config.appservice.ghost_prefix, pk.to_bech32().unwrap_or_default(), self.config.homeserver.server_name)
    }

    pub fn ghost_pubkey(&self, mxid: &str) -> Option<PublicKey> {
        let local = mxid.strip_prefix('@')?.strip_suffix(&format!(":{}", self.config.homeserver.server_name))?;
        let npub = local.strip_prefix(&self.config.appservice.ghost_prefix)?;
        nostr::nips::nip19::FromBech32::from_bech32(npub).ok()
    }

    /// Users the bridge owns (the bot and every ghost).
    pub fn in_namespace(&self, mxid: &str) -> bool {
        mxid == self.bot_mxid || self.ghost_pubkey(mxid).is_some()
    }

    pub fn permission(&self, mxid: &str) -> Permission {
        self.config.permission(mxid)
    }

    pub async fn register_room(&self, room: &str, cid: &str) {
        self.rooms.write().await.insert(room.to_owned(), cid.to_owned());
    }

    pub async fn community_of_room(&self, room: &str) -> Option<String> {
        self.rooms.read().await.get(room).cloned()
    }

    pub async fn handle(&self, cid: &str) -> Option<CommunityHandle> {
        self.communities.read().await.get(cid).cloned()
    }

    pub async fn handles(&self) -> Vec<CommunityHandle> {
        self.communities.read().await.values().cloned().collect()
    }

    pub async fn insert_handle(&self, cid: &str, handle: CommunityHandle) {
        self.communities.write().await.insert(cid.to_owned(), handle);
    }

    pub async fn remove_handle(&self, cid: &str) {
        self.communities.write().await.remove(cid);
    }

    /// Ask a community actor something and wait for its answer.
    pub async fn ask(&self, cid: &str, make: impl FnOnce(oneshot::Sender<String>) -> Msg) -> Option<String> {
        let handle = self.handle(cid).await?;
        let (tx, rx) = oneshot::channel();
        handle.tx.send(make(tx)).ok()?;
        rx.await.ok()
    }

    pub async fn is_encrypted(&self, room: &str) -> bool {
        self.encrypted_rooms.read().await.contains(room)
    }

    pub async fn mark_encrypted(&self, room: &str) {
        self.encrypted_rooms.write().await.insert(room.to_owned());
    }

    /// Send an event as a bridge-owned user, encrypting it if the room is.
    /// Reactions stay in the clear, as clients send them.
    pub async fn send(&self, sender: &str, room: &str, event_type: &str, content: &Value, ts_ms: Option<u64>) -> Result<String> {
        let who = As::user(sender);
        if event_type != "m.reaction"
            && let Some(crypto) = &self.crypto
            && self.is_encrypted(room).await
        {
            let encrypted = crypto.encrypt(sender, room, event_type, content).await?;
            return match ts_ms {
                Some(ts) => self.mx.send_ts(who, room, "m.room.encrypted", &encrypted, ts).await,
                None => self.mx.send(who, room, "m.room.encrypted", &encrypted).await,
            };
        }
        match ts_ms {
            Some(ts) => self.mx.send_ts(who, room, event_type, content, ts).await,
            None => self.mx.send(who, room, event_type, content).await,
        }
    }

    /// Upload media for a room: encrypted rooms get an `EncryptedFile` (`file`),
    /// others a plain `url`. Returns the key and value to put in the content.
    pub async fn upload_for_room(&self, sender: &str, room: &str, bytes: Vec<u8>, mime: &str, name: &str) -> Result<(&'static str, Value)> {
        if self.crypto.is_some() && self.is_encrypted(room).await {
            let (cipher, mut file) = crypto::encrypt_attachment(&bytes);
            let mxc = self.mx.upload(As::user(sender), cipher, "application/octet-stream", None).await?;
            file["url"] = json!(mxc);
            return Ok(("file", file));
        }
        Ok(("url", json!(self.mx.upload(As::user(sender), bytes, mime, Some(name)).await?)))
    }

    /// Send a notice as the bot.
    pub async fn notice(&self, room: &str, text: &str) {
        let (body, html, _) = format::armada_to_matrix(text, &|_| None);
        let mut content = json!({ "msgtype": "m.notice", "body": body });
        if let Some(html) = html {
            content["format"] = json!("org.matrix.custom.html");
            content["formatted_body"] = json!(html);
        }
        if let Err(e) = self.send(&self.bot_mxid, room, "m.room.message", &content, None).await {
            tracing::warn!(%room, error = %e, "failed to send notice");
        }
    }

    /// The bridge's relays for global things (profiles, its inbox).
    pub fn relays(&self) -> Vec<String> {
        self.config.bridge.relays.iter().filter_map(|r| relay_pool::normalize_relay_url(r)).collect()
    }

    // ── Startup ─────────────────────────────────────────────────────────────

    pub async fn start(self: &Arc<Self>) -> Result<()> {
        self.mx.register(&self.config.appservice.bot_localpart).await?;
        if let Err(e) = self.mx.set_displayname(&self.bot_mxid, &self.config.appservice.bot_displayname).await {
            tracing::warn!(error = %e, "could not set the bot's display name");
        }
        if let Some(avatar) = &self.config.appservice.bot_avatar
            && let Err(e) = self.mx.set_avatar(&self.bot_mxid, avatar).await
        {
            tracing::warn!(error = %e, "could not set the bot's avatar");
        }
        self.publish_bot_identity().await;

        // The inbox: Direct Invites addressed to the bridge.
        let inbox = Filter::new().kind(Kind::Custom(concord::kinds::WRAP)).pubkey(self.bot.public_key()).custom_tag(
            nostr::prelude::SingleLetterTag::from_char('k').expect("k is a single-letter tag"),
            concord::kinds::DIRECT_INVITE.to_string(),
        );
        self.pool.subscribe(INBOX_SUB, &self.relays(), vec![inbox]);

        let portals = self.db.portals().await?;
        for p in portals.iter().filter(|p| p.encrypted) {
            self.mark_encrypted(&p.room_id).await;
        }
        if let Some(crypto) = &self.crypto {
            crypto.machine(&self.bot_mxid).await.context("setting up the bot's encryption device")?;
        }
        for row in self.db.communities().await? {
            if row.status == "revoked" {
                continue;
            }
            let membership = match self.db.open_membership(&row) {
                Ok(m) => m,
                Err(e) => {
                    tracing::error!(community = %row.community_id, error = %e, "cannot open stored community keys");
                    continue;
                }
            };
            let mine: Vec<_> = portals.iter().filter(|p| p.community_id == row.community_id).cloned().collect();
            community::spawn(self.clone(), row, membership, mine).await;
        }
        Ok(())
    }

    /// The bot's kind 0 (`bot: true`), its DM relays (10050) so Direct Invites can
    /// reach it, and its command manifest (10304, Armada NIP.md).
    async fn publish_bot_identity(&self) {
        let relays = self.relays();
        let profile = json!({
            "name": self.config.appservice.bot_displayname,
            "about": format!("Bridges Armada communities to Matrix ({}). An admin approves with /bridge approve <code>.", self.config.homeserver.server_name),
            "bot": true,
        });
        let dm_relays: Vec<nostr::prelude::Tag> = relays.iter().filter_map(|r| nostr::prelude::Tag::parse(["relay", r.as_str()]).ok()).collect();
        let manifest = json!({
            "v": 1,
            "commands": [
                { "name": "bridge", "description": "Manage the Matrix bridge for this community", "args": [
                    { "name": "action", "type": "choice", "description": "", "required": true, "choices": ["approve", "revoke", "status", "include", "exclude"] },
                    { "name": "code", "type": "string", "description": "The approval code shown on Matrix", "required": false },
                ] },
            ],
        });
        let events = [
            (Kind::Metadata, profile.to_string(), vec![]),
            (Kind::Custom(10050), String::new(), dm_relays),
            (Kind::Custom(concord::kinds::BOT_MANIFEST), manifest.to_string(), vec![]),
        ];
        for (kind, content, tags) in events {
            let event = nostr::prelude::UnsignedEvent::new(self.bot.public_key(), nostr::prelude::Timestamp::now(), kind, tags, content);
            match nostr::event::FinalizeEvent::finalize(event, &self.bot) {
                Ok(event) => {
                    let res = self.pool.publish(&relays, &event, Duration::from_secs(10)).await;
                    if res.accepted.is_empty() {
                        tracing::warn!(kind = %kind, rejected = ?res.rejected, "no relay accepted the bot's event");
                    }
                }
                Err(e) => tracing::warn!(error = %e, "could not sign the bot's event"),
            }
        }
    }

    // ── Routing ─────────────────────────────────────────────────────────────

    /// Route Nostr traffic: subscription ids are `<community id>:<plane>`.
    pub async fn run_nostr(self: Arc<Self>, mut rx: mpsc::UnboundedReceiver<PoolEvent>) {
        while let Some(ev) = rx.recv().await {
            let PoolEvent::Event { relay, sub_id, event } = ev else { continue };
            if sub_id == INBOX_SUB {
                let this = self.clone();
                tokio::spawn(async move { this.direct_invite(event).await });
                continue;
            }
            let Some((cid, plane)) = sub_id.split_once(':') else { continue };
            let Some(plane) = community::PlaneSub::parse(plane) else { continue };
            if let Some(handle) = self.handle(cid).await {
                let _ = handle.tx.send(Msg::Wrap { plane, relay, event: Box::new(event) });
            }
        }
    }

    async fn direct_invite(self: Arc<Self>, event: Event) {
        let Some(invite) = concord::direct_invite::unwrap(&event, &self.bot) else { return };
        let cid = invite.bundle.community_id.clone();
        match self.db.mark_direct_invite(&event.id.to_hex(), Some(&cid), Some(&invite.inviter)).await {
            Ok(true) => {}
            _ => return,
        }
        if let Some(handle) = self.handle(&cid).await {
            let _ = handle.tx.send(Msg::DirectInvite(Box::new(invite)));
        } else {
            tracing::info!(community = %cid, inviter = %invite.inviter, name = %invite.bundle.name, "Direct Invite to an unbridged community; a Matrix admin can bridge it with an invite link");
        }
    }

    pub async fn run_matrix(self: Arc<Self>, mut rx: mpsc::Receiver<Transaction>) {
        while let Some(txn) = rx.recv().await {
            if let Some(crypto) = &self.crypto {
                crypto.receive(&txn).await;
            }
            for event in txn.events {
                if let Err(e) = self.matrix_event(event).await {
                    tracing::warn!(error = %e, "failed to handle a Matrix event");
                }
            }
            for edu in txn.ephemeral {
                self.matrix_ephemeral(edu).await;
            }
        }
    }

    async fn matrix_event(self: &Arc<Self>, mut event: Value) -> Result<()> {
        let room = event["room_id"].as_str().unwrap_or_default().to_owned();
        match event["type"].as_str().unwrap_or_default() {
            "m.room.encryption" => {
                self.mark_encrypted(&room).await;
                self.db.set_portal_encrypted(&room).await?;
            }
            "m.room.member" => {
                if let Some(crypto) = &self.crypto {
                    crypto.invalidate_members(&room).await;
                }
            }
            "m.room.encrypted" if !self.in_namespace(event["sender"].as_str().unwrap_or_default()) => {
                if let Some(crypto) = &self.crypto {
                    match crypto.decrypt(&self.bot_mxid, &event).await {
                        Ok(decrypted) => event = decrypted,
                        Err(e) => {
                            tracing::warn!(%room, error = %e, "could not decrypt an event");
                            return Ok(());
                        }
                    }
                }
            }
            _ => {}
        }
        let sender = event["sender"].as_str().unwrap_or_default().to_owned();
        let kind = event["type"].as_str().unwrap_or_default();

        // Invites to the bot: accept from anyone allowed to use the bridge.
        if kind == "m.room.member" && event["state_key"].as_str() == Some(self.bot_mxid.as_str()) && event["content"]["membership"] == "invite" {
            if self.permission(&sender) >= Permission::User {
                self.mx.join(&self.bot_mxid, &room).await?;
                if self.mx.get_state(As::BOT, &room, "m.room.encryption", "").await.ok().flatten().is_some() {
                    self.mark_encrypted(&room).await;
                }
                if event["content"]["is_direct"].as_bool() == Some(true) || self.community_of_room(&room).await.is_none() {
                    self.db.set_management_room(&room, &sender).await?;
                    self.notice(&room, &commands::welcome(self)).await;
                }
            } else {
                let _ = self.mx.leave(&self.bot_mxid, &room).await;
            }
            return Ok(());
        }
        if self.in_namespace(&sender) {
            return Ok(());
        }
        if let Some(cid) = self.community_of_room(&room).await {
            if let Some(handle) = self.handle(&cid).await {
                let _ = handle.tx.send(Msg::Matrix(Box::new(event)));
            }
            return Ok(());
        }
        if kind == "m.room.message"
            && let Some(owner) = self.db.management_room(&room).await?
            && owner == sender
        {
            let body = event["content"]["body"].as_str().unwrap_or_default().to_owned();
            let this = self.clone();
            tokio::spawn(async move { commands::management(this, room, sender, body).await });
        }
        Ok(())
    }

    async fn matrix_ephemeral(&self, edu: Value) {
        if edu["type"] != "m.typing" {
            return;
        }
        let Some(room) = edu["room_id"].as_str() else { return };
        let Some(cid) = self.community_of_room(room).await else { return };
        let now: HashSet<String> = edu["content"]["user_ids"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).filter(|u| !self.in_namespace(u)).map(str::to_owned).collect())
            .unwrap_or_default();
        let started: Vec<String> = {
            let mut typing = self.typing.lock().await;
            let before = typing.insert(room.to_owned(), now.clone()).unwrap_or_default();
            now.difference(&before).cloned().collect()
        };
        if let Some(handle) = self.handle(&cid).await {
            for user in started {
                let _ = handle.tx.send(Msg::Typing { room: room.to_owned(), user });
            }
        }
    }

    /// Periodic maintenance: ask every community to tick (expiry, profile refresh).
    pub async fn run_ticks(self: Arc<Self>) {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            for handle in self.handles().await {
                let _ = handle.tx.send(Msg::Tick);
            }
        }
    }
}
