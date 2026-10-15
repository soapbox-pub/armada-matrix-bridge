//! Postgres access. Queries are plain runtime-checked SQL; the schema is in
//! `migrations/`.

use anyhow::{Context, Result};
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use tokio_postgres::types::ToSql;
use tokio_postgres::{NoTls, Row};

use crate::keys::KeyRing;
use concord::community::Membership;


/// Schema migrations, applied in order and recorded in `schema_migrations`.
const MIGRATIONS: &[(i32, &str)] = &[(1, include_str!("../migrations/0001_init.sql"))];

#[derive(Clone)]
pub struct Db {
    pool: Pool,
    keys: KeyRing,
}

#[derive(Clone, Debug)]
pub struct CommunityRow {
    pub community_id: String,
    pub membership: Vec<u8>,
    pub status: String,
    pub approval_code: Option<String>,
    pub requested_by: String,
    pub approved_by: Option<String>,
    pub space_room_id: Option<String>,
    pub management_room: Option<String>,
}

#[derive(Clone, Debug)]
pub struct PortalRow {
    pub community_id: String,
    pub channel_id: String,
    pub room_id: String,
    pub enabled: bool,
    pub encrypted: bool,
    pub name: String,
}

// Rows mirror their tables whole, read or not.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct MessageRow {
    pub room_id: String,
    pub event_id: String,
    pub community_id: String,
    pub channel_id: String,
    pub rumor_id: String,
    pub part: i32,
    pub kind: i32,
    pub author: String,
    pub origin: String,
    pub thread_root: Option<String>,
    pub expires_at: Option<i64>,
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct ReactionRow {
    pub room_id: String,
    pub event_id: String,
    pub community_id: String,
    pub rumor_id: String,
    pub target_rumor_id: String,
    pub author: String,
    pub key: String,
    pub origin: String,
}

#[derive(Clone, Debug)]
pub struct GhostRow {
    pub pubkey: String,
    pub mxid: String,
    pub registered: bool,
    pub displayname: Option<String>,
    pub avatar_url: Option<String>,
    pub avatar_mxc: Option<String>,
    pub profile_at: i64,
}

impl Db {
    pub async fn connect(url: &str, max: u32, keys: KeyRing) -> Result<Db> {
        let config: tokio_postgres::Config = url.parse().context("parsing database.url")?;
        let manager = Manager::from_config(config, NoTls, ManagerConfig { recycling_method: RecyclingMethod::Fast });
        let pool = Pool::builder(manager).max_size(max as usize).build()?;
        let db = Db { pool, keys };
        db.migrate().await?;
        Ok(db)
    }

    async fn migrate(&self) -> Result<()> {
        let mut client = self.pool.get().await?;
        client.batch_execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INT PRIMARY KEY)").await?;
        for (version, sql) in MIGRATIONS {
            let tx = client.transaction().await?;
            // Serialize concurrent starts.
            tx.batch_execute("LOCK TABLE schema_migrations IN EXCLUSIVE MODE").await?;
            let done = tx.query_opt("SELECT 1 FROM schema_migrations WHERE version = $1", &[version]).await?.is_some();
            if !done {
                tx.batch_execute(sql).await.with_context(|| format!("migration {version}"))?;
                tx.execute("INSERT INTO schema_migrations (version) VALUES ($1)", &[version]).await?;
            }
            tx.commit().await?;
        }
        Ok(())
    }

    async fn exec(&self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<u64> {
        Ok(self.pool.get().await?.execute(sql, params).await?)
    }

    async fn all(&self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Vec<Row>> {
        Ok(self.pool.get().await?.query(sql, params).await?)
    }

    async fn one(&self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Option<Row>> {
        Ok(self.pool.get().await?.query_opt(sql, params).await?)
    }

    // ── Communities ─────────────────────────────────────────────────────────

    pub fn open_membership(&self, row: &CommunityRow) -> Result<Membership> {
        Ok(serde_json::from_slice(&self.keys.unseal(&row.membership)?)?)
    }

    pub async fn communities(&self) -> Result<Vec<CommunityRow>> {
        Ok(self.all(&format!("SELECT {COMMUNITY_COLS} FROM communities"), &[]).await?.iter().map(CommunityRow::from).collect())
    }

    pub async fn community(&self, id: &str) -> Result<Option<CommunityRow>> {
        Ok(self.one(&format!("SELECT {COMMUNITY_COLS} FROM communities WHERE community_id = $1"), &[&id]).await?.as_ref().map(CommunityRow::from))
    }

    pub async fn insert_community(&self, m: &Membership, code: &str, requested_by: &str, management_room: Option<&str>) -> Result<()> {
        let sealed = self.keys.seal(&serde_json::to_vec(m)?);
        self.exec(
            "INSERT INTO communities (community_id, membership, status, approval_code, requested_by, management_room) VALUES ($1, $2, 'pending', $3, $4, $5)",
            &[&m.community_id, &sealed, &code, &requested_by, &management_room],
        )
        .await?;
        Ok(())
    }

    pub async fn save_membership(&self, m: &Membership) -> Result<()> {
        let sealed = self.keys.seal(&serde_json::to_vec(m)?);
        self.exec("UPDATE communities SET membership = $2, updated_at = now() WHERE community_id = $1", &[&m.community_id, &sealed]).await?;
        Ok(())
    }

    pub async fn set_status(&self, id: &str, status: &str, approved_by: Option<&str>) -> Result<()> {
        self.exec(
            "UPDATE communities SET status = $2, approved_by = COALESCE($3, approved_by), updated_at = now() WHERE community_id = $1",
            &[&id, &status, &approved_by],
        )
        .await?;
        Ok(())
    }

    pub async fn set_space(&self, id: &str, space: &str) -> Result<()> {
        self.exec("UPDATE communities SET space_room_id = $2 WHERE community_id = $1", &[&id, &space]).await?;
        Ok(())
    }

    pub async fn delete_community(&self, id: &str) -> Result<()> {
        self.exec("DELETE FROM communities WHERE community_id = $1", &[&id]).await?;
        Ok(())
    }

    // ── Plane wraps ─────────────────────────────────────────────────────────

    pub async fn store_wrap(&self, cid: &str, plane: &str, event: &nostr::prelude::Event) -> Result<bool> {
        let json: serde_json::Value = serde_json::from_str(&event.as_json())?;
        let n = self
            .exec(
                "INSERT INTO plane_wraps (community_id, plane, wrap_id, stream_pk, created_at, event) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
                &[&cid, &plane, &event.id.to_hex(), &event.pubkey.to_hex(), &(event.created_at.as_secs() as i64), &json],
            )
            .await?;
        Ok(n > 0)
    }

    pub async fn wraps(&self, cid: &str, plane: &str) -> Result<Vec<nostr::prelude::Event>> {
        let rows = self.all("SELECT event FROM plane_wraps WHERE community_id = $1 AND plane = $2 ORDER BY created_at", &[&cid, &plane]).await?;
        Ok(rows.iter().filter_map(|r| nostr::prelude::Event::from_json(r.get::<_, serde_json::Value>(0).to_string()).ok()).collect())
    }

    // ── Portals ─────────────────────────────────────────────────────────────

    pub async fn portals(&self) -> Result<Vec<PortalRow>> {
        let rows = self.all("SELECT community_id, channel_id, room_id, enabled, encrypted, name FROM portals", &[]).await?;
        Ok(rows
            .iter()
            .map(|r| PortalRow { community_id: r.get(0), channel_id: r.get(1), room_id: r.get(2), enabled: r.get(3), encrypted: r.get(4), name: r.get(5) })
            .collect())
    }

    pub async fn insert_portal(&self, cid: &str, channel: &str, room: &str, encrypted: bool, name: &str) -> Result<()> {
        self.exec(
            "INSERT INTO portals (community_id, channel_id, room_id, encrypted, name) VALUES ($1, $2, $3, $4, $5)",
            &[&cid, &channel, &room, &encrypted, &name],
        )
        .await?;
        Ok(())
    }

    pub async fn update_portal(&self, room: &str, enabled: bool, name: &str) -> Result<()> {
        self.exec("UPDATE portals SET enabled = $2, name = $3 WHERE room_id = $1", &[&room, &enabled, &name]).await?;
        Ok(())
    }

    pub async fn set_portal_encrypted(&self, room: &str) -> Result<()> {
        self.exec("UPDATE portals SET encrypted = true WHERE room_id = $1", &[&room]).await?;
        Ok(())
    }

    pub async fn channel_settings(&self, cid: &str) -> Result<Vec<(String, bool)>> {
        let rows = self.all("SELECT channel_id, enabled FROM channel_settings WHERE community_id = $1", &[&cid]).await?;
        Ok(rows.iter().map(|r| (r.get(0), r.get(1))).collect())
    }

    pub async fn set_channel_setting(&self, cid: &str, channel: &str, enabled: bool, by: &str) -> Result<()> {
        self.exec(
            "INSERT INTO channel_settings (community_id, channel_id, enabled, changed_by) VALUES ($1, $2, $3, $4)
             ON CONFLICT (community_id, channel_id) DO UPDATE SET enabled = $3, changed_by = $4",
            &[&cid, &channel, &enabled, &by],
        )
        .await?;
        Ok(())
    }

    // ── Messages ────────────────────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_message(
        &self,
        room: &str,
        event_id: &str,
        cid: &str,
        channel: &str,
        rumor_id: &str,
        part: i32,
        kind: u16,
        author: &str,
        origin: &str,
        thread_root: Option<&str>,
        expires_at: Option<u64>,
    ) -> Result<()> {
        self.exec(
            "INSERT INTO messages (room_id, event_id, community_id, channel_id, rumor_id, part, kind, author, origin, thread_root, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT DO NOTHING",
            &[&room, &event_id, &cid, &channel, &rumor_id, &part, &(kind as i32), &author, &origin, &thread_root, &expires_at.map(|e| e as i64)],
        )
        .await?;
        Ok(())
    }

    pub async fn messages_by_rumor(&self, cid: &str, rumor_id: &str) -> Result<Vec<MessageRow>> {
        let rows = self.all(&format!("SELECT {MESSAGE_COLS} FROM messages WHERE community_id = $1 AND rumor_id = $2 ORDER BY part"), &[&cid, &rumor_id]).await?;
        Ok(rows.iter().map(MessageRow::from).collect())
    }

    pub async fn message_by_event(&self, room: &str, event_id: &str) -> Result<Option<MessageRow>> {
        Ok(self.one(&format!("SELECT {MESSAGE_COLS} FROM messages WHERE room_id = $1 AND event_id = $2"), &[&room, &event_id]).await?.as_ref().map(MessageRow::from))
    }

    pub async fn has_rumor(&self, cid: &str, rumor_id: &str) -> Result<bool> {
        Ok(self.one("SELECT 1 FROM messages WHERE community_id = $1 AND rumor_id = $2 LIMIT 1", &[&cid, &rumor_id]).await?.is_some())
    }

    pub async fn delete_messages_by_rumor(&self, cid: &str, rumor_id: &str) -> Result<()> {
        self.exec("DELETE FROM messages WHERE community_id = $1 AND rumor_id = $2", &[&cid, &rumor_id]).await?;
        Ok(())
    }

    /// Matrix events whose Armada rumor has expired (CORD-08), oldest first.
    pub async fn expired_messages(&self, cid: &str, now: u64, limit: i64) -> Result<Vec<MessageRow>> {
        let rows = self
            .all(
                &format!("SELECT {MESSAGE_COLS} FROM messages WHERE community_id = $1 AND expires_at IS NOT NULL AND expires_at <= $2 ORDER BY expires_at LIMIT $3"),
                &[&cid, &(now as i64), &limit],
            )
            .await?;
        Ok(rows.iter().map(MessageRow::from).collect())
    }

    pub async fn delete_message_event(&self, room: &str, event_id: &str) -> Result<()> {
        self.exec("DELETE FROM messages WHERE room_id = $1 AND event_id = $2", &[&room, &event_id]).await?;
        Ok(())
    }

    // ── Reactions ───────────────────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_reaction(&self, room: &str, event_id: &str, cid: &str, rumor_id: &str, target: &str, author: &str, key: &str, origin: &str) -> Result<()> {
        self.exec(
            "INSERT INTO reactions (room_id, event_id, community_id, rumor_id, target_rumor_id, author, key, origin) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING",
            &[&room, &event_id, &cid, &rumor_id, &target, &author, &key, &origin],
        )
        .await?;
        Ok(())
    }

    pub async fn reaction_by_rumor(&self, cid: &str, rumor_id: &str) -> Result<Option<ReactionRow>> {
        Ok(self.one(&format!("SELECT {REACTION_COLS} FROM reactions WHERE community_id = $1 AND rumor_id = $2"), &[&cid, &rumor_id]).await?.as_ref().map(ReactionRow::from))
    }

    pub async fn reaction_by_event(&self, room: &str, event_id: &str) -> Result<Option<ReactionRow>> {
        Ok(self.one(&format!("SELECT {REACTION_COLS} FROM reactions WHERE room_id = $1 AND event_id = $2"), &[&room, &event_id]).await?.as_ref().map(ReactionRow::from))
    }

    pub async fn delete_reaction(&self, room: &str, event_id: &str) -> Result<()> {
        self.exec("DELETE FROM reactions WHERE room_id = $1 AND event_id = $2", &[&room, &event_id]).await?;
        Ok(())
    }

    // ── Ghosts and puppets ──────────────────────────────────────────────────

    pub async fn ghost(&self, pubkey: &str) -> Result<Option<GhostRow>> {
        let row = self.one("SELECT pubkey, mxid, registered, displayname, avatar_url, avatar_mxc, profile_at FROM ghosts WHERE pubkey = $1", &[&pubkey]).await?;
        Ok(row.map(|r| GhostRow {
            pubkey: r.get(0),
            mxid: r.get(1),
            registered: r.get(2),
            displayname: r.get(3),
            avatar_url: r.get(4),
            avatar_mxc: r.get(5),
            profile_at: r.get(6),
        }))
    }

    pub async fn upsert_ghost(&self, g: &GhostRow) -> Result<()> {
        self.exec(
            "INSERT INTO ghosts (pubkey, mxid, registered, displayname, avatar_url, avatar_mxc, profile_at) VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (pubkey) DO UPDATE SET registered = $3, displayname = $4, avatar_url = $5, avatar_mxc = $6, profile_at = $7",
            &[&g.pubkey, &g.mxid, &g.registered, &g.displayname, &g.avatar_url, &g.avatar_mxc, &g.profile_at],
        )
        .await?;
        Ok(())
    }

    pub async fn puppet_mxid(&self, pubkey: &str) -> Result<Option<String>> {
        Ok(self.one("SELECT mxid FROM puppets WHERE pubkey = $1", &[&pubkey]).await?.map(|r| r.get(0)))
    }

    pub async fn upsert_puppet(&self, pubkey: &str, mxid: &str) -> Result<()> {
        self.exec("INSERT INTO puppets (pubkey, mxid) VALUES ($1, $2) ON CONFLICT DO NOTHING", &[&pubkey, &mxid]).await?;
        Ok(())
    }

    pub async fn puppet_profile_hash(&self, pubkey: &str) -> Result<Option<String>> {
        Ok(self.one("SELECT profile_hash FROM puppets WHERE pubkey = $1", &[&pubkey]).await?.and_then(|r| r.get(0)))
    }

    pub async fn set_puppet_profile_hash(&self, pubkey: &str, hash: &str) -> Result<()> {
        self.exec("UPDATE puppets SET profile_hash = $2 WHERE pubkey = $1", &[&pubkey, &hash]).await?;
        Ok(())
    }

    pub async fn puppet_joined(&self, cid: &str, pubkey: &str, epoch: u64) -> Result<bool> {
        Ok(self.one("SELECT 1 FROM puppet_joins WHERE community_id = $1 AND pubkey = $2 AND root_epoch = $3", &[&cid, &pubkey, &(epoch as i64)]).await?.is_some())
    }

    pub async fn set_puppet_joined(&self, cid: &str, pubkey: &str, epoch: u64) -> Result<()> {
        self.exec(
            "INSERT INTO puppet_joins (community_id, pubkey, root_epoch) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            &[&cid, &pubkey, &(epoch as i64)],
        )
        .await?;
        Ok(())
    }

    // ── Room membership cache ───────────────────────────────────────────────

    pub async fn is_room_member(&self, room: &str, mxid: &str) -> Result<bool> {
        Ok(self.one("SELECT 1 FROM room_members WHERE room_id = $1 AND mxid = $2", &[&room, &mxid]).await?.is_some())
    }

    pub async fn set_room_member(&self, room: &str, mxid: &str, joined: bool) -> Result<()> {
        if joined {
            self.exec("INSERT INTO room_members (room_id, mxid) VALUES ($1, $2) ON CONFLICT DO NOTHING", &[&room, &mxid]).await?;
        } else {
            self.exec("DELETE FROM room_members WHERE room_id = $1 AND mxid = $2", &[&room, &mxid]).await?;
        }
        Ok(())
    }

    // ── Cursors, invites, management rooms ──────────────────────────────────

    pub async fn cursor(&self, scope: &str) -> Result<Option<u64>> {
        Ok(self.one("SELECT MIN(newest) FROM cursors WHERE scope = $1", &[&scope]).await?.and_then(|r| r.get::<_, Option<i64>>(0)).map(|n| n as u64))
    }

    pub async fn bump_cursor(&self, scope: &str, relay: &str, newest: u64) -> Result<()> {
        self.exec(
            "INSERT INTO cursors (scope, relay, newest) VALUES ($1, $2, $3) ON CONFLICT (scope, relay) DO UPDATE SET newest = GREATEST(cursors.newest, $3)",
            &[&scope, &relay, &(newest as i64)],
        )
        .await?;
        Ok(())
    }

    pub async fn mark_direct_invite(&self, wrap_id: &str, cid: Option<&str>, inviter: Option<&str>) -> Result<bool> {
        let n = self
            .exec("INSERT INTO direct_invites (wrap_id, community_id, inviter) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING", &[&wrap_id, &cid, &inviter])
            .await?;
        Ok(n > 0)
    }

    pub async fn management_room(&self, room: &str) -> Result<Option<String>> {
        Ok(self.one("SELECT mxid FROM management_rooms WHERE room_id = $1", &[&room]).await?.map(|r| r.get(0)))
    }

    pub async fn set_management_room(&self, room: &str, mxid: &str) -> Result<()> {
        self.exec("INSERT INTO management_rooms (room_id, mxid) VALUES ($1, $2) ON CONFLICT (room_id) DO UPDATE SET mxid = $2", &[&room, &mxid]).await?;
        Ok(())
    }
}

const COMMUNITY_COLS: &str = "community_id, membership, status, approval_code, requested_by, approved_by, space_room_id, management_room";
const MESSAGE_COLS: &str = "room_id, event_id, community_id, channel_id, rumor_id, part, kind, author, origin, thread_root, expires_at";
const REACTION_COLS: &str = "room_id, event_id, community_id, rumor_id, target_rumor_id, author, key, origin";

impl From<&Row> for CommunityRow {
    fn from(r: &Row) -> Self {
        CommunityRow {
            community_id: r.get(0),
            membership: r.get(1),
            status: r.get(2),
            approval_code: r.get(3),
            requested_by: r.get(4),
            approved_by: r.get(5),
            space_room_id: r.get(6),
            management_room: r.get(7),
        }
    }
}

impl From<&Row> for MessageRow {
    fn from(r: &Row) -> Self {
        MessageRow {
            room_id: r.get(0),
            event_id: r.get(1),
            community_id: r.get(2),
            channel_id: r.get(3),
            rumor_id: r.get(4),
            part: r.get(5),
            kind: r.get(6),
            author: r.get(7),
            origin: r.get(8),
            thread_root: r.get(9),
            expires_at: r.get(10),
        }
    }
}

impl From<&Row> for ReactionRow {
    fn from(r: &Row) -> Self {
        ReactionRow {
            room_id: r.get(0),
            event_id: r.get(1),
            community_id: r.get(2),
            rumor_id: r.get(3),
            target_rumor_id: r.get(4),
            author: r.get(5),
            key: r.get(6),
            origin: r.get(7),
        }
    }
}
