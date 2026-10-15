//! Postgres access. Queries are plain runtime-checked SQL; the schema is in
//! `migrations/`.

use anyhow::Result;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

use crate::keys::KeyRing;
use concord::community::Membership;

macro_rules! message_cols {
    () => {
        "room_id, event_id, community_id, channel_id, rumor_id, part, kind, author, origin, thread_root, expires_at"
    };
}

#[derive(Clone)]
pub struct Db {
    pub pool: PgPool,
    keys: KeyRing,
}

#[derive(Clone, Debug, sqlx::FromRow)]
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

#[derive(Clone, Debug, sqlx::FromRow)]
pub struct PortalRow {
    pub community_id: String,
    pub channel_id: String,
    pub room_id: String,
    pub enabled: bool,
    pub encrypted: bool,
    pub name: String,
}

#[derive(Clone, Debug, sqlx::FromRow)]
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

#[derive(Clone, Debug, sqlx::FromRow)]
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

#[derive(Clone, Debug, sqlx::FromRow)]
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
        let pool = PgPoolOptions::new().max_connections(max).connect(url).await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Db { pool, keys })
    }

    // ── Communities ─────────────────────────────────────────────────────────

    pub fn open_membership(&self, row: &CommunityRow) -> Result<Membership> {
        Ok(serde_json::from_slice(&self.keys.unseal(&row.membership)?)?)
    }

    pub async fn communities(&self) -> Result<Vec<CommunityRow>> {
        Ok(sqlx::query_as("SELECT community_id, membership, status, approval_code, requested_by, approved_by, space_room_id, management_room FROM communities")
            .fetch_all(&self.pool)
            .await?)
    }

    pub async fn community(&self, id: &str) -> Result<Option<CommunityRow>> {
        Ok(sqlx::query_as("SELECT community_id, membership, status, approval_code, requested_by, approved_by, space_room_id, management_room FROM communities WHERE community_id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?)
    }

    pub async fn insert_community(&self, m: &Membership, code: &str, requested_by: &str, management_room: Option<&str>) -> Result<()> {
        sqlx::query("INSERT INTO communities (community_id, membership, status, approval_code, requested_by, management_room) VALUES ($1, $2, 'pending', $3, $4, $5)")
            .bind(&m.community_id)
            .bind(self.keys.seal(&serde_json::to_vec(m)?))
            .bind(code)
            .bind(requested_by)
            .bind(management_room)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn save_membership(&self, m: &Membership) -> Result<()> {
        sqlx::query("UPDATE communities SET membership = $2, updated_at = now() WHERE community_id = $1")
            .bind(&m.community_id)
            .bind(self.keys.seal(&serde_json::to_vec(m)?))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn set_status(&self, id: &str, status: &str, approved_by: Option<&str>) -> Result<()> {
        sqlx::query("UPDATE communities SET status = $2, approved_by = COALESCE($3, approved_by), updated_at = now() WHERE community_id = $1")
            .bind(id)
            .bind(status)
            .bind(approved_by)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn set_pending(&self, id: &str, code: &str, requested_by: &str, management_room: Option<&str>) -> Result<()> {
        sqlx::query("UPDATE communities SET status = 'pending', approval_code = $2, requested_by = $3, management_room = $4, updated_at = now() WHERE community_id = $1")
            .bind(id)
            .bind(code)
            .bind(requested_by)
            .bind(management_room)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn set_space(&self, id: &str, space: &str) -> Result<()> {
        sqlx::query("UPDATE communities SET space_room_id = $2 WHERE community_id = $1").bind(id).bind(space).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn delete_community(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM communities WHERE community_id = $1").bind(id).execute(&self.pool).await?;
        Ok(())
    }

    // ── Plane wraps ─────────────────────────────────────────────────────────

    pub async fn store_wrap(&self, cid: &str, plane: &str, event: &nostr::prelude::Event) -> Result<bool> {
        let res = sqlx::query("INSERT INTO plane_wraps (community_id, plane, wrap_id, stream_pk, created_at, event) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING")
            .bind(cid)
            .bind(plane)
            .bind(event.id.to_hex())
            .bind(event.pubkey.to_hex())
            .bind(event.created_at.as_secs() as i64)
            .bind(sqlx::types::Json(serde_json::from_str::<serde_json::Value>(&event.as_json())?))
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn wraps(&self, cid: &str, plane: &str) -> Result<Vec<nostr::prelude::Event>> {
        let rows: Vec<(sqlx::types::Json<serde_json::Value>,)> =
            sqlx::query_as("SELECT event FROM plane_wraps WHERE community_id = $1 AND plane = $2 ORDER BY created_at").bind(cid).bind(plane).fetch_all(&self.pool).await?;
        Ok(rows.into_iter().filter_map(|(j,)| nostr::prelude::Event::from_json(j.0.to_string()).ok()).collect())
    }

    // ── Portals ─────────────────────────────────────────────────────────────

    pub async fn portals(&self) -> Result<Vec<PortalRow>> {
        Ok(sqlx::query_as("SELECT community_id, channel_id, room_id, enabled, encrypted, name FROM portals").fetch_all(&self.pool).await?)
    }

    pub async fn insert_portal(&self, cid: &str, channel: &str, room: &str, encrypted: bool, name: &str) -> Result<()> {
        sqlx::query("INSERT INTO portals (community_id, channel_id, room_id, encrypted, name) VALUES ($1, $2, $3, $4, $5)")
            .bind(cid)
            .bind(channel)
            .bind(room)
            .bind(encrypted)
            .bind(name)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_portal(&self, room: &str, enabled: bool, name: &str) -> Result<()> {
        sqlx::query("UPDATE portals SET enabled = $2, name = $3 WHERE room_id = $1").bind(room).bind(enabled).bind(name).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn set_portal_encrypted(&self, room: &str) -> Result<()> {
        sqlx::query("UPDATE portals SET encrypted = true WHERE room_id = $1").bind(room).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn channel_settings(&self, cid: &str) -> Result<Vec<(String, bool)>> {
        Ok(sqlx::query_as("SELECT channel_id, enabled FROM channel_settings WHERE community_id = $1").bind(cid).fetch_all(&self.pool).await?)
    }

    pub async fn set_channel_setting(&self, cid: &str, channel: &str, enabled: bool, by: &str) -> Result<()> {
        sqlx::query("INSERT INTO channel_settings (community_id, channel_id, enabled, changed_by) VALUES ($1, $2, $3, $4) ON CONFLICT (community_id, channel_id) DO UPDATE SET enabled = $3, changed_by = $4")
            .bind(cid)
            .bind(channel)
            .bind(enabled)
            .bind(by)
            .execute(&self.pool)
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
        sqlx::query(
            "INSERT INTO messages (room_id, event_id, community_id, channel_id, rumor_id, part, kind, author, origin, thread_root, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT DO NOTHING",
        )
        .bind(room)
        .bind(event_id)
        .bind(cid)
        .bind(channel)
        .bind(rumor_id)
        .bind(part)
        .bind(kind as i32)
        .bind(author)
        .bind(origin)
        .bind(thread_root)
        .bind(expires_at.map(|e| e as i64))
        .execute(&self.pool)
        .await?;
        Ok(())
    }


    pub async fn messages_by_rumor(&self, cid: &str, rumor_id: &str) -> Result<Vec<MessageRow>> {
        Ok(sqlx::query_as(concat!("SELECT ", message_cols!(), " FROM messages WHERE community_id = $1 AND rumor_id = $2 ORDER BY part"))
            .bind(cid)
            .bind(rumor_id)
            .fetch_all(&self.pool)
            .await?)
    }

    pub async fn message_by_event(&self, room: &str, event_id: &str) -> Result<Option<MessageRow>> {
        Ok(sqlx::query_as(concat!("SELECT ", message_cols!(), " FROM messages WHERE room_id = $1 AND event_id = $2"))
            .bind(room)
            .bind(event_id)
            .fetch_optional(&self.pool)
            .await?)
    }

    pub async fn has_rumor(&self, cid: &str, rumor_id: &str) -> Result<bool> {
        let row: Option<(i32,)> = sqlx::query_as("SELECT 1 FROM messages WHERE community_id = $1 AND rumor_id = $2 LIMIT 1")
            .bind(cid)
            .bind(rumor_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    pub async fn delete_messages_by_rumor(&self, cid: &str, rumor_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM messages WHERE community_id = $1 AND rumor_id = $2").bind(cid).bind(rumor_id).execute(&self.pool).await?;
        Ok(())
    }

    /// Matrix events whose Armada rumor has expired (CORD-08), oldest first.
    pub async fn expired_messages(&self, cid: &str, now: u64, limit: i64) -> Result<Vec<MessageRow>> {
        Ok(sqlx::query_as(concat!(
            "SELECT ",
            message_cols!(),
            " FROM messages WHERE community_id = $3 AND expires_at IS NOT NULL AND expires_at <= $1 ORDER BY expires_at LIMIT $2"
        ))
            .bind(now as i64)
            .bind(limit)
            .bind(cid)
            .fetch_all(&self.pool)
            .await?)
    }

    pub async fn delete_message_event(&self, room: &str, event_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM messages WHERE room_id = $1 AND event_id = $2").bind(room).bind(event_id).execute(&self.pool).await?;
        Ok(())
    }

    // ── Reactions ───────────────────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_reaction(&self, room: &str, event_id: &str, cid: &str, rumor_id: &str, target: &str, author: &str, key: &str, origin: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO reactions (room_id, event_id, community_id, rumor_id, target_rumor_id, author, key, origin) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING",
        )
        .bind(room)
        .bind(event_id)
        .bind(cid)
        .bind(rumor_id)
        .bind(target)
        .bind(author)
        .bind(key)
        .bind(origin)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn reaction_by_rumor(&self, cid: &str, rumor_id: &str) -> Result<Option<ReactionRow>> {
        Ok(sqlx::query_as("SELECT room_id, event_id, community_id, rumor_id, target_rumor_id, author, key, origin FROM reactions WHERE community_id = $1 AND rumor_id = $2")
            .bind(cid)
            .bind(rumor_id)
            .fetch_optional(&self.pool)
            .await?)
    }

    pub async fn reaction_by_event(&self, room: &str, event_id: &str) -> Result<Option<ReactionRow>> {
        Ok(sqlx::query_as("SELECT room_id, event_id, community_id, rumor_id, target_rumor_id, author, key, origin FROM reactions WHERE room_id = $1 AND event_id = $2")
            .bind(room)
            .bind(event_id)
            .fetch_optional(&self.pool)
            .await?)
    }

    pub async fn delete_reaction(&self, room: &str, event_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM reactions WHERE room_id = $1 AND event_id = $2").bind(room).bind(event_id).execute(&self.pool).await?;
        Ok(())
    }

    // ── Ghosts and puppets ──────────────────────────────────────────────────

    pub async fn ghost(&self, pubkey: &str) -> Result<Option<GhostRow>> {
        Ok(sqlx::query_as("SELECT pubkey, mxid, registered, displayname, avatar_url, avatar_mxc, profile_at FROM ghosts WHERE pubkey = $1")
            .bind(pubkey)
            .fetch_optional(&self.pool)
            .await?)
    }

    pub async fn upsert_ghost(&self, g: &GhostRow) -> Result<()> {
        sqlx::query(
            "INSERT INTO ghosts (pubkey, mxid, registered, displayname, avatar_url, avatar_mxc, profile_at) VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (pubkey) DO UPDATE SET registered = $3, displayname = $4, avatar_url = $5, avatar_mxc = $6, profile_at = $7",
        )
        .bind(&g.pubkey)
        .bind(&g.mxid)
        .bind(g.registered)
        .bind(&g.displayname)
        .bind(&g.avatar_url)
        .bind(&g.avatar_mxc)
        .bind(g.profile_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn puppet_mxid(&self, pubkey: &str) -> Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as("SELECT mxid FROM puppets WHERE pubkey = $1").bind(pubkey).fetch_optional(&self.pool).await?;
        Ok(row.map(|r| r.0))
    }

    pub async fn upsert_puppet(&self, pubkey: &str, mxid: &str) -> Result<()> {
        sqlx::query("INSERT INTO puppets (pubkey, mxid) VALUES ($1, $2) ON CONFLICT DO NOTHING").bind(pubkey).bind(mxid).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn puppet_profile_hash(&self, pubkey: &str) -> Result<Option<String>> {
        let row: Option<(Option<String>,)> = sqlx::query_as("SELECT profile_hash FROM puppets WHERE pubkey = $1").bind(pubkey).fetch_optional(&self.pool).await?;
        Ok(row.and_then(|r| r.0))
    }

    pub async fn set_puppet_profile_hash(&self, pubkey: &str, hash: &str) -> Result<()> {
        sqlx::query("UPDATE puppets SET profile_hash = $2 WHERE pubkey = $1").bind(pubkey).bind(hash).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn puppet_joined(&self, cid: &str, pubkey: &str, epoch: u64) -> Result<bool> {
        let row: Option<(i32,)> = sqlx::query_as("SELECT 1 FROM puppet_joins WHERE community_id = $1 AND pubkey = $2 AND root_epoch = $3")
            .bind(cid)
            .bind(pubkey)
            .bind(epoch as i64)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    pub async fn set_puppet_joined(&self, cid: &str, pubkey: &str, epoch: u64) -> Result<()> {
        sqlx::query("INSERT INTO puppet_joins (community_id, pubkey, root_epoch) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
            .bind(cid)
            .bind(pubkey)
            .bind(epoch as i64)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ── Room membership cache ───────────────────────────────────────────────

    pub async fn is_room_member(&self, room: &str, mxid: &str) -> Result<bool> {
        let row: Option<(i32,)> = sqlx::query_as("SELECT 1 FROM room_members WHERE room_id = $1 AND mxid = $2").bind(room).bind(mxid).fetch_optional(&self.pool).await?;
        Ok(row.is_some())
    }

    pub async fn set_room_member(&self, room: &str, mxid: &str, joined: bool) -> Result<()> {
        if joined {
            sqlx::query("INSERT INTO room_members (room_id, mxid) VALUES ($1, $2) ON CONFLICT DO NOTHING").bind(room).bind(mxid).execute(&self.pool).await?;
        } else {
            sqlx::query("DELETE FROM room_members WHERE room_id = $1 AND mxid = $2").bind(room).bind(mxid).execute(&self.pool).await?;
        }
        Ok(())
    }

    pub async fn room_ghosts(&self, room: &str) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as("SELECT mxid FROM room_members WHERE room_id = $1").bind(room).fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    // ── Cursors, invites, management rooms ──────────────────────────────────

    pub async fn cursor(&self, scope: &str) -> Result<Option<u64>> {
        let row: Option<(Option<i64>,)> = sqlx::query_as("SELECT MIN(newest) FROM cursors WHERE scope = $1").bind(scope).fetch_optional(&self.pool).await?;
        Ok(row.and_then(|r| r.0).map(|n| n as u64))
    }

    pub async fn bump_cursor(&self, scope: &str, relay: &str, newest: u64) -> Result<()> {
        sqlx::query("INSERT INTO cursors (scope, relay, newest) VALUES ($1, $2, $3) ON CONFLICT (scope, relay) DO UPDATE SET newest = GREATEST(cursors.newest, $3)")
            .bind(scope)
            .bind(relay)
            .bind(newest as i64)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn mark_direct_invite(&self, wrap_id: &str, cid: Option<&str>, inviter: Option<&str>) -> Result<bool> {
        let res = sqlx::query("INSERT INTO direct_invites (wrap_id, community_id, inviter) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
            .bind(wrap_id)
            .bind(cid)
            .bind(inviter)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn management_room(&self, room: &str) -> Result<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as("SELECT mxid FROM management_rooms WHERE room_id = $1").bind(room).fetch_optional(&self.pool).await?;
        Ok(row.map(|r| r.0))
    }

    pub async fn set_management_room(&self, room: &str, mxid: &str) -> Result<()> {
        sqlx::query("INSERT INTO management_rooms (room_id, mxid) VALUES ($1, $2) ON CONFLICT (room_id) DO UPDATE SET mxid = $2").bind(room).bind(mxid).execute(&self.pool).await?;
        Ok(())
    }
}
