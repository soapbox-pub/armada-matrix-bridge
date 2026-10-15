//! Ghosts: Armada members as Matrix users. Registered on first use, named and
//! pictured from their kind 0 profile, and joined to a portal before they speak.

use std::time::Duration;

use anyhow::Result;
use nostr::nips::nip19::ToBech32;
use nostr::prelude::{Filter, Kind, PublicKey};
use serde_json::Value;

use super::Bridge;
use super::community::Community;
use crate::db::GhostRow;
use crate::matrix::As;

const PROFILE_TTL_SECS: i64 = 6 * 60 * 60;

pub struct Profile {
    pub name: Option<String>,
    pub picture: Option<String>,
}

/// The newest kind 0 for `pk` from the bridge's and the community's relays.
pub async fn fetch_profile(b: &Bridge, pk: &PublicKey, extra_relays: &[String]) -> Option<Profile> {
    let mut relays = b.relays();
    relays.extend(extra_relays.iter().cloned());
    relays.dedup();
    let events = b.pool.query(&relays, vec![Filter::new().kind(Kind::Metadata).author(*pk).limit(1)], Duration::from_secs(4)).await;
    let newest = events.into_iter().filter(|e| e.verify().is_ok()).max_by_key(|e| e.created_at)?;
    let v: Value = serde_json::from_str(&newest.content).ok()?;
    let pick = |k: &str| v.get(k).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned);
    Some(Profile { name: pick("display_name").or_else(|| pick("name")), picture: pick("picture") })
}

fn fallback_name(pk: &PublicKey) -> String {
    let npub = pk.to_bech32().unwrap_or_default();
    format!("{}…", &npub[..12.min(npub.len())])
}

/// Register the ghost if needed and keep its profile fresh. Returns its MXID.
pub async fn ensure(b: &Bridge, pk: &PublicKey, relays: &[String]) -> Result<String> {
    let hex = pk.to_hex();
    let mxid = b.ghost_mxid(pk);
    let mut row = b.db.ghost(&hex).await?.unwrap_or(GhostRow {
        pubkey: hex.clone(),
        mxid: mxid.clone(),
        registered: false,
        displayname: None,
        avatar_url: None,
        avatar_mxc: None,
        profile_at: 0,
    });
    if !row.registered {
        let localpart = mxid.trim_start_matches('@').split(':').next().unwrap_or_default();
        b.mx.register(localpart).await?;
        row.registered = true;
    }
    let now = (super::now_ms() / 1000) as i64;
    if now - row.profile_at > PROFILE_TTL_SECS {
        let profile = fetch_profile(b, pk, relays).await;
        let name = format!("{}{}", profile.as_ref().and_then(|p| p.name.clone()).unwrap_or_else(|| fallback_name(pk)), b.config.bridge.ghost_name_suffix);
        if row.displayname.as_deref() != Some(name.as_str()) {
            b.mx.set_displayname(&mxid, &name).await?;
            row.displayname = Some(name);
        }
        let picture = profile.and_then(|p| p.picture);
        if picture.is_some() && picture != row.avatar_url {
            match super::media::rehost_url(b, picture.as_deref().unwrap()).await {
                Ok(mxc) => {
                    b.mx.set_avatar(&mxid, &mxc).await?;
                    row.avatar_mxc = Some(mxc);
                    row.avatar_url = picture;
                }
                Err(e) => tracing::debug!(%mxid, error = %e, "could not rehost avatar"),
            }
        }
        row.profile_at = now;
    }
    b.db.upsert_ghost(&row).await?;
    Ok(mxid)
}

/// Make sure a bridge-owned user is joined to a room (portals are invite-only,
/// so the bot invites first).
pub async fn ensure_in_room(b: &Bridge, mxid: &str, room: &str) -> Result<()> {
    if b.db.is_room_member(room, mxid).await? {
        return Ok(());
    }
    b.mx.invite(As::BOT, room, mxid).await?;
    b.mx.join(mxid, room).await?;
    b.db.set_room_member(room, mxid, true).await?;
    Ok(())
}

/// Ensure the ghost exists and is in `room`; returns its MXID.
pub async fn ready(c: &Community, pk: &PublicKey, room: &str) -> Result<String> {
    let mxid = ensure(&c.b, pk, &c.relays()).await?;
    ensure_in_room(&c.b, &mxid, room).await?;
    Ok(mxid)
}

/// Kick a ghost out of every portal (a kick or ban on Armada).
pub async fn remove_from_portals(c: &Community, pk: &PublicKey, reason: &str) {
    let mxid = c.b.ghost_mxid(pk);
    for p in c.portals.values() {
        if c.b.db.is_room_member(&p.room_id, &mxid).await.unwrap_or(false) {
            let _ = c.b.mx.kick(As::BOT, &p.room_id, &mxid, reason).await;
            let _ = c.b.db.set_room_member(&p.room_id, &mxid, false).await;
        }
    }
}
