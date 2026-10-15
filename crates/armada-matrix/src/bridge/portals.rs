//! The Matrix side of a community: one space, one portal room per bridged
//! channel. Armada's Control Plane is the authority for names, topics, ordering
//! and which channels exist; this module makes Matrix follow it.

use std::time::Duration;

use anyhow::{Context, Result};
use concord::community::ChannelView;
use serde_json::{Value, json};

use super::community::Community;
use crate::db::PortalRow;
use crate::matrix::As;

fn power_levels(c: &Community) -> Value {
    let mut users = serde_json::Map::new();
    users.insert(c.b.bot_mxid.clone(), json!(100));
    if c.requested_by.starts_with('@') {
        users.insert(c.requested_by.clone(), json!(100));
    }
    json!({
        "users": users,
        "events": {
            // Armada owns these; Matrix changes would be overwritten.
            "m.room.name": 100, "m.room.topic": 100, "m.room.avatar": 100,
            "m.space.child": 100, "m.space.parent": 100,
            "m.room.encryption": 50, "m.room.power_levels": 100,
        },
        "invite": 0,
    })
}

async fn space_avatar(c: &Community) -> Option<String> {
    let icon = c.folded.metadata.as_ref()?.icon.as_ref()?;
    let (blob, _) = super::media::fetch(&c.b, &icon.url, 5 * 1024 * 1024).await.ok()?;
    let plain = concord::media::decrypt_pointer(&blob, &icon.key, &icon.nonce)?;
    if !concord::media::sha256_hex(&plain).eq_ignore_ascii_case(&icon.hash) {
        return None;
    }
    c.b.mx.upload(As::BOT, plain, "image/png", None).await.ok()
}

async fn ensure_space(c: &mut Community) -> Result<String> {
    if let Some(space) = &c.space {
        return Ok(space.clone());
    }
    let mut initial_state = vec![json!({ "type": "m.room.history_visibility", "state_key": "", "content": { "history_visibility": "shared" } })];
    if let Some(avatar) = space_avatar(c).await {
        initial_state.push(json!({ "type": "m.room.avatar", "state_key": "", "content": { "url": avatar } }));
    }
    let topic = c.folded.metadata.as_ref().and_then(|m| m.description.clone()).unwrap_or_default();
    let space = c
        .b
        .mx
        .create_room(
            As::BOT,
            &json!({
                "name": c.name(),
                "topic": topic,
                "creation_content": { "type": "m.space" },
                "preset": "private_chat",
                "visibility": "private",
                "power_level_content_override": power_levels(c),
                "initial_state": initial_state,
            }),
        )
        .await?;
    c.b.db.set_space(&c.id, &space).await?;
    c.b.register_room(&space, &c.id).await;
    c.space = Some(space.clone());
    if c.requested_by.starts_with('@') {
        c.b.mx.invite(As::BOT, &space, &c.requested_by).await?;
    }
    Ok(space)
}

fn child_order(ch: &ChannelView, index: usize) -> String {
    // Spaces order children by `order` lexicographically.
    format!("{:06}", ch.position.map(|p| p.max(0.0) as usize).unwrap_or(10_000 + index))
}

fn room_topic(c: &Community, ch: &ChannelView) -> String {
    let mut topic = format!("#{} in {} on Armada, bridged.", ch.name, c.name());
    if ch.private {
        topic.push_str(" This is a private channel; its messages are visible to everyone in this room.");
    }
    topic
}

async fn create_portal(c: &mut Community, space: &str, ch: &ChannelView, index: usize) -> Result<PortalRow> {
    let server = c.b.config.homeserver.server_name.clone();
    let encrypted = c.b.config.encryption.enabled && c.b.config.encryption.default;
    let mut initial_state = vec![
        json!({ "type": "m.space.parent", "state_key": space, "content": { "via": [server], "canonical": true } }),
        json!({ "type": "m.room.join_rules", "state_key": "", "content": {
            "join_rule": "restricted", "allow": [{ "type": "m.room_membership", "room_id": space }],
        } }),
        json!({ "type": "m.room.history_visibility", "state_key": "", "content": { "history_visibility": "shared" } }),
    ];
    if encrypted {
        initial_state.push(json!({ "type": "m.room.encryption", "state_key": "", "content": { "algorithm": "m.megolm.v1.aes-sha2" } }));
    }
    let room = c
        .b
        .mx
        .create_room(
            As::BOT,
            &json!({
                "name": ch.name,
                "topic": room_topic(c, ch),
                "preset": "private_chat",
                "visibility": "private",
                "power_level_content_override": power_levels(c),
                "initial_state": initial_state,
            }),
        )
        .await?;
    c.b.mx.set_state(As::BOT, space, "m.space.child", &room, &json!({ "via": [c.b.config.homeserver.server_name], "order": child_order(ch, index) })).await?;
    c.b.db.insert_portal(&c.id, &ch.id_hex, &room, encrypted, &ch.name).await?;
    c.b.db.set_room_member(&room, &c.b.bot_mxid, true).await?;
    c.b.register_room(&room, &c.id).await;
    if c.requested_by.starts_with('@') {
        let _ = c.b.mx.invite(As::BOT, &room, &c.requested_by).await;
    }
    Ok(PortalRow { community_id: c.id.clone(), channel_id: ch.id_hex.clone(), room_id: room, enabled: true, encrypted, name: ch.name.clone() })
}

/// Bring the space and portals in line with the folded Control Plane.
pub async fn reconcile(c: &mut Community) -> Result<()> {
    let space = ensure_space(c).await?;

    let meta_key = format!("space-meta:{}:{}", c.name(), c.folded.metadata.as_ref().and_then(|m| m.description.clone()).unwrap_or_default());
    if c.seen.put(meta_key, ()).is_none() {
        let _ = c.b.mx.set_state(As::BOT, &space, "m.room.name", "", &json!({ "name": c.name() })).await;
        if let Some(desc) = c.folded.metadata.as_ref().and_then(|m| m.description.clone()) {
            let _ = c.b.mx.set_state(As::BOT, &space, "m.room.topic", "", &json!({ "topic": desc })).await;
        }
    }

    let channels = c.channels.clone();
    let mut created = vec![];
    for (index, ch) in channels.iter().enumerate() {
        let enabled = c.channel_enabled(ch);
        match c.portals.get(&ch.id_hex).cloned() {
            None if enabled => {
                let portal = create_portal(c, &space, ch, index).await.with_context(|| format!("creating a room for #{}", ch.name))?;
                c.portals.insert(ch.id_hex.clone(), portal);
                created.push(ch.id_hex.clone());
            }
            None => {}
            Some(p) => {
                if p.name != ch.name {
                    c.b.mx.set_state(As::BOT, &p.room_id, "m.room.name", "", &json!({ "name": ch.name })).await?;
                    c.b.mx.set_state(As::BOT, &p.room_id, "m.room.topic", "", &json!({ "topic": room_topic(c, ch) })).await?;
                }
                if p.enabled != enabled {
                    let note = if enabled { "An Armada admin included this channel; messages are bridged again." } else { "An Armada admin excluded this channel; messages are no longer bridged." };
                    c.b.notice(&p.room_id, note).await;
                }
                if p.name != ch.name || p.enabled != enabled {
                    c.b.db.update_portal(&p.room_id, enabled, &ch.name).await?;
                    let entry = c.portals.get_mut(&ch.id_hex).unwrap();
                    entry.name = ch.name.clone();
                    entry.enabled = enabled;
                }
            }
        }
    }

    // Channels that vanished (deleted, or a private channel whose key we lost).
    let live: std::collections::HashSet<&str> = channels.iter().map(|c| c.id_hex.as_str()).collect();
    let gone: Vec<PortalRow> = c.portals.values().filter(|p| p.enabled && !live.contains(p.channel_id.as_str())).cloned().collect();
    for p in gone {
        let why = if c.folded.channels.get(&p.channel_id).is_some_and(|f| f.deleted) {
            "This channel was deleted on Armada."
        } else {
            "The bridge can no longer read this channel on Armada."
        };
        c.b.notice(&p.room_id, why).await;
        c.b.db.update_portal(&p.room_id, false, &p.name).await?;
        c.portals.get_mut(&p.channel_id).unwrap().enabled = false;
        let _ = c.b.mx.set_state(As::BOT, &space, "m.space.child", &p.room_id, &json!({})).await;
    }

    for channel in created {
        if let Err(e) = super::to_matrix::backfill(c, &channel).await {
            tracing::warn!(community = %c.id, %channel, error = %e, "backfill failed");
        }
    }
    Ok(())
}

/// Invite a Matrix user to the space and every portal.
pub async fn invite_user(c: &Community, space: &str, mxid: &str) -> Result<()> {
    c.b.mx.invite(As::BOT, space, mxid).await?;
    for p in c.portals.values().filter(|p| p.enabled) {
        c.b.mx.invite(As::BOT, &p.room_id, mxid).await?;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(())
}
