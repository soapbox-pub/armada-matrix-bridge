//! Matrix → Armada: events in portal rooms become rumors sealed by the sender's
//! puppet — an Armada key derived from their MXID — and wrapped at the channel's
//! current stream.

use anyhow::{Context, Result};
use concord::chat::{self, Binding, Target};
use concord::kinds::{self, Plane};
use concord::stream::WrapOptions;
use nostr::prelude::{Keys, PublicKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::community::Community;
use super::{format, now_ms};
use crate::config::Permission;
use crate::db::{MessageRow, PortalRow};

fn proxy_tag(c: &Community, room: &str, event_id: &str) -> Vec<String> {
    let url = format!("https://matrix.to/#/{room}/{event_id}?via={}", c.b.config.homeserver.server_name);
    vec!["proxy".into(), url, "web".into()]
}

/// The puppet for a Matrix user, joined to the community at the current epoch
/// and with a current profile.
async fn puppet(c: &Community, mxid: &str) -> Result<Keys> {
    let keys = c.b.keys.puppet(mxid);
    let hex = keys.public_key().to_hex();
    c.b.db.upsert_puppet(&hex, mxid).await?;

    let profile = c.b.mx.profile(mxid).await.unwrap_or_default();
    let name = profile.get("displayname").and_then(Value::as_str).unwrap_or(mxid).to_owned();
    let avatar = profile.get("avatar_url").and_then(Value::as_str).map(str::to_owned);
    let hash = hex::encode(Sha256::digest(format!("{name}\0{}", avatar.as_deref().unwrap_or("")).as_bytes()));
    if c.b.db.puppet_profile_hash(&hex).await?.as_deref() != Some(hash.as_str()) {
        let mut metadata = json!({
            "name": format!("{name}{}", c.b.config.bridge.puppet_name_suffix),
            "about": format!("Bridged from Matrix ({}).", c.b.config.homeserver.server_name),
        });
        if let Some(mxc) = &avatar {
            match c.b.mx.download(mxc, 5 * 1024 * 1024).await {
                Ok((bytes, _)) => match super::media::upload_blob(&c.b, &keys, bytes).await {
                    Ok(url) => metadata["picture"] = json!(url),
                    Err(e) => tracing::debug!(%mxid, error = %e, "could not upload avatar to Blossom"),
                },
                Err(e) => tracing::debug!(%mxid, error = %e, "could not download avatar"),
            }
        }
        let event = nostr::event::FinalizeEvent::finalize(
            nostr::prelude::UnsignedEvent::new(keys.public_key(), nostr::prelude::Timestamp::now(), nostr::prelude::Kind::Metadata, [], metadata.to_string()),
            &keys,
        )?;
        let mut relays = c.b.relays();
        relays.extend(c.relays());
        let res = c.b.pool.publish(&relays, &event, std::time::Duration::from_secs(10)).await;
        if !res.accepted.is_empty() {
            c.b.db.set_puppet_profile_hash(&hex, &hash).await?;
        }
    }

    if !c.b.db.puppet_joined(&c.id, &hex, c.m.root_epoch).await? {
        let join = concord::guestbook::join(&hex, now_ms(), None);
        c.publish(&join, Plane::Guestbook, &c.m.current_guestbook_stream(), &keys, WrapOptions::default()).await.context("puppet Join")?;
        c.b.db.set_puppet_joined(&c.id, &hex, c.m.root_epoch).await?;
    }
    Ok(keys)
}

/// Who a pill should mention on Armada: a ghost's own key, or a Matrix user's puppet.
fn mention_key(c: &Community, mxid: &str) -> Option<PublicKey> {
    c.b.ghost_pubkey(mxid).or_else(|| (mxid != c.b.bot_mxid).then(|| c.b.keys.puppet(mxid).public_key()))
}

pub async fn handle(c: &mut Community, event: Value) -> Result<()> {
    let room = event["room_id"].as_str().unwrap_or_default().to_owned();
    let sender = event["sender"].as_str().unwrap_or_default().to_owned();
    let Some(portal) = c.portal_for_room(&room).filter(|p| p.enabled).cloned() else { return Ok(()) };
    if c.b.permission(&sender) < Permission::User || c.dissolved || c.m.excluded_at.is_some() {
        return Ok(());
    }
    match event["type"].as_str().unwrap_or_default() {
        "m.room.message" if event["content"]["m.relates_to"]["rel_type"] == "m.replace" => edit(c, &portal, &sender, &event).await,
        "m.room.message" | "m.sticker" => message(c, &portal, &sender, &event).await,
        "m.reaction" => reaction(c, &portal, &sender, &event).await,
        "m.room.redaction" => redaction(c, &portal, &sender, &event).await,
        "m.room.encrypted" => {
            if c.seen.put(format!("encrypted:{room}"), ()).is_none() {
                c.b.notice(&room, "This room is encrypted, but end-to-end encryption isn't enabled on this bridge, so messages here can't reach Armada.").await;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn binding<'a>(c: &'a Community, portal: &'a PortalRow) -> Result<(Binding<'a>, concord::stream::StreamKey)> {
    let ch = c.channel(&portal.channel_id).context("channel is not readable")?;
    let current = ch.current();
    Ok((Binding { channel_id_hex: &portal.channel_id, epoch: current.epoch }, (&current.key).into()))
}

async fn row_for(c: &Community, room: &str, event_id: &str) -> Result<Option<MessageRow>> {
    c.b.db.message_by_event(room, event_id).await
}

async fn message(c: &mut Community, portal: &PortalRow, sender: &str, event: &Value) -> Result<()> {
    let room = &portal.room_id;
    let event_id = event["event_id"].as_str().unwrap_or_default();
    let content = &event["content"];
    let msgtype = if event["type"] == "m.sticker" { "m.image" } else { content["msgtype"].as_str().unwrap_or("m.text") };
    let keys = puppet(c, sender).await?;
    let author = keys.public_key().to_hex();

    let relates = &content["m.relates_to"];
    let reply_to = relates["m.in_reply_to"]["event_id"].as_str();
    let thread_root_event = (relates["rel_type"] == "m.thread").then(|| relates["event_id"].as_str()).flatten();

    // Text, with Matrix pills turned into nostr: mentions.
    let body = content["body"].as_str().unwrap_or_default();
    let html = (content["format"] == "org.matrix.custom.html").then(|| content["formatted_body"].as_str()).flatten();
    let (mut text, mentioned) = match msgtype {
        "m.text" | "m.notice" | "m.emote" => format::matrix_to_armada(body, html, reply_to.is_some(), &|m| mention_key(c, m)),
        // A media body is a filename unless a caption was given (`filename` set).
        _ => (content["filename"].as_str().filter(|f| *f != body).map(|_| body.to_owned()).unwrap_or_default(), vec![]),
    };
    if msgtype == "m.emote" {
        text = format!("* {text}");
    }

    let mut extra: Vec<Vec<String>> = mentioned.iter().map(|pk| vec!["p".to_string(), pk.to_hex()]).collect();
    extra.push(proxy_tag(c, room, event_id));

    if matches!(msgtype, "m.image" | "m.video" | "m.audio" | "m.file") {
        let info = &content["info"];
        let mime = info["mimetype"].as_str().unwrap_or("application/octet-stream").to_owned();
        let bytes = if let Some(mxc) = content["url"].as_str() {
            c.b.mx.download(mxc, c.b.config.bridge.max_media_bytes).await?.0
        } else if content["file"].is_object() {
            super::crypto::download_encrypted(&c.b, &content["file"]).await?
        } else {
            anyhow::bail!("media event without a url");
        };
        let dim = info["w"].as_u64().zip(info["h"].as_u64()).map(|(w, h)| (w as u32, h as u32));
        let imeta = super::media::upload_attachment(&c.b, &keys, &bytes, &mime, dim, None).await?;
        text = if text.is_empty() { imeta.url.clone() } else { format!("{text}\n{}", imeta.url) };
        extra.push(imeta.to_tag());
    }
    if text.trim().is_empty() {
        return Ok(());
    }

    // A Matrix thread is a NIP-22 thread; a plain reply is a NIP-C7 quote.
    let thread = match thread_root_event {
        Some(root) => row_for(c, room, root).await?,
        None => None,
    };
    let reply_row = match reply_to.filter(|_| relates["is_falling_back"] != true) {
        Some(r) => row_for(c, room, r).await?,
        None => None,
    };
    let (b, stream) = binding(c, portal)?;
    let rumor = match &thread {
        Some(root) => {
            let parent = reply_row.as_ref().filter(|r| r.rumor_id != root.rumor_id);
            let root_tags = vec![
                vec!["K".to_string(), root.kind.to_string()],
                vec!["E".to_string(), root.rumor_id.clone(), String::new(), root.author.clone()],
                vec!["P".to_string(), root.author.clone()],
            ];
            let target = match parent {
                Some(p) => Target { id: &p.rumor_id, kind: p.kind as u16, author: &p.author, tags: &root_tags },
                None => Target { id: &root.rumor_id, kind: root.kind as u16, author: &root.author, tags: &[] },
            };
            chat::message(&b, &author, text, Some(&target), None, extra, now_ms(), c.timer_secs())
        }
        None => {
            let quote = reply_row.as_ref().map(|r| Target { id: &r.rumor_id, kind: r.kind as u16, author: &r.author, tags: &[] });
            chat::message(&b, &author, text, None, quote.as_ref(), extra, now_ms(), c.timer_secs())
        }
    };
    let expiration = rumor.tag_value("expiration").and_then(concord::parse_tag_decimal);
    c.publish(&rumor, Plane::Chat, &stream, &keys, WrapOptions { expiration, ..Default::default() }).await?;
    let thread_root = thread.map(|t| t.thread_root.unwrap_or(t.event_id));
    c.b.db
        .insert_message(room, event_id, &c.id, &portal.channel_id, &rumor.id, 0, rumor.kind, &author, "matrix", thread_root.as_deref(), expiration)
        .await?;
    Ok(())
}

async fn edit(c: &mut Community, portal: &PortalRow, sender: &str, event: &Value) -> Result<()> {
    let content = &event["content"];
    let Some(target) = content["m.relates_to"]["event_id"].as_str() else { return Ok(()) };
    let keys = c.b.keys.puppet(sender);
    let author = keys.public_key().to_hex();
    let Some(row) = row_for(c, &portal.room_id, target).await? else { return Ok(()) };
    if row.origin != "matrix" || row.author != author {
        return Ok(());
    }
    let new = &content["m.new_content"];
    let html = (new["format"] == "org.matrix.custom.html").then(|| new["formatted_body"].as_str()).flatten();
    let (text, mentioned) = format::matrix_to_armada(new["body"].as_str().unwrap_or_default(), html, false, &|m| mention_key(c, m));
    let mut extra: Vec<Vec<String>> = mentioned.iter().map(|pk| vec!["p".to_string(), pk.to_hex()]).collect();
    extra.push(proxy_tag(c, &portal.room_id, event["event_id"].as_str().unwrap_or_default()));
    let (b, stream) = binding(c, portal)?;
    let expiration = row.expires_at.map(|e| e as u64);
    let rumor = chat::edit(&b, &author, &row.rumor_id, text, extra, now_ms(), expiration);
    c.publish(&rumor, Plane::Chat, &stream, &keys, WrapOptions { expiration, ..Default::default() }).await?;
    Ok(())
}

async fn reaction(c: &mut Community, portal: &PortalRow, sender: &str, event: &Value) -> Result<()> {
    let rel = &event["content"]["m.relates_to"];
    let (Some(target), Some(key)) = (rel["event_id"].as_str(), rel["key"].as_str()) else { return Ok(()) };
    let Some(row) = row_for(c, &portal.room_id, target).await? else { return Ok(()) };
    let keys = puppet(c, sender).await?;
    let author = keys.public_key().to_hex();
    let (b, stream) = binding(c, portal)?;
    let t = Target { id: &row.rumor_id, kind: row.kind as u16, author: &row.author, tags: &[] };
    let rumor = chat::reaction(&b, &author, &t, key, vec![], now_ms(), c.timer_secs());
    let expiration = rumor.tag_value("expiration").and_then(concord::parse_tag_decimal);
    c.publish(&rumor, Plane::Chat, &stream, &keys, WrapOptions { expiration, ..Default::default() }).await?;
    let event_id = event["event_id"].as_str().unwrap_or_default();
    c.b.db.insert_reaction(&portal.room_id, event_id, &c.id, &rumor.id, &row.rumor_id, &author, key, "matrix").await?;
    Ok(())
}

async fn redaction(c: &mut Community, portal: &PortalRow, sender: &str, event: &Value) -> Result<()> {
    // Room v11 moved `redacts` into content.
    let Some(target) = event["content"]["redacts"].as_str().or(event["redacts"].as_str()) else { return Ok(()) };
    let author = c.b.keys.puppet(sender).public_key().to_hex();
    let (rumor_id, kind) = if let Some(r) = c.b.db.reaction_by_event(&portal.room_id, target).await? {
        if r.origin != "matrix" || r.author != author {
            return Ok(());
        }
        c.b.db.delete_reaction(&portal.room_id, target).await?;
        (r.rumor_id, kinds::REACTION)
    } else if let Some(row) = row_for(c, &portal.room_id, target).await? {
        // Only the author's own redaction deletes on Armada; Matrix moderators
        // have no authority over Armada history.
        if row.origin != "matrix" || row.author != author {
            return Ok(());
        }
        c.b.db.delete_messages_by_rumor(&c.id, &row.rumor_id).await?;
        (row.rumor_id, row.kind as u16)
    } else {
        return Ok(());
    };
    let keys = c.b.keys.puppet(sender);
    let (b, stream) = binding(c, portal)?;
    let rumor = chat::delete(&b, &author, &rumor_id, kind, now_ms());
    c.publish(&rumor, Plane::Chat, &stream, &keys, WrapOptions::default()).await?;
    Ok(())
}

/// Matrix typing → an ephemeral Armada typing signal, at most every 4 s per user.
pub async fn typing(c: &mut Community, room: &str, user: &str) -> Result<()> {
    let Some(portal) = c.portal_for_room(room).filter(|p| p.enabled).cloned() else { return Ok(()) };
    if c.b.permission(user) < Permission::User {
        return Ok(());
    }
    let now = std::time::Instant::now();
    if c.typing_sent.get(user).is_some_and(|t| now.duration_since(*t).as_secs() < 4) {
        return Ok(());
    }
    let keys = c.b.keys.puppet(user);
    let author = keys.public_key().to_hex();
    // Typing never makes someone a member; only speaking does.
    if !c.b.db.puppet_joined(&c.id, &author, c.m.root_epoch).await? {
        return Ok(());
    }
    c.typing_sent.insert(user.to_owned(), now);
    let (b, stream) = binding(c, &portal)?;
    let rumor = chat::typing(&b, &author, now_ms());
    c.publish(&rumor, Plane::Chat, &stream, &keys, WrapOptions { ephemeral: true, expiration: None }).await?;
    Ok(())
}
