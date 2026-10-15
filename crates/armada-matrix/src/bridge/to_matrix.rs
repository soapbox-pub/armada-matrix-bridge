//! Armada → Matrix: chat rumors become events sent by the author's ghost.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::Result;
use concord::chat;
use concord::kinds::{self, Plane};
use concord::media::Imeta;
use concord::roles::perm;
use concord::stream::{Opened, check_channel_binding, open_plane_wrap};
use nostr::prelude::{Event, Filter, Kind, PublicKey};
use serde_json::{Value, json};

use super::community::{Community, StreamRoute};
use super::format::{self, Pill};
use super::{ghosts, now_ms};
use crate::db::{MessageRow, PortalRow};
use crate::matrix::As;

/// Open a chat wrap and apply every reader-side rule (binding, retirement
/// cutoff, expiry, banlist). `None` means drop it.
fn open_chat(c: &Community, route: &StreamRoute, event: &Event) -> Option<Opened> {
    let opened = open_plane_wrap(event, &route.key, Plane::Chat).ok()?;
    check_channel_binding(&opened.rumor, &route.channel_id, route.epoch).ok()?;
    // A retired epoch's rotation time is a hard cutoff for writes under it.
    if route.retired_at.is_some_and(|r| opened.rumor.created_at > r) {
        return None;
    }
    if chat::is_expired(&opened.rumor, now_ms() / 1000) || c.folded.banned.contains(opened.author()) {
        return None;
    }
    Some(opened)
}

pub async fn handle(c: &mut Community, event: Event) -> Result<()> {
    let Some(route) = c.routes.get(&event.pubkey.to_hex()).cloned() else { return Ok(()) };
    if c.seen.put(event.id.to_hex(), ()).is_some() {
        return Ok(());
    }
    let Some(opened) = open_chat(c, &route, &event) else { return Ok(()) };
    if opened.author() == c.b.bot_hex() {
        return Ok(());
    }
    if super::commands::is_armada_command(&opened.rumor) {
        return super::commands::armada(c, &opened, &route.channel_id).await;
    }
    if c.status != super::community::Status::Active {
        return Ok(());
    }
    let Some(portal) = c.portals.get(&route.channel_id).filter(|p| p.enabled).cloned() else { return Ok(()) };
    // Our own puppets' messages started on Matrix.
    if c.b.db.puppet_mxid(opened.author()).await?.is_some() {
        return Ok(());
    }
    if c.b.db.has_rumor(&c.id, &opened.rumor.id).await? || c.b.db.reaction_by_rumor(&c.id, &opened.rumor.id).await?.is_some() {
        return Ok(());
    }
    match opened.rumor.kind {
        kinds::MESSAGE | kinds::COMMENT | kinds::POLL => message(c, &portal, &opened).await,
        kinds::REACTION => reaction(c, &portal, &opened).await,
        kinds::EDIT => edit(c, &portal, &opened).await,
        kinds::DELETE => delete(c, &portal, &opened).await,
        kinds::TIMER_NOTICE => timer_notice(c, &portal, &opened).await,
        _ => Ok(()),
    }
}

/// Ephemeral traffic: typing.
pub async fn live(c: &mut Community, event: Event) -> Result<()> {
    if c.status != super::community::Status::Active {
        return Ok(());
    }
    let Some(route) = c.routes.get(&event.pubkey.to_hex()).cloned() else { return Ok(()) };
    let Some(opened) = open_chat(c, &route, &event) else { return Ok(()) };
    if opened.rumor.kind != kinds::TYPING || opened.author() == c.b.bot_hex() {
        return Ok(());
    }
    let Some(portal) = c.portals.get(&route.channel_id).filter(|p| p.enabled) else { return Ok(()) };
    let Ok(pk) = PublicKey::from_hex(opened.author()) else { return Ok(()) };
    let mxid = c.b.ghost_mxid(&pk);
    // Typing alone never pulls a ghost into a room.
    if c.b.db.is_room_member(&portal.room_id, &mxid).await? {
        c.b.mx.typing(&mxid, &portal.room_id, true).await?;
    }
    Ok(())
}

/// The Matrix event that represents a rumor (its first part).
async fn mapped(c: &Community, rumor_id: &str) -> Result<Option<MessageRow>> {
    Ok(c.b.db.messages_by_rumor(&c.id, rumor_id).await?.into_iter().next())
}

async fn pills(c: &Community, content: &str) -> HashMap<PublicKey, Pill> {
    let mut out = HashMap::new();
    for (_, pk) in format::find_mentions(content) {
        let hex = pk.to_hex();
        let pill = if let Ok(Some(mxid)) = c.b.db.puppet_mxid(&hex).await {
            Some(Pill { name: mxid.clone(), mxid })
        } else if let Ok(Some(g)) = c.b.db.ghost(&hex).await {
            Some(Pill { name: g.displayname.unwrap_or_else(|| g.mxid.clone()), mxid: g.mxid })
        } else {
            None
        };
        if let Some(p) = pill {
            out.insert(pk, p);
        }
    }
    out
}

/// NIP-30 custom emoji: `:code:` in the content with an image URL tag.
async fn custom_emoji(c: &mut Community, rumor: &concord::rumor::Rumor) -> Vec<(String, String)> {
    let mut out = vec![];
    for t in rumor.tags_named("emoji") {
        let (Some(code), Some(url)) = (t.get(1), t.get(2)) else { continue };
        let mxc = match c.emoji.get(url) {
            Some(m) => m.clone(),
            None => match super::media::rehost_url(&c.b, url).await {
                Ok(m) => {
                    c.emoji.insert(url.clone(), m.clone());
                    m
                }
                Err(_) => continue,
            },
        };
        out.push((code.clone(), mxc));
    }
    out
}

/// The relation a message carries: an inline reply (`q`) or a thread (1111).
async fn relation(c: &Community, rumor: &concord::rumor::Rumor) -> Result<(Option<Value>, Option<String>)> {
    if let Some(root) = chat::thread_root(rumor) {
        let Some(root_row) = mapped(c, root).await? else { return Ok((None, None)) };
        let thread_root = root_row.thread_root.clone().unwrap_or(root_row.event_id.clone());
        let parent = chat::thread_parent(rumor).filter(|p| *p != root);
        let reply_to = match parent {
            Some(p) => mapped(c, p).await?.map(|r| r.event_id),
            None => None,
        };
        let rel = json!({
            "rel_type": "m.thread",
            "event_id": thread_root,
            "is_falling_back": reply_to.is_none(),
            "m.in_reply_to": { "event_id": reply_to.unwrap_or_else(|| thread_root.clone()) },
        });
        return Ok((Some(rel), Some(thread_root)));
    }
    if let Some(parent) = chat::inline_reply_parent(rumor)
        && let Some(row) = mapped(c, parent).await?
    {
        let mut rel = json!({ "m.in_reply_to": { "event_id": row.event_id } });
        if let Some(root) = &row.thread_root {
            rel = json!({ "rel_type": "m.thread", "event_id": root, "is_falling_back": false, "m.in_reply_to": { "event_id": row.event_id } });
        }
        return Ok((Some(rel), row.thread_root));
    }
    Ok((None, None))
}

async fn message(c: &mut Community, portal: &PortalRow, opened: &Opened) -> Result<()> {
    let rumor = &opened.rumor;
    let pk = PublicKey::from_hex(opened.author())?;
    let ghost = ghosts::ready(c, &pk, &portal.room_id).await?;
    let (relates, thread_root) = relation(c, rumor).await?;
    let expires_at = rumor.tag_value("expiration").and_then(concord::parse_tag_decimal);

    let imetas: Vec<Imeta> = rumor.tags_named("imeta").filter_map(Imeta::parse).collect();
    let mut text = rumor.content.clone();
    for m in &imetas {
        text = text.replace(&m.url, "");
    }
    if let Some(subject) = rumor.tag_value("subject").filter(|s| !s.is_empty()) {
        text = format!("**{subject}**\n\n{text}");
    }
    if rumor.kind == kinds::POLL {
        let options: Vec<String> = rumor.tags_named("option").filter_map(|t| t.get(2)).map(|l| format!("- {l}")).collect();
        text = format!("📊 **Poll:** {text}\n{}\n\n_Vote on Armada._", options.join("\n"));
    }
    let text = text.trim().to_owned();

    let mut parts: Vec<Value> = vec![];
    if !text.is_empty() {
        let pills = pills(c, &text).await;
        let (body, html, mentioned) = format::armada_to_matrix(&text, &|pk| pills.get(pk).map(|p| Pill { mxid: p.mxid.clone(), name: p.name.clone() }));
        let mut html = html;
        let emoji = custom_emoji(c, rumor).await;
        if !emoji.is_empty() {
            let mut h = html.unwrap_or_else(|| body.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('\n', "<br />"));
            for (code, mxc) in emoji {
                h = h.replace(&format!(":{code}:"), &format!("<img data-mx-emoticon src=\"{mxc}\" alt=\":{code}:\" title=\":{code}:\" height=\"32\" />"));
            }
            html = Some(h);
        }
        let mut content = json!({ "msgtype": "m.text", "body": body, "m.mentions": { "user_ids": mentioned } });
        if let Some(html) = html {
            content["format"] = json!("org.matrix.custom.html");
            content["formatted_body"] = json!(html);
        }
        parts.push(content);
    }
    for m in &imetas {
        match super::media::download_imeta(&c.b, m).await {
            Ok(att) => {
                let mxc = c.b.mx.upload(As::user(&ghost), att.bytes.clone(), &att.mime, Some(&att.name)).await?;
                let mut info = json!({ "mimetype": att.mime, "size": att.bytes.len() });
                if let Some((w, h)) = att.dim {
                    info["w"] = json!(w);
                    info["h"] = json!(h);
                }
                if let Some(d) = att.duration {
                    info["duration"] = json!((d * 1000.0) as u64);
                }
                parts.push(json!({
                    "msgtype": super::media::msgtype(&att.mime),
                    "body": att.alt.clone().unwrap_or(att.name.clone()),
                    "filename": att.name,
                    "url": mxc,
                    "info": info,
                }));
            }
            Err(e) => {
                tracing::debug!(url = %m.url, error = %e, "attachment not bridged");
                parts.push(json!({ "msgtype": "m.text", "body": format!("📎 {} (couldn't be bridged)", m.url) }));
            }
        }
    }
    for (i, mut content) in parts.into_iter().enumerate() {
        if let Some(rel) = &relates {
            content["m.relates_to"] = rel.clone();
        }
        let event_id = c.b.mx.send_ts(As::user(&ghost), &portal.room_id, "m.room.message", &content, opened.ms).await?;
        c.b.db
            .insert_message(&portal.room_id, &event_id, &c.id, &portal.channel_id, &rumor.id, i as i32, rumor.kind, opened.author(), "armada", thread_root.as_deref(), expires_at)
            .await?;
    }
    Ok(())
}

pub fn reaction_key(content: &str) -> String {
    match content {
        "+" | "" => "👍".into(),
        "-" => "👎".into(),
        other => other.to_owned(),
    }
}

async fn reaction(c: &mut Community, portal: &PortalRow, opened: &Opened) -> Result<()> {
    let Some(target) = chat::e_target(&opened.rumor) else { return Ok(()) };
    let Some(row) = mapped(c, target).await? else { return Ok(()) };
    let pk = PublicKey::from_hex(opened.author())?;
    let ghost = ghosts::ready(c, &pk, &portal.room_id).await?;
    let key = reaction_key(&opened.rumor.content);
    let content = json!({ "m.relates_to": { "rel_type": "m.annotation", "event_id": row.event_id, "key": key } });
    let event_id = c.b.mx.send_ts(As::user(&ghost), &portal.room_id, "m.reaction", &content, opened.ms).await?;
    c.b.db.insert_reaction(&portal.room_id, &event_id, &c.id, &opened.rumor.id, target, opened.author(), &key, "armada").await?;
    Ok(())
}

async fn edit(c: &mut Community, portal: &PortalRow, opened: &Opened) -> Result<()> {
    let Some(target) = chat::e_target(&opened.rumor) else { return Ok(()) };
    let Some(row) = mapped(c, target).await? else { return Ok(()) };
    // Only the original author may edit (CORD-03 fold rule).
    if row.author != opened.author() {
        return Ok(());
    }
    let pk = PublicKey::from_hex(opened.author())?;
    let ghost = ghosts::ready(c, &pk, &portal.room_id).await?;
    let pills = pills(c, &opened.rumor.content).await;
    let (body, html, mentioned) = format::armada_to_matrix(&opened.rumor.content, &|pk| pills.get(pk).map(|p| Pill { mxid: p.mxid.clone(), name: p.name.clone() }));
    let mut new_content = json!({ "msgtype": "m.text", "body": body, "m.mentions": { "user_ids": mentioned } });
    if let Some(html) = &html {
        new_content["format"] = json!("org.matrix.custom.html");
        new_content["formatted_body"] = json!(html);
    }
    let mut content = json!({
        "msgtype": "m.text",
        "body": format!("* {}", new_content["body"].as_str().unwrap_or("")),
        "m.new_content": new_content,
        "m.relates_to": { "rel_type": "m.replace", "event_id": row.event_id },
        "m.mentions": {},
    });
    if let Some(html) = html {
        content["format"] = json!("org.matrix.custom.html");
        content["formatted_body"] = json!(format!("* {html}"));
    }
    let event_id = c.b.mx.send_ts(As::user(&ghost), &portal.room_id, "m.room.message", &content, opened.ms).await?;
    c.b.db.insert_message(&portal.room_id, &event_id, &c.id, &portal.channel_id, &opened.rumor.id, 0, kinds::EDIT, opened.author(), "armada", None, None).await?;
    Ok(())
}

async fn delete(c: &mut Community, portal: &PortalRow, opened: &Opened) -> Result<()> {
    let deleter = opened.author();
    let citation = concord::edition::Citation::from_tags(&opened.rumor.tags);
    for t in opened.rumor.tags_named("e") {
        let Some(target) = t.get(1) else { continue };
        if let Some(r) = c.b.db.reaction_by_rumor(&c.id, target).await? {
            if r.author == deleter {
                let pk = PublicKey::from_hex(deleter)?;
                c.b.mx.redact(As::user(&c.b.ghost_mxid(&pk)), &r.room_id, &r.event_id, None).await?;
                c.b.db.delete_reaction(&r.room_id, &r.event_id).await?;
            }
            continue;
        }
        let rows = c.b.db.messages_by_rumor(&c.id, target).await?;
        let Some(first) = rows.first() else { continue };
        let f = &c.folded;
        let actor = if first.author == deleter {
            c.b.ghost_mxid(&PublicKey::from_hex(deleter)?)
        } else if f.roster.can_act_on_member(deleter, &f.owner, &first.author, perm::MANAGE_MESSAGES)
            && f.citation_satisfied(&c.id_bytes, deleter, citation.as_ref())
        {
            c.b.bot_mxid.clone()
        } else {
            continue;
        };
        let reason = (actor == c.b.bot_mxid).then_some("Deleted by a moderator on Armada");
        for row in rows.iter().filter(|r| r.room_id == portal.room_id) {
            c.b.mx.redact(As::user(&actor), &row.room_id, &row.event_id, reason).await?;
        }
        c.b.db.delete_messages_by_rumor(&c.id, target).await?;
    }
    Ok(())
}

async fn timer_notice(c: &mut Community, portal: &PortalRow, opened: &Opened) -> Result<()> {
    if !c.folded.roster.is_authorized(opened.author(), &c.folded.owner, perm::MANAGE_METADATA) {
        return Ok(());
    }
    let Some(secs) = opened.rumor.tag_value("timer").and_then(concord::parse_tag_decimal) else { return Ok(()) };
    let text = if secs == 0 {
        "Disappearing messages were turned off on Armada.".to_owned()
    } else {
        format!("Disappearing messages are on: new messages disappear after {}. The bridge redacts them here too.", human_duration(secs))
    };
    c.b.notice(&portal.room_id, &text).await;
    Ok(())
}

fn human_duration(secs: u64) -> String {
    let (n, unit) = match secs {
        s if s % 86_400 == 0 => (s / 86_400, "day"),
        s if s % 3600 == 0 => (s / 3600, "hour"),
        s if s % 60 == 0 => (s / 60, "minute"),
        s => (s, "second"),
    };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

/// Redact Matrix copies of messages whose Armada timer ran out (CORD-08).
pub async fn expire(c: &mut Community) -> Result<()> {
    for row in c.b.db.expired_messages(&c.id, now_ms() / 1000, 100).await? {
        let _ = c.b.mx.redact(As::BOT, &row.room_id, &row.event_id, Some("Disappeared on Armada")).await;
        c.b.db.delete_message_event(&row.room_id, &row.event_id).await?;
    }
    Ok(())
}

/// Bring recent history into a newly created portal.
pub async fn backfill(c: &mut Community, channel_id: &str) -> Result<()> {
    let limit = c.b.config.bridge.backfill_messages;
    if limit == 0 {
        return Ok(());
    }
    let Some(ch) = c.channel(channel_id) else { return Ok(()) };
    let authors: Vec<PublicKey> = ch.streams.iter().map(|s| s.key.pubkey()).collect();
    let filter = Filter::new().kind(Kind::Custom(kinds::WRAP)).authors(authors).limit(limit * 3);
    let mut events = c.b.pool.query(&c.relays(), vec![filter], Duration::from_secs(10)).await;
    events.sort_by_key(|e| e.created_at);
    // Keep the newest `limit` visible messages plus whatever refers to them.
    let mut visible = 0usize;
    let mut keep_from = 0;
    for (i, e) in events.iter().enumerate().rev() {
        let Some(route) = c.routes.get(&e.pubkey.to_hex()) else { continue };
        if let Some(o) = open_chat(c, route, e)
            && chat::is_visible_kind(o.rumor.kind)
        {
            visible += 1;
            if visible >= limit {
                keep_from = i;
                break;
            }
        }
    }
    for event in events.into_iter().skip(keep_from) {
        if let Err(e) = handle(c, event).await {
            tracing::debug!(error = %e, "backfill event failed");
        }
    }
    Ok(())
}
