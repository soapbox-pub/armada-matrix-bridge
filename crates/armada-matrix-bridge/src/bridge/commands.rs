//! Commands. Matrix room moderators link their rooms to Armada channels with
//! `!armada link` in the room and `/bridge link <code>` in the channel. Matrix
//! users also bridge whole communities as spaces and manage them in a DM with
//! the bot; the operator manages any of them over the control socket; Armada
//! admins approve, revoke and scope bridges with `/bridge …` in any channel.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use concord::invite::{parse_bundle_event, parse_invite_link};
use concord::kinds;
use concord::roles::perm;
use concord::rumor::Rumor;
use concord::stream::Opened;
use nostr::nips::nip19::ToBech32;
use nostr::prelude::{Filter, Kind, PublicKey};
use serde_json::Value;

use super::community::{self, Command, Community, Msg, Status};
use super::{Bridge, now_ms};
use crate::config::Permission;
use crate::matrix::As;
use crate::matrix::client::enc;

/// Requests nobody approves on Armada are dropped after this many days.
pub const PENDING_DAYS: i32 = 7;
/// Unapproved requests one Matrix user may have open at once.
const MAX_PENDING: i64 = 3;
const NOT_ALLOWED: &str = "this bridge only bridges new communities for approved users; ask its operator for access";
/// How long a link code from `!armada link` stays valid.
const LINK_CODE_HOURS: u32 = 24;
pub const LINK_HOWTO: &str = "To link a channel, a moderator of a Matrix room sends `!armada link` there, and someone who can manage channels posts the code it gives in the channel with `/bridge link <code>`.";

/// Who is issuing a command.
pub enum Who {
    /// Someone on the host, over the control socket.
    Operator,
    Matrix(String),
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Access {
    None,
    /// In the community's space: may see it and invite people.
    Member,
    /// Bridged it, or holds power level 100 in its space: may also unbridge it.
    Manager,
}

pub fn welcome(b: &Bridge) -> String {
    format!(
        "Hi! I bridge [Armada](https://armada.buzz) communities to Matrix. My Armada identity is `{}`.\n\n{}",
        b.bot_npub(),
        help(b)
    )
}

/// Said when invited to a room that isn't a DM.
pub fn room_welcome(b: &Bridge) -> String {
    format!(
        "Hi! I bridge [Armada](https://armada.buzz) channels to Matrix. To link this room to one, a moderator sends `{}link` here.",
        prefix(b)
    )
}

fn prefix(b: &Bridge) -> String {
    format!("{} ", b.config.bridge.command_prefix)
}

fn help(b: &Bridge) -> String {
    let p = &b.config.bridge.command_prefix;
    format!(
        "To link a Matrix room to an Armada channel, invite me to the room and send `{p} link` there.\n\n\
         Commands here (the `{p}` prefix is optional):\n\
         - `list` — bridged communities you're in\n\
         - `status <community>` — one community's state\n\
         - `invite <community> <@user:server>` — invite someone to its Matrix space\n\
         - `unbridge <community>` — stop bridging a community you bridged or administer\n\n\
         `<community>` is the start of its id or its name, as shown by `list`."
    )
}

fn operator_help() -> String {
    "Commands: `list`, `status <community>`, `invite <community> <@user:server>`, `unbridge <community>`.".into()
}

async fn access(b: &Bridge, cid: &str, who: &Who) -> Access {
    let mxid = match who {
        Who::Operator => return Access::Manager,
        Who::Matrix(mxid) => mxid,
    };
    if b.permission(mxid) >= Permission::Admin {
        return Access::Manager;
    }
    let Ok(Some(row)) = b.db.community(cid).await else { return Access::None };
    if row.requested_by == *mxid {
        return Access::Manager;
    }
    let Some(space) = row.space_room_id else { return Access::None };
    if let Ok(Some(pl)) = b.mx.get_state(As::BOT, &space, "m.room.power_levels", "").await
        && pl["users"][mxid.as_str()].as_i64().unwrap_or(0) >= 100
    {
        return Access::Manager;
    }
    match b.mx.get_state(As::BOT, &space, "m.room.member", mxid).await {
        Ok(Some(m)) if m["membership"] == "join" => Access::Member,
        _ => Access::None,
    }
}

async fn status(b: &Bridge, cid: &str) -> String {
    b.ask(cid, |tx| Msg::Command(Command::Status, tx)).await.unwrap_or_default()
}

/// The first community matching `query` (id or name prefix) that `who`
/// has at least `need` access to. Others are invisible, so their names don't leak.
async fn find(b: &Bridge, who: &Who, query: &str, need: Access) -> Option<String> {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return None;
    }
    let mut matches = vec![];
    for h in b.handles().await {
        if h.id.starts_with(&query) || status(b, &h.id).await.to_lowercase().starts_with(&format!("**{query}")) {
            matches.push(h.id);
        }
    }
    for cid in matches {
        if access(b, &cid, who).await >= need {
            return Some(cid);
        }
    }
    None
}

pub async fn management(b: Arc<Bridge>, room: String, sender: String, body: String) {
    let text = body.trim();
    let text = text.strip_prefix(&b.config.bridge.command_prefix).unwrap_or(text).trim();
    let reply = run(&b, &Who::Matrix(sender), Some(&room), text).await;
    b.notice(&room, &reply).await;
}

/// A command from the control socket.
pub async fn operator(b: Arc<Bridge>, line: &str) -> String {
    run(&b, &Who::Operator, None, line.trim()).await
}

async fn run(b: &Arc<Bridge>, who: &Who, room: Option<&str>, text: &str) -> String {
    let (cmd, args) = text.split_once(char::is_whitespace).unwrap_or((text, ""));
    let args = args.trim();
    let no_such = || "No such community.".to_owned();
    match (cmd.to_lowercase().as_str(), who, room) {
        ("help" | "", Who::Operator, _) => operator_help(),
        ("help" | "", _, _) => help(b),
        ("list", _, _) => {
            let mut lines = vec![];
            for h in b.handles().await {
                if access(b, &h.id, who).await < Access::Member {
                    continue;
                }
                let mut line = format!("- {}", status(b, &h.id).await);
                if let Who::Operator = who
                    && let Ok(Some(row)) = b.db.community(&h.id).await
                {
                    line.push_str(&format!(" [requested by {}]", row.requested_by));
                }
                lines.push(line);
            }
            if lines.is_empty() { "No communities yet.".into() } else { lines.join("\n") }
        }
        ("status", _, _) => match find(b, who, args, Access::Member).await {
            Some(cid) => status(b, &cid).await,
            None => no_such(),
        },
        ("link", Who::Matrix(sender), Some(room)) => match link_code(b, room, sender).await {
            Ok(msg) => msg,
            Err(e) => format!("Couldn't link this room: {e:#}"),
        },
        ("bridge", Who::Matrix(sender), Some(room)) => match bridge(b.clone(), room, sender, args).await {
            Ok(msg) => msg,
            Err(e) => format!("Couldn't bridge that: {e:#}"),
        },
        ("unbridge", _, _) => match find(b, who, args, Access::Member).await {
            Some(cid) if access(b, &cid, who).await < Access::Manager => {
                "Only whoever bridged it, or an admin (power level 100) of its space, can unbridge it.".into()
            }
            Some(cid) => {
                let by = match who {
                    Who::Operator => "The bridge operator".to_owned(),
                    Who::Matrix(mxid) => mxid.clone(),
                };
                b.ask(&cid, |tx| Msg::Command(Command::Unbridge { by }, tx)).await.unwrap_or_default()
            }
            None => no_such(),
        },
        ("invite", _, _) => {
            let (query, mxid) = args.rsplit_once(char::is_whitespace).unwrap_or((args, ""));
            if !mxid.starts_with('@') {
                return "Usage: `invite <community> <@user:server>`".into();
            }
            match find(b, who, query, Access::Member).await {
                Some(cid) => b.ask(&cid, |tx| Msg::Command(Command::Invite { mxid: mxid.to_owned() }, tx)).await.unwrap_or_default(),
                None => no_such(),
            }
        }
        (_, Who::Operator, _) => format!("Unknown command. {}", operator_help()),
        _ => format!("Unknown command. {}", help(b)),
    }
}

async fn bridge(b: Arc<Bridge>, room: &str, sender: &str, link: &str) -> Result<String> {
    let link = parse_invite_link(link)?;
    let signer = PublicKey::from_hex(&link.link_signer)?;
    let mut relays: Vec<String> = link.bootstrap_relays.iter().filter_map(|r| relay_pool::normalize_relay_url(r)).collect();
    relays.extend(b.relays());
    let filter = Filter::new().kind(Kind::Custom(kinds::INVITE_BUNDLE)).author(signer).identifier("");
    let events = b.pool.query(&relays, vec![filter], Duration::from_secs(8)).await;
    let event = events.into_iter().max_by_key(|e| e.created_at).ok_or_else(|| anyhow::anyhow!("the invite's bundle wasn't found on its relays"))?;
    let bundle = parse_bundle_event(&event, &link, now_ms())?;

    if let Some(row) = b.db.community(&bundle.community_id).await? {
        let cid = row.community_id.clone();
        match row.status.as_str() {
            // A valid invite link is as good as an invitation to its space.
            "active" => {
                let mxid = sender.to_owned();
                return Ok(b.ask(&cid, |tx| Msg::Command(Command::Invite { mxid }, tx)).await.unwrap_or_default());
            }
            "pending" => {
                return Ok(format!("{}\n\nSend the invite link again once it's approved to join its Matrix space.", status(&b, &cid).await));
            }
            _ if b.permission(sender) < Permission::Bridge => anyhow::bail!("{NOT_ALLOWED}"),
            // Re-requesting a revoked community: fresh keys, fresh approval.
            _ => {
                b.db.delete_community(&cid).await?;
                b.remove_handle(&cid).await;
            }
        }
    }
    if b.permission(sender) < Permission::Bridge {
        anyhow::bail!("{NOT_ALLOWED}");
    }
    if b.permission(sender) < Permission::Admin && b.db.pending_count(sender).await? >= MAX_PENDING {
        anyhow::bail!("you already have {MAX_PENDING} communities waiting for approval on Armada");
    }
    let code = community::join(b.clone(), &bundle, sender, room).await?;
    Ok(format!(
        "Joined **{}** on Armada as the bridge (`{}`).\n\n\
         Nothing is bridged yet. Someone in that community who can **manage channels** must post this in any of its channels within {PENDING_DAYS} days:\n\n\
         `/bridge approve {code}`\n\n\
         Public channels are bridged after approval; private channels only when an Armada admin runs `/bridge include` in them.",
        bundle.name,
        b.bot_npub(),
    ))
}

/// What a Matrix user can do in `room`, from its power levels: whether they
/// may change its settings (at least `state_default`, or a room v12 creator),
/// what the bridge would be missing there, and what would merely work less well.
async fn room_check(b: &Bridge, room: &str, mxid: &str) -> Result<(bool, Vec<String>, Vec<String>)> {
    let state = b.mx.get(&format!("/_matrix/client/v3/rooms/{}/state", enc(room)), As::BOT).await?;
    let events = state.as_array().cloned().unwrap_or_default();
    let find = |t: &str| events.iter().find(|e| e["type"] == t && e["state_key"] == "").cloned();
    let create = find("m.room.create").unwrap_or_default();
    let creators: Vec<&str> =
        std::iter::once(&create["sender"]).chain(create["content"]["additional_creators"].as_array().into_iter().flatten()).filter_map(Value::as_str).collect();
    let v12 = create["content"]["room_version"].as_str().and_then(|v| v.parse::<u32>().ok()).is_some_and(|v| v >= 12);
    let Some(pl) = find("m.room.power_levels").map(|e| e["content"].clone()) else {
        // No power levels: the creator holds 100, everyone else 0.
        return Ok((creators.contains(&mxid), vec![], vec![]));
    };
    let level = |v: &Value, default: i64| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())).unwrap_or(default);
    let users_default = level(&pl["users_default"], 0);
    let of = |who: &str| if v12 && creators.contains(&who) { i64::MAX } else { level(&pl["users"][who], users_default) };
    let moderator = of(mxid) >= level(&pl["state_default"], 50);
    let mut missing = vec![];
    if of(&b.bot_mxid) < level(&pl["invite"], 0) {
        missing.push(format!("I can't invite people here, so Armada members can't join. Give {} permission to invite.", b.bot_mxid));
    }
    let send = level(&pl["events"]["m.room.message"], level(&pl["events_default"], 0));
    if users_default < send {
        missing.push("New members can't send messages here, so Armada members couldn't post. Let the default role send messages.".into());
    }
    let mut notes = vec![];
    if of(&b.bot_mxid) < level(&pl["redact"], 50) {
        notes.push(format!(
            "When an Armada moderator deletes a message that came from Matrix, I can only remove it here if {} may remove messages (redact).",
            b.bot_mxid
        ));
    }
    Ok((moderator, missing, notes))
}

/// `!armada link`: a code that links this room to the Armada channel it is posted in.
async fn link_code(b: &Bridge, room: &str, sender: &str) -> Result<String> {
    if b.permission(sender) < Permission::Bridge {
        anyhow::bail!("this bridge only links rooms for approved users; ask its operator for access");
    }
    if let Some((_, true)) = b.db.management_room(room).await? {
        anyhow::bail!("send this in the Matrix room you want to link, not in a direct message with me");
    }
    let (moderator, missing, notes) = room_check(b, room, sender).await?;
    if !moderator {
        anyhow::bail!("only this room's moderators can link it");
    }
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let chars: String = rand::random::<[u8; 8]>().iter().map(|n| ALPHABET[*n as usize % ALPHABET.len()] as char).collect();
    let code = format!("{}-{}", &chars[..4], &chars[4..]);
    b.db.new_link_code(&code, room, sender).await?;
    let mut reply = format!(
        "To link this room to an Armada channel:\n\n\
         1. On Armada, invite me to the community, as you would invite anyone: `{}`. Skip this if I'm already in it.\n\
         2. In the channel you want linked, someone who can **manage channels** posts:\n\n\
         `/bridge link {code}`\n\n\
         The code works once, within {LINK_CODE_HOURS} hours. I won't change this room's name, settings or permissions.",
        b.bot_npub()
    );
    if !missing.is_empty() {
        reply.push_str("\n\nFirst, fix this room's permissions:\n");
        for m in missing {
            reply.push_str(&format!("- {m}\n"));
        }
    }
    for n in notes {
        reply.push_str(&format!("\n\nOptional: {n}"));
    }
    Ok(reply)
}

/// A `!armada` command in a room bridged to `cid`.
pub async fn portal(b: Arc<Bridge>, cid: String, room: String, sender: String, text: String) {
    let cmd = text.split_whitespace().next().unwrap_or("").to_lowercase();
    let p = prefix(&b);
    let reply = match cmd.as_str() {
        "status" => status(&b, &cid).await,
        "link" => format!("This room is already linked. Send `{p}unlink` first to link it somewhere else."),
        "unlink" => match room_check(&b, &room, &sender).await {
            Ok((true, _, _)) => b.ask(&cid, |tx| Msg::Command(Command::Unlink { room: room.clone(), by: sender.clone() }, tx)).await.unwrap_or_default(),
            Ok(_) => "Only this room's moderators can unlink it.".into(),
            Err(e) => format!("Couldn't check your power level here: {e:#}"),
        },
        _ => format!("Commands in a bridged room: `{p}status`, `{p}unlink`."),
    };
    if !reply.is_empty() {
        b.notice(&room, &reply).await;
    }
}

/// Drop requests nobody approved in time.
pub async fn expire_pending(b: &Bridge) {
    let Ok(stale) = b.db.stale_pending(PENDING_DAYS).await else { return };
    for cid in stale {
        tracing::info!(community = %cid, "dropping an unapproved bridge request");
        b.ask(&cid, |tx| Msg::Command(Command::Expire, tx)).await;
        b.remove_handle(&cid).await;
        if let Err(e) = b.db.delete_community(&cid).await {
            tracing::warn!(community = %cid, error = %e, "could not delete an expired request");
        }
    }
}

// ── Armada side ─────────────────────────────────────────────────────────────

pub fn is_armada_command(r: &Rumor) -> bool {
    r.kind == kinds::MESSAGE && r.content.trim_start().starts_with("/bridge")
}

pub async fn armada(c: &mut Community, opened: &Opened, channel_id: &str) -> Result<()> {
    if c.status == Status::Revoked || c.dissolved {
        return Ok(());
    }
    let text = opened.rumor.content.trim();
    let mut words = text.split_whitespace().skip(1);
    let action = words.next().unwrap_or("status").to_lowercase();
    let arg = words.next().unwrap_or("");
    let author = opened.author().to_owned();
    let f = &c.folded;
    let authorized = f.roster.is_authorized(&author, &f.owner, perm::MANAGE_CHANNELS);
    let reply: String = match action.as_str() {
        "status" => c.status_text(),
        _ if !authorized => "Only members who can manage channels can change the Matrix bridge.".into(),
        "link" => link(c, arg, channel_id, &author).await?,
        "unlink" if !c.linked => "This community is bridged as a whole Matrix space. Use `/bridge exclude` to stop bridging this channel.".into(),
        "unlink" => match c.portals.get(channel_id).cloned() {
            Some(p) => {
                super::portals::unlink(c, channel_id, &format!("An Armada admin unlinked this room from #{}. Messages are no longer bridged.", p.name)).await?;
                "This channel is no longer linked to Matrix.".into()
            }
            None => "This channel isn't linked to a Matrix room.".into(),
        },
        "approve" | "include" | "exclude" if c.linked => format!("Channels here are linked to Matrix rooms one at a time. {LINK_HOWTO} `/bridge unlink` stops one."),
        "approve" => match (c.status, &c.approval_code) {
            (Status::Active, _) => "The bridge is already approved.".into(),
            (Status::Pending, Some(code)) if code.eq_ignore_ascii_case(arg) => {
                c.status = Status::Active;
                c.approved_by = Some(author.clone());
                c.b.db.set_status(&c.id, "active", Some(&author)).await?;
                Box::pin(super::portals::reconcile(c)).await?;
                if let Some(room) = &c.management_room {
                    c.b.notice(room, &format!("**{}** was approved on Armada. Its Matrix space is ready.", c.name())).await;
                }
                format!(
                    "Approved. Public channels are now bridged to Matrix on {}. Run `/bridge include` in a private channel to bridge it too, `/bridge exclude` in any channel to stop, or `/bridge revoke` to remove the bridge.",
                    c.b.config.homeserver.server_name
                )
            }
            _ => "That approval code doesn't match.".into(),
        },
        "revoke" => {
            c.revoke("An Armada admin revoked the bridge.").await;
            "The Matrix bridge is revoked. Messages are no longer bridged.".into()
        }
        "include" | "exclude" => {
            let enabled = action == "include";
            c.b.db.set_channel_setting(&c.id, channel_id, enabled, &author).await?;
            c.settings.insert(channel_id.to_owned(), enabled);
            if c.status == Status::Active {
                Box::pin(super::portals::reconcile(c)).await?;
            }
            if enabled { "This channel is bridged to Matrix.".into() } else { "This channel is no longer bridged to Matrix.".into() }
        }
        _ if c.linked => "Usage: `/bridge link <code>`, `/bridge unlink`, `/bridge status`, `/bridge revoke`.".into(),
        _ => "Usage: `/bridge approve <code>`, `/bridge status`, `/bridge include`, `/bridge exclude`, `/bridge revoke`.".into(),
    };
    c.post_as_bot(channel_id, &reply, Some(&opened.rumor)).await
}

/// `/bridge link <code>`: link this channel to the Matrix room the code came from.
async fn link(c: &mut Community, code: &str, channel_id: &str, author: &str) -> Result<String> {
    if !c.linked {
        return Ok("This community is bridged as a whole Matrix space, so its channels can't also be linked to other rooms.".into());
    }
    if c.portals.contains_key(channel_id) {
        return Ok("This channel is already linked to a Matrix room. Run `/bridge unlink` first to link a different one.".into());
    }
    let code: String = code.chars().filter(char::is_ascii_alphanumeric).collect::<String>().to_uppercase();
    let code = if code.len() == 8 { format!("{}-{}", &code[..4], &code[4..]) } else { code };
    let Some((room, mxid)) = c.b.db.take_link_code(&code).await? else {
        return Ok("That code doesn't exist or has expired. Send `!armada link` in the Matrix room for a new one.".into());
    };
    if c.b.community_of_room(&room).await.is_some() {
        return Ok("That Matrix room is already linked to a channel.".into());
    }
    super::portals::link(c, channel_id, &room).await?;
    if c.status == Status::Pending {
        c.status = Status::Active;
        c.approved_by = Some(author.to_owned());
        c.b.db.set_status(&c.id, "active", Some(author)).await?;
    }
    let channel = c.channel(channel_id).map(|ch| ch.name.clone()).unwrap_or_default();
    let by = PublicKey::from_hex(author).ok().and_then(|pk| pk.to_bech32().ok()).unwrap_or_default();
    c.b.notice(
        &room,
        &format!("Linked to **#{channel}** in **{}** on Armada (approved by nostr:{by}). Messages are bridged both ways. A moderator can stop it with `!armada unlink`.", c.name()),
    )
    .await;
    Ok(format!("Linked this channel to a Matrix room, as {mxid} asked. Messages are bridged both ways; `/bridge unlink` stops it."))
}
