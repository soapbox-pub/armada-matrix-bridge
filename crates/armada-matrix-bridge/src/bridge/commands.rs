//! Commands. Matrix users bridge communities and manage the ones they bridged
//! in a DM with the bot; the operator manages any of them over the control
//! socket; Armada admins approve, revoke and scope bridges with `/bridge …` in
//! any channel.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use concord::invite::{parse_bundle_event, parse_invite_link};
use concord::kinds;
use concord::roles::perm;
use concord::rumor::Rumor;
use concord::stream::Opened;
use nostr::prelude::{Filter, Kind, PublicKey};

use super::community::{self, Command, Community, Msg, Status};
use super::{Bridge, now_ms};
use crate::config::Permission;
use crate::matrix::As;

/// Requests nobody approves on Armada are dropped after this many days.
pub const PENDING_DAYS: i32 = 7;
/// Unapproved requests one Matrix user may have open at once.
const MAX_PENDING: i64 = 3;

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

fn help(b: &Bridge) -> String {
    let p = &b.config.bridge.command_prefix;
    format!(
        "Commands (the `{p}` prefix is optional here):\n\
         - `bridge <invite link>` — bridge an Armada community once its admins approve, or join its space if it's already bridged\n\
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
            // Re-requesting a revoked community: fresh keys, fresh approval.
            _ => {
                b.db.delete_community(&cid).await?;
                b.remove_handle(&cid).await;
            }
        }
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
        _ => "Usage: `/bridge approve <code>`, `/bridge status`, `/bridge include`, `/bridge exclude`, `/bridge revoke`.".into(),
    };
    c.post_as_bot(channel_id, &reply, Some(&opened.rumor)).await
}
