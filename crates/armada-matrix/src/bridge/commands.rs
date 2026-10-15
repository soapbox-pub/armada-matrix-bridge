//! Commands: Matrix admins manage the bridge in a DM with the bot; Armada
//! admins approve, revoke and scope it with `/bridge …` in any channel.

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
         - `bridge <invite link>` — join an Armada community and ask its admins to approve bridging it\n\
         - `list` — communities this bridge knows\n\
         - `status <community>` — one community's state\n\
         - `invite <community> <@user:server>` — invite someone to its Matrix space\n\
         - `unbridge <community>` — stop bridging a community\n\n\
         `<community>` is the start of its id or its name, as shown by `list`."
    )
}

/// Find a community by id prefix or exact name.
async fn find(b: &Bridge, query: &str) -> Option<String> {
    let query = query.trim().to_lowercase();
    for h in b.handles().await {
        if !query.is_empty() && h.id.starts_with(&query) {
            return Some(h.id);
        }
    }
    for h in b.handles().await {
        let status = b.ask(&h.id, |tx| Msg::Command(Command::Status, tx)).await.unwrap_or_default();
        if status.to_lowercase().starts_with(&format!("**{query}**")) {
            return Some(h.id);
        }
    }
    None
}

pub async fn management(b: Arc<Bridge>, room: String, sender: String, body: String) {
    let text = body.trim();
    let text = text.strip_prefix(&b.config.bridge.command_prefix).unwrap_or(text).trim();
    let (cmd, args) = text.split_once(char::is_whitespace).unwrap_or((text, ""));
    let args = args.trim();
    let admin = b.permission(&sender) >= Permission::Admin;
    let reply = match cmd.to_lowercase().as_str() {
        "help" | "" => help(&b),
        "list" => {
            let mut lines = vec![];
            for h in b.handles().await {
                if let Some(s) = b.ask(&h.id, |tx| Msg::Command(Command::Status, tx)).await {
                    lines.push(format!("- {s}"));
                }
            }
            if lines.is_empty() { "No communities yet.".into() } else { lines.join("\n") }
        }
        "status" => match find(&b, args).await {
            Some(cid) => b.ask(&cid, |tx| Msg::Command(Command::Status, tx)).await.unwrap_or_default(),
            None => "No such community.".into(),
        },
        "bridge" if !admin => "Only bridge admins can bridge communities.".into(),
        "bridge" => match bridge(b.clone(), &room, &sender, args).await {
            Ok(msg) => msg,
            Err(e) => format!("Couldn't bridge that: {e:#}"),
        },
        "unbridge" if !admin => "Only bridge admins can unbridge communities.".into(),
        "unbridge" => match find(&b, args).await {
            Some(cid) => b.ask(&cid, |tx| Msg::Command(Command::Unbridge { by: sender.clone() }, tx)).await.unwrap_or_default(),
            None => "No such community.".into(),
        },
        "invite" if !admin => "Only bridge admins can invite people to bridged spaces.".into(),
        "invite" => {
            let (query, mxid) = args.rsplit_once(char::is_whitespace).unwrap_or((args, ""));
            match (find(&b, query).await, mxid.starts_with('@')) {
                (Some(cid), true) => b.ask(&cid, |tx| Msg::Command(Command::Invite { mxid: mxid.to_owned() }, tx)).await.unwrap_or_default(),
                (None, _) => "No such community.".into(),
                (_, false) => "Usage: `invite <community> <@user:server>`".into(),
            }
        }
        _ => format!("Unknown command. {}", help(&b)),
    };
    b.notice(&room, &reply).await;
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
        if row.status != "revoked" {
            let status = b.ask(&row.community_id, |tx| Msg::Command(Command::Status, tx)).await.unwrap_or_default();
            return Ok(format!("Already known: {status}"));
        }
        // Re-requesting a revoked community: fresh keys, fresh approval.
        b.db.delete_community(&row.community_id).await?;
        b.remove_handle(&row.community_id).await;
    }
    let code = community::join(b.clone(), &bundle, sender, room).await?;
    Ok(format!(
        "Joined **{}** on Armada as the bridge (`{}`).\n\n\
         Nothing is bridged yet. Someone in that community who can **manage channels** must post this in any of its channels:\n\n\
         `/bridge approve {code}`\n\n\
         Public channels are bridged after approval; private channels only when an Armada admin runs `/bridge include` in them.",
        bundle.name,
        b.bot_npub(),
    ))
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
