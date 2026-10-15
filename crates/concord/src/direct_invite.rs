//! Direct Invites — CORD-05 §6: a standard NIP-59 giftwrap (kind-13 seal,
//! recipient-`p`-tagged 1059 with `["k","3313"]`) whose rumor carries the bundle.

use nostr::prelude::{Event, Keys, Kind};

use crate::derive::conversation_key;
use crate::invite::InviteBundle;
use crate::rumor::Rumor;
use crate::{kinds, nip44};

/// An unwrapped Direct Invite: the bundle and its verified inviter.
#[derive(Clone, Debug)]
pub struct DirectInvite {
    pub inviter: String,
    pub bundle: InviteBundle,
    pub created_at: u64,
}

/// Unwrap a giftwrap addressed to `me`; `None` if it is malformed, not an
/// invite, or its rumor claims an author other than the seal's signer.
pub fn unwrap(wrap: &Event, me: &Keys) -> Option<DirectInvite> {
    if wrap.kind != Kind::Custom(kinds::WRAP) {
        return None;
    }
    let seal_json = nip44::decrypt_str(&conversation_key(me.secret_key(), &wrap.pubkey), &wrap.content).ok()?;
    let seal = Event::from_json(&seal_json).ok()?;
    if seal.kind != Kind::Custom(kinds::NIP59_SEAL) || seal.verify().is_err() {
        return None;
    }
    let rumor_json = nip44::decrypt_str(&conversation_key(me.secret_key(), &seal.pubkey), &seal.content).ok()?;
    let rumor: Rumor = serde_json::from_str(&rumor_json).ok()?;
    if rumor.pubkey != seal.pubkey.to_hex() || rumor.kind != kinds::DIRECT_INVITE {
        return None;
    }
    let bundle: InviteBundle = serde_json::from_str(&rumor.content).ok()?;
    Some(DirectInvite { inviter: rumor.pubkey, bundle: bundle.validate().ok()?, created_at: rumor.created_at })
}
