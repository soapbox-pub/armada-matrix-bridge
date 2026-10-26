//! Direct Invites — CORD-05 §6: a standard NIP-59 giftwrap (kind-13 seal,
//! recipient-`p`-tagged 1059 with `["k","3313"]`) whose rumor carries the bundle.

use nostr::prelude::{Event, Keys, Kind};

use crate::derive::conversation_key;
use crate::invite::InviteBundle;
use crate::{kinds, nip44};

/// The rumor fields an invite needs. Armada's rumor carries no `id`, so this is
/// not a [`crate::rumor::Rumor`].
#[derive(serde::Deserialize)]
struct InviteRumor {
    pubkey: String,
    created_at: u64,
    kind: u16,
    content: String,
}

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
    let rumor: InviteRumor = serde_json::from_str(&rumor_json).ok()?;
    if rumor.pubkey != seal.pubkey.to_hex() || rumor.kind != kinds::DIRECT_INVITE {
        return None;
    }
    let bundle: InviteBundle = serde_json::from_str(&rumor.content).ok()?;
    Some(DirectInvite { inviter: rumor.pubkey, bundle: bundle.validate().ok()?, created_at: rumor.created_at })
}

#[cfg(test)]
mod tests {
    use nostr::event::FinalizeEvent;
    use nostr::prelude::{Tag, Timestamp, UnsignedEvent};

    use super::*;
    use crate::derive::community_id_of;
    use crate::to_hex;

    fn signed(keys: &Keys, kind: u16, tags: Vec<Tag>, content: String) -> Event {
        UnsignedEvent::new(keys.public_key(), Timestamp::now(), Kind::Custom(kind), tags, content).finalize(keys).unwrap()
    }

    /// Shaped like Armada's `buildDirectInviteRumor` + `sealDirectInvite` +
    /// `wrapDirectInvite`: the rumor has no `id`.
    #[test]
    fn unwraps_armadas_invite() {
        let (me, inviter, ephemeral) = (Keys::generate(), Keys::generate(), Keys::generate());
        let (owner, salt) = (inviter.public_key().to_bytes(), [7u8; 32]);
        let bundle = serde_json::json!({
            "community_id": to_hex(&community_id_of(&owner, &salt)), "owner": to_hex(&owner), "owner_salt": to_hex(&salt),
            "community_root": to_hex(&[1u8; 32]), "root_epoch": 0, "channels": [], "relays": ["wss://relay.example"], "name": "Test",
        });
        let rumor = serde_json::json!({
            "kind": kinds::DIRECT_INVITE, "content": bundle.to_string(), "tags": [], "created_at": 1_800_000_000u64, "pubkey": inviter.public_key().to_hex(),
        });
        let seal_content = nip44::encrypt_str(&conversation_key(inviter.secret_key(), &me.public_key()), &rumor.to_string()).unwrap();
        let seal = signed(&inviter, kinds::NIP59_SEAL, vec![], seal_content);
        let wrap_content = nip44::encrypt_str(&conversation_key(ephemeral.secret_key(), &me.public_key()), &seal.as_json()).unwrap();
        let tags = vec![Tag::parse(["p", &me.public_key().to_hex()]).unwrap(), Tag::parse(["k", &kinds::DIRECT_INVITE.to_string()]).unwrap()];
        let wrap = signed(&ephemeral, kinds::WRAP, tags, wrap_content);

        let invite = unwrap(&wrap, &me).expect("unwraps");
        assert_eq!(invite.inviter, inviter.public_key().to_hex());
        assert_eq!(invite.bundle.name, "Test");
        assert!(unwrap(&wrap, &Keys::generate()).is_none());
    }
}
