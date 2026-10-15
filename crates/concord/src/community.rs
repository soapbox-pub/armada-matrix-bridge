//! What a member holds for one Community: every root epoch (current plus
//! retained priors, for history), the Control Plane pair, and private Channel
//! keys. Serializable, so a bridge can persist it. Mirrors Armada's `Community`
//! and its `channelsView`, plus the receiving half of CORD-06.

use serde::{Deserialize, Serialize};

use crate::control::FoldedControl;
use crate::derive::{
    GroupKey, base_rekey_group_key, channel_group_key, channel_rekey_group_key, control_group_key, control_signer_group_key,
    guestbook_group_key,
};
use crate::invite::{BundleChannel, InviteBundle};
use crate::rekey::{self, Continuity, Rotation};
use crate::roles::perm;
use crate::stream::StreamKey;
use crate::{Bytes32, hex32, to_hex};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeldRoot {
    pub epoch: u64,
    pub key: String,
    /// The epoch's Control Plane address; absent on a legacy pre-split epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_pk: Option<String>,
    /// Unix seconds of the superseding rotation: a hard read cutoff.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<u64>,
    /// Whose Refounding minted this epoch (its Guestbook snapshot authority).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refounder: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PriorKey {
    pub key: String,
    pub epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateChannelKey {
    pub id: String,
    pub key: String,
    pub epoch: u64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub priors: Vec<PriorKey>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Membership {
    pub community_id: String,
    pub owner: String,
    pub owner_salt: String,
    pub root_epoch: u64,
    pub root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_pk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_root: Option<String>,
    /// Newest first; includes the current root.
    pub held_roots: Vec<HeldRoot>,
    #[serde(default)]
    pub private_channels: Vec<PrivateChannelKey>,
    /// channel id → the epoch whose rotation cut us out (stale bundles can't undo it).
    #[serde(default)]
    pub channel_cuts: Vec<(String, u64)>,
    pub relays: Vec<String>,
    pub name: String,
    /// When we joined (ms). A rotation predating it is history, not a removal.
    pub joined_at_ms: u64,
    /// A complete rotation excluded us at this epoch: read-only from here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub excluded_at: Option<u64>,
}

/// One readable stream of a Channel.
#[derive(Clone, Debug)]
pub struct ChannelStream {
    pub epoch: u64,
    pub key: GroupKey,
    pub retired_at: Option<u64>,
}

/// A Channel as the member can read it.
#[derive(Clone, Debug)]
pub struct ChannelView {
    pub id_hex: String,
    pub name: String,
    pub private: bool,
    pub forum: bool,
    pub category: Option<String>,
    pub position: Option<f64>,
    /// Newest first; `streams[0]` is where writes go.
    pub streams: Vec<ChannelStream>,
}

impl ChannelView {
    pub fn current(&self) -> &ChannelStream {
        &self.streams[0]
    }
}

/// What a rekey sweep decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RekeyOutcome {
    /// Adopted a new root at this epoch.
    AdoptedRoot(u64),
    /// A complete post-join rotation by an outranking rotator carried no blob for us.
    Excluded(u64),
    Nothing,
}

fn b32(s: &str) -> Bytes32 {
    hex32(s).expect("membership holds well-formed hex")
}

impl Membership {
    pub fn from_bundle(bundle: &InviteBundle, now_ms: u64) -> Membership {
        Membership {
            community_id: bundle.community_id.to_lowercase(),
            owner: bundle.owner.to_lowercase(),
            owner_salt: bundle.owner_salt.to_lowercase(),
            root_epoch: bundle.root_epoch,
            root: bundle.community_root.to_lowercase(),
            control_pk: bundle.control_pk.clone(),
            control_root: None,
            held_roots: vec![HeldRoot {
                epoch: bundle.root_epoch,
                key: bundle.community_root.to_lowercase(),
                control_pk: bundle.control_pk.clone(),
                retired_at: None,
                refounder: None,
            }],
            private_channels: bundle
                .channels
                .iter()
                .filter(|c| hex32(&c.id).is_some() && hex32(&c.key).is_some())
                .map(|c| PrivateChannelKey { id: c.id.to_lowercase(), key: c.key.to_lowercase(), epoch: c.epoch, name: c.name.clone(), priors: vec![] })
                .collect(),
            channel_cuts: vec![],
            relays: bundle.relays.clone(),
            name: bundle.name.clone(),
            joined_at_ms: now_ms,
            excluded_at: None,
        }
    }

    pub fn id(&self) -> Bytes32 {
        b32(&self.community_id)
    }

    pub fn root_key(&self) -> Bytes32 {
        b32(&self.root)
    }

    fn control_stream_for(&self, root: &HeldRoot) -> StreamKey {
        let read = control_group_key(&b32(&root.key), &self.id(), root.epoch);
        let Some(pk) = root.control_pk.as_deref().and_then(|pk| nostr::prelude::PublicKey::from_hex(pk).ok()) else {
            return (&read).into();
        };
        let signer = (root.epoch == self.root_epoch)
            .then(|| self.control_root.as_deref().and_then(hex32))
            .flatten()
            .map(|cr| control_signer_group_key(&cr, &self.id(), root.epoch))
            .filter(|g| g.pubkey() == pk);
        StreamKey { pk, conv_key: read.conv_key, sk: signer.map(|g| g.keys.secret_key().clone()), restricted: true }
    }

    /// Control Plane streams across every held epoch, newest first.
    pub fn control_streams(&self) -> Vec<StreamKey> {
        self.held_roots.iter().map(|r| self.control_stream_for(r)).collect()
    }

    pub fn current_control_stream(&self) -> StreamKey {
        let current = self.held_roots.iter().find(|r| r.epoch == self.root_epoch).cloned().unwrap_or(HeldRoot {
            epoch: self.root_epoch,
            key: self.root.clone(),
            control_pk: self.control_pk.clone(),
            retired_at: None,
            refounder: None,
        });
        self.control_stream_for(&current)
    }

    pub fn guestbook_streams(&self) -> Vec<StreamKey> {
        self.held_roots.iter().map(|r| guestbook_group_key(&b32(&r.key), &self.id(), r.epoch).into()).collect()
    }

    pub fn current_guestbook_stream(&self) -> StreamKey {
        guestbook_group_key(&self.root_key(), &self.id(), self.root_epoch).into()
    }

    /// The npubs whose Refoundings minted held epochs (snapshot authorities).
    pub fn snapshot_authorities(&self) -> std::collections::HashSet<String> {
        self.held_roots.iter().filter(|r| r.epoch > 0).filter_map(|r| r.refounder.clone()).collect()
    }

    /// The channels this member can read (Armada `channelsView`): public ones derive
    /// from every held root; private ones need a held key; deleted ones are dropped.
    pub fn channels(&self, folded: Option<&FoldedControl>) -> Vec<ChannelView> {
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for def in folded.map(|f| f.channels.values()).into_iter().flatten() {
            seen.insert(def.channel_id_hex.clone());
            if def.deleted {
                continue;
            }
            let id = b32(&def.channel_id_hex);
            let root_streams: Vec<ChannelStream> = self
                .held_roots
                .iter()
                .map(|r| ChannelStream { epoch: r.epoch, key: channel_group_key(&b32(&r.key), &id, r.epoch), retired_at: r.retired_at })
                .collect();
            let held = self.private_channels.iter().find(|c| c.id == def.channel_id_hex);
            let channel_streams = held.map(|h| private_streams(h, &id)).unwrap_or_default();
            let streams = if def.private {
                if held.is_none() {
                    continue;
                }
                channel_streams
            } else {
                root_streams.into_iter().chain(channel_streams).collect()
            };
            out.push(ChannelView {
                id_hex: def.channel_id_hex.clone(),
                name: def.name.clone(),
                private: def.private,
                forum: def.forum,
                category: def.category.clone(),
                position: def.position,
                streams,
            });
        }
        for held in &self.private_channels {
            if seen.contains(&held.id) {
                continue;
            }
            let id = b32(&held.id);
            out.push(ChannelView {
                id_hex: held.id.clone(),
                name: if held.name.is_empty() { held.id[..8].to_owned() } else { held.name.clone() },
                private: true,
                forum: false,
                category: None,
                position: None,
                streams: private_streams(held, &id),
            });
        }
        out.sort_by(|a, b| match (a.position, b.position) {
            (Some(x), Some(y)) => x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal).then_with(|| a.name.cmp(&b.name)),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.name.cmp(&b.name),
        });
        out
    }

    /// Adopt private Channel keys from a Direct Invite on the SAME base (a role-gated
    /// key vend). A bundle may never move the base: only a rekey blob with proven
    /// continuity can. Returns the channel ids newly adopted or advanced.
    pub fn adopt_catch_up(&mut self, bundle: &InviteBundle) -> Vec<String> {
        if !bundle.community_root.eq_ignore_ascii_case(&self.root)
            || bundle.root_epoch != self.root_epoch
            || bundle.control_pk.as_deref().map(str::to_lowercase) != self.control_pk.as_deref().map(str::to_lowercase)
        {
            return vec![];
        }
        let mut adopted = vec![];
        for c in &bundle.channels {
            let id = c.id.to_lowercase();
            if hex32(&id).is_none() || hex32(&c.key).is_none() {
                continue;
            }
            if self.channel_cuts.iter().any(|(cid, cut)| cid == &id && c.epoch < *cut) {
                continue;
            }
            match self.private_channels.iter_mut().find(|h| h.id == id) {
                Some(h) if c.epoch > h.epoch => {
                    h.priors.insert(0, PriorKey { key: h.key.clone(), epoch: h.epoch, retired_at: None });
                    h.key = c.key.to_lowercase();
                    h.epoch = c.epoch;
                    adopted.push(id);
                }
                Some(_) => {}
                None => {
                    let BundleChannel { key, epoch, name, .. } = c.clone();
                    self.private_channels.push(PrivateChannelKey { id: id.clone(), key: key.to_lowercase(), epoch, name, priors: vec![] });
                    adopted.push(id);
                }
            }
        }
        adopted
    }

    /// The address where the next base rotation would appear.
    pub fn next_base_rekey_address(&self) -> GroupKey {
        base_rekey_group_key(&self.root_key(), &self.id(), self.root_epoch + 1)
    }

    /// Addresses of upcoming private Channel rotations, under every held root,
    /// with their (channel id, epoch).
    pub fn channel_rekey_addresses(&self) -> Vec<(GroupKey, String, u64)> {
        let mut out = vec![];
        for ch in &self.private_channels {
            let id = b32(&ch.id);
            for r in &self.held_roots {
                for ahead in 1..=rekey::CHANNEL_REKEY_LOOKAHEAD {
                    out.push((channel_rekey_group_key(&b32(&r.key), &id, ch.epoch + ahead), ch.id.clone(), ch.epoch + ahead));
                }
            }
        }
        out
    }

    /// Process base rotations at `root_epoch + 1` (CORD-06 §2). `rotations` must
    /// come from the next base-rekey address. Authority is the roster, never key
    /// possession: the rotator must be the owner or hold BAN, be unbanned, and
    /// cite a satisfied Grant.
    pub fn apply_base_rotations(&mut self, rotations: &[Rotation], folded: &FoldedControl, me: &nostr::prelude::Keys) -> RekeyOutcome {
        let me_hex = me.public_key().to_hex();
        let next = self.root_epoch + 1;
        let cid = self.id();
        let mut adopted: Option<(rekey::BaseBlob, String, u64)> = None;
        let mut excluded = false;
        for set in rotations {
            if set.scope_hex != rekey::ROOT_SCOPE_HEX
                || set.new_epoch != next
                || !set.is_complete()
                || folded.banned.contains(&set.rotator)
                || !folded.roster.is_authorized(&set.rotator, &folded.owner, perm::BAN)
                || !folded.citation_satisfied(&cid, &set.rotator, set.authority.as_ref())
                || set.continues_from(self.root_epoch, &self.root_key()) != Continuity::Ok
            {
                continue;
            }
            let post_join = set.published_ms() >= self.joined_at_ms;
            let could_exclude = post_join && folded.roster.outranks_member(&set.rotator, &folded.owner, &me_hex);
            let blob = rekey::my_locator(&set.rotator, &me_hex, &set.scope_hex, set.new_epoch).and_then(|loc| set.find_blob(&loc));
            let Some(blob) = blob else {
                excluded |= could_exclude;
                continue;
            };
            let Ok(rotator) = nostr::prelude::PublicKey::from_hex(&set.rotator) else { continue };
            match rekey::open_blob(blob, me.secret_key(), &rotator).and_then(|plain| rekey::decode_base_blob(&plain, &cid, next)) {
                Ok(b) => {
                    if adopted.as_ref().is_none_or(|(a, _, _)| b.new_root < a.new_root) {
                        adopted = Some((b, set.rotator.clone(), set.published_ms()));
                    }
                }
                Err(_) => excluded |= could_exclude,
            }
        }
        if let Some((blob, rotator, published_ms)) = adopted {
            let retired_at = published_ms / 1000;
            for r in &mut self.held_roots {
                if r.epoch == self.root_epoch && r.retired_at.is_none() {
                    r.retired_at = Some(retired_at);
                }
            }
            self.held_roots.insert(
                0,
                HeldRoot { epoch: next, key: to_hex(&blob.new_root), control_pk: blob.control_pk.clone(), retired_at: None, refounder: Some(rotator) },
            );
            self.root = to_hex(&blob.new_root);
            self.root_epoch = next;
            self.control_pk = blob.control_pk;
            self.control_root = blob.control_root.map(|c| to_hex(&c));
            self.excluded_at = None;
            return RekeyOutcome::AdoptedRoot(next);
        }
        if excluded {
            self.excluded_at = Some(next);
            return RekeyOutcome::Excluded(next);
        }
        RekeyOutcome::Nothing
    }

    /// Process private Channel rotations (CORD-06 §2), walking each channel's
    /// epochs ascending. Returns `(channel id, adopted epoch or None if cut)`.
    pub fn apply_channel_rotations(&mut self, rotations: &[Rotation], folded: &FoldedControl, me: &nostr::prelude::Keys) -> Vec<(String, Option<u64>)> {
        let me_hex = me.public_key().to_hex();
        let cid = self.id();
        let mut changes = vec![];
        let mut cuts = vec![];
        for ch in &mut self.private_channels {
            let mut sets: Vec<&Rotation> = rotations
                .iter()
                .filter(|s| {
                    s.scope_hex == ch.id
                        && s.new_epoch > ch.epoch
                        && s.is_complete()
                        && !folded.banned.contains(&s.rotator)
                        && (folded.roster.is_authorized(&s.rotator, &folded.owner, perm::BAN)
                            || folded.roster.is_authorized(&s.rotator, &folded.owner, perm::MANAGE_CHANNELS))
                        && folded.citation_satisfied(&cid, &s.rotator, s.authority.as_ref())
                })
                .collect();
            if sets.is_empty() {
                continue;
            }
            sets.sort_by_key(|s| s.new_epoch);
            let id = b32(&ch.id);
            let (mut chain_epoch, mut chain_key) = (ch.epoch, b32(&ch.key));
            let mut adopted: Option<(Bytes32, u64)> = None;
            let mut excluded_at: Option<u64> = None;
            let mut stepped: Vec<PriorKey> = vec![];
            let mut epochs: Vec<u64> = sets.iter().map(|s| s.new_epoch).collect();
            epochs.dedup();
            for epoch in epochs {
                let mut key_here: Option<(Bytes32, u64)> = None;
                let mut addressed = false;
                for set in sets.iter().filter(|s| s.new_epoch == epoch) {
                    let Some(blob) = rekey::my_locator(&set.rotator, &me_hex, &ch.id, epoch).and_then(|l| set.find_blob(&l)) else { continue };
                    addressed = true;
                    if set.continues_from(chain_epoch, &chain_key) != Continuity::Ok {
                        continue;
                    }
                    let Ok(rotator) = nostr::prelude::PublicKey::from_hex(&set.rotator) else { continue };
                    if let Ok(k) = rekey::open_blob(blob, me.secret_key(), &rotator).and_then(|p| rekey::decode_channel_blob(&p, &id, epoch)) {
                        let at = set.published_ms();
                        key_here = Some(match key_here {
                            Some((prev, prev_at)) => (prev.min(k), prev_at.min(at)),
                            None => (k, at),
                        });
                    }
                }
                if let Some((k, at)) = key_here {
                    stepped.insert(0, PriorKey { key: to_hex(&chain_key), epoch: chain_epoch, retired_at: Some(at / 1000) });
                    adopted = Some((k, epoch));
                    chain_epoch = epoch;
                    chain_key = k;
                    continue;
                }
                if addressed {
                    continue;
                }
                if sets.iter().filter(|s| s.new_epoch == epoch).any(|s| {
                    s.published_ms() >= self.joined_at_ms && folded.roster.outranks_member(&s.rotator, &folded.owner, &me_hex)
                }) {
                    excluded_at = Some(epoch);
                }
            }
            match (adopted, excluded_at) {
                (Some((k, epoch)), ex) if ex.is_none_or(|x| epoch > x) => {
                    let mut priors = stepped;
                    priors.append(&mut ch.priors);
                    ch.priors = priors;
                    ch.key = to_hex(&k);
                    ch.epoch = epoch;
                    changes.push((ch.id.clone(), Some(epoch)));
                }
                (_, Some(x)) => {
                    cuts.push((ch.id.clone(), x));
                    changes.push((ch.id.clone(), None));
                }
                _ => {}
            }
        }
        for (id, epoch) in cuts {
            self.private_channels.retain(|c| c.id != id);
            self.channel_cuts.push((id, epoch));
        }
        changes
    }
}

fn private_streams(h: &PrivateChannelKey, id: &Bytes32) -> Vec<ChannelStream> {
    std::iter::once(ChannelStream { epoch: h.epoch, key: channel_group_key(&b32(&h.key), id, h.epoch), retired_at: None })
        .chain(h.priors.iter().filter_map(|p| {
            Some(ChannelStream { epoch: p.epoch, key: channel_group_key(&hex32(&p.key)?, id, p.epoch), retired_at: p.retired_at })
        }))
        .collect()
}
