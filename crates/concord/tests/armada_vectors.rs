//! Byte-compatibility with Armada: every expectation here was produced by
//! Armada's own TypeScript (`tools/vectors/gen.ts`).

use std::collections::HashSet;

use concord::community::{Membership, RekeyOutcome};
use concord::control::fold_control;
use concord::derive::*;
use concord::edition::{edition_hash, parse_edition};
use concord::invite::{decode_fragment, encode_fragment, parse_bundle_event, parse_invite_link, stock_relays};
use concord::kinds::Plane;
use concord::nostr::prelude::{Event, Keys, SecretKey};
use concord::rekey::{group_rotations, parse_rekey};
use concord::stream::{StreamKey, check_channel_binding, open_plane_wrap, open_wrap};
use concord::{hex32, to_hex};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/armada.json")).unwrap()
}

fn h(v: &Value) -> [u8; 32] {
    hex32(v.as_str().unwrap()).unwrap()
}

fn event(v: &Value) -> Event {
    Event::from_json(v.to_string()).unwrap()
}

fn keys(v: &Value) -> Keys {
    Keys::new(SecretKey::from_hex(v.as_str().unwrap()).unwrap())
}

#[test]
fn derivations_match() {
    let v = vectors();
    let k = &v["keys"];
    let d = &v["derive"];
    let (root, cid, chan) = (h(&k["community_root"]), h(&k["community_id"]), h(&k["channel_id"]));
    assert_eq!(to_hex(&community_id_of(&h(&k["owner"]), &h(&k["owner_salt"]))), k["community_id"].as_str().unwrap());

    let check = |g: GroupKey, want: &Value| {
        assert_eq!(g.pk_hex(), want["pk"].as_str().unwrap());
        assert_eq!(to_hex(&g.keys.secret_key().to_secret_bytes()), want["sk"].as_str().unwrap());
        assert_eq!(to_hex(&g.conv_key), want["conv_key"].as_str().unwrap());
    };
    check(channel_group_key(&root, &chan, 0), &d["channel_public_e0"]);
    check(channel_group_key(&h(&k["private_channel_key"]), &chan, 3), &d["channel_private_e3"]);
    check(control_group_key(&root, &cid, 0), &d["control_e0"]);
    check(control_signer_group_key(&h(&k["control_root"]), &cid, 0), &d["control_signer_e0"]);
    check(guestbook_group_key(&root, &cid, 2), &d["guestbook_e2"]);
    check(dissolved_group_key(&cid), &d["dissolved"]);
    check(channel_rekey_group_key(&root, &chan, 4), &d["channel_rekey_e4"]);
    check(base_rekey_group_key(&root, &cid, 1), &d["base_rekey_e1"]);

    let s = |v: &Value| v.as_str().unwrap().to_owned();
    assert_eq!(to_hex(&grant_locator(&cid, &h(&k["alice"]))), s(&d["grant_locator_alice"]));
    assert_eq!(to_hex(&pins_locator(&cid, &chan)), s(&d["pins_locator"]));
    assert_eq!(to_hex(&banlist_locator(&cid)), s(&d["banlist_locator"]));
    assert_eq!(to_hex(&invite_links_locator(&cid, &h(&k["owner"]))), s(&d["invite_links_locator_owner"]));
    assert_eq!(to_hex(&signal_locator(&cid, "pause")), s(&d["signal_locator_pause"]));
    assert_eq!(to_hex(&recipient_locator(&h(&k["owner"]), &h(&k["alice"]), &[0; 32], 1)), s(&d["recipient_locator"]));
    assert_eq!(to_hex(&invite_bundle_key(&[0x99; 16])), s(&d["invite_bundle_key"]));
    assert_eq!(to_hex(&epoch_key_commitment(7, &root)), s(&d["epoch_key_commitment"]));
}

#[test]
fn edition_hash_matches() {
    let e = &vectors()["edition_hash"];
    let got = edition_hash(&h(&e["entity_id"]), 2, Some(&h(&e["prev"])), e["content"].as_str().unwrap().as_bytes());
    assert_eq!(to_hex(&got), e["hash"].as_str().unwrap());
    let got = edition_hash(&h(&e["entity_id"]), 1, None, b"{}");
    assert_eq!(to_hex(&got), e["hash_no_prev"].as_str().unwrap());
}

#[test]
fn opens_armada_chat_wrap() {
    let v = vectors();
    let k = &v["keys"];
    let stream: StreamKey = channel_group_key(&h(&k["community_root"]), &h(&k["channel_id"]), 0).into();
    let opened = open_plane_wrap(&event(&v["chat_wrap"]["wrap"]), &stream, Plane::Chat).unwrap();
    let want = &v["chat_wrap"]["rumor"];
    assert_eq!(opened.rumor.id, want["id"].as_str().unwrap());
    assert_eq!(opened.rumor.content, want["content"].as_str().unwrap());
    assert_eq!(opened.author(), k["alice"].as_str().unwrap());
    assert_eq!(opened.ms, 1_700_000_000_417);
    check_channel_binding(&opened.rumor, k["channel_id"].as_str().unwrap(), 0).unwrap();
    assert!(check_channel_binding(&opened.rumor, k["channel_id"].as_str().unwrap(), 1).is_err());
    // The wrong stream refuses it.
    let other: StreamKey = channel_group_key(&h(&k["community_root"]), &h(&k["channel_id"]), 1).into();
    assert!(open_wrap(&event(&v["chat_wrap"]["wrap"]), &other).is_err());
}

#[test]
fn rust_wraps_round_trip() {
    let v = vectors();
    let k = &v["keys"];
    let stream: StreamKey = channel_group_key(&h(&k["community_root"]), &h(&k["channel_id"]), 0).into();
    let alice = keys(&k["alice_sk"]);
    let b = concord::chat::Binding { channel_id_hex: k["channel_id"].as_str().unwrap(), epoch: 0 };
    let rumor = concord::chat::message(&b, &alice.public_key().to_hex(), "héllo \u{1F389}".into(), None, None, vec![], 1_700_000_123_456, Some(60));
    let wrap = concord::stream::seal_and_wrap(&rumor, Plane::Chat, &stream, &alice, Default::default()).unwrap();
    let opened = open_plane_wrap(&wrap, &stream, Plane::Chat).unwrap();
    assert_eq!(opened.rumor, rumor);
    assert_eq!(opened.rumor.tag_value("expiration"), Some("1700000183"));
}

fn membership(v: &Value) -> Membership {
    let k = &v["keys"];
    let bundle = serde_json::json!({
        "community_id": k["community_id"], "owner": k["owner"], "owner_salt": k["owner_salt"],
        "community_root": k["community_root"], "root_epoch": 0, "control_pk": v["control"]["control_pk"],
        "channels": [], "relays": [], "name": "x",
    });
    Membership::from_bundle(&serde_json::from_value::<concord::invite::InviteBundle>(bundle).unwrap().validate().unwrap(), 0)
}

#[test]
fn control_fold_matches_armada() {
    let v = vectors();
    let m = membership(&v);
    let streams = m.control_streams();
    let editions: Vec<_> = v["control"]["wraps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| parse_edition(open_plane_wrap(&event(w), &streams[0], Plane::Control).unwrap()).unwrap())
        .collect();
    let folded = fold_control(&editions, &m.id(), &m.owner, None, None);
    let want = &v["control"]["expect"];
    assert_eq!(folded.metadata.as_ref().unwrap().name, want["name"].as_str().unwrap());
    let want_channels = want["channels"].as_object().unwrap();
    assert_eq!(folded.channels.len(), want_channels.len());
    for (id, c) in want_channels {
        let got = &folded.channels[id];
        assert_eq!(got.name, c["name"].as_str().unwrap());
        assert_eq!(got.private, c["private"].as_bool().unwrap());
    }
    let banned: HashSet<String> = want["banned"].as_array().unwrap().iter().map(|b| b.as_str().unwrap().to_owned()).collect();
    assert_eq!(folded.banned, banned);
    assert_eq!(folded.roster.roles.len(), 1);
    assert_eq!(folded.roster.grants.len(), 1);
    assert_eq!(folded.channels["0202020202020202020202020202020202020202020202020202020202020202"].position, Some(1.0));

    // Without the control_pk's signature, a forged wrap must be refused.
    let read = control_group_key(&m.root_key(), &m.id(), 0);
    let mut forged_stream: StreamKey = (&read).into();
    forged_stream.pk = streams[0].pk;
    forged_stream.restricted = false;
    let forged = concord::stream::seal_and_wrap(&editions[0].opened.rumor, Plane::Control, &(&read).into(), &keys(&v["keys"]["owner_sk"]), Default::default()).unwrap();
    assert!(open_wrap(&forged, &streams[0]).is_err());

    let views = m.channels(Some(&folded));
    assert_eq!(views.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["random", "lobby"]);
}

#[test]
fn invites_match() {
    let v = vectors();
    let i = &v["invite"];
    let token: [u8; 16] = [0x99; 16];
    assert_eq!(encode_fragment(&token, &stock_relays()).unwrap(), i["fragment_stock"].as_str().unwrap());
    let custom: Vec<String> = ["wss://relay.ditto.pub", "wss://relay.example.com", "ws://localhost:7777"].map(String::from).to_vec();
    assert_eq!(encode_fragment(&token, &custom).unwrap(), i["fragment_custom"].as_str().unwrap());
    assert_eq!(decode_fragment(i["fragment_custom"].as_str().unwrap()).unwrap(), (token, custom));

    let link = parse_invite_link(i["url"].as_str().unwrap()).unwrap();
    assert_eq!(link.link_signer, i["link_signer"].as_str().unwrap());
    assert_eq!(link.token, token);
    assert_eq!(link.bootstrap_relays, ["wss://relay.ditto.pub", "wss://relay.example.com"]);

    let bundle = parse_bundle_event(&event(&i["bundle_event"]), &link, 0).unwrap();
    assert_eq!(bundle.name, "Test Community");
    assert_eq!(bundle.channels[0].epoch, 3);
    assert_eq!(bundle.label.as_deref(), Some("Reddit"));
    assert!(parse_invite_link("https://example.com/not-an-invite#abc").is_err());
}

#[test]
fn adopts_armada_refounding() {
    let v = vectors();
    let mut m = membership(&v);
    let address = m.next_base_rekey_address();
    let stream: StreamKey = (&address).into();
    let parsed: Vec<_> = v["rekey"]["wraps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| parse_rekey(&open_plane_wrap(&event(w), &stream, Plane::Rekey).unwrap()).unwrap())
        .collect();
    let rotations = group_rotations(parsed);
    let folded = concord::control::FoldedControl { owner: m.owner.clone(), ..Default::default() };

    // Alice is a member: she gets the root and control_pk, not the control_root.
    let alice = keys(&v["keys"]["alice_sk"]);
    let mut am = m.clone();
    assert_eq!(am.apply_base_rotations(&rotations, &folded, &alice), RekeyOutcome::AdoptedRoot(1));
    assert_eq!(am.root, v["rekey"]["new_root"].as_str().unwrap());
    assert_eq!(am.control_pk.as_deref(), v["rekey"]["new_control_pk"].as_str());
    assert!(am.control_root.is_none());
    assert_eq!(am.held_roots.len(), 2);
    assert_eq!(am.held_roots[1].retired_at, Some(1_700_000_100));

    // The owner (staff) also gets the control_root, and can then write Control.
    let owner = keys(&v["keys"]["owner_sk"]);
    assert_eq!(m.apply_base_rotations(&rotations, &folded, &owner), RekeyOutcome::AdoptedRoot(1));
    assert_eq!(m.control_root.as_deref(), v["rekey"]["new_control_root"].as_str());
    assert!(m.current_control_stream().sk.is_some());

    // Bob joined before the rotation and got no blob; the owner outranks him.
    let bob = keys(&v["keys"]["bob_sk"]);
    let mut bm = membership(&v);
    assert_eq!(bm.apply_base_rotations(&rotations, &folded, &bob), RekeyOutcome::Excluded(1));
}

#[test]
fn guestbook_and_comment_tags_match() {
    let v = vectors();
    let m = membership(&v);
    let opened = open_plane_wrap(&event(&v["guestbook"]["wrap"]), &m.current_guestbook_stream(), Plane::Guestbook).unwrap();
    let rebuilt = concord::guestbook::join(opened.author(), opened.ms, Some((v["keys"]["owner"].as_str().unwrap(), "Reddit")));
    assert_eq!(rebuilt.id, opened.rumor.id);

    let r = &v["chat_wrap"]["rumor"];
    let tags: Vec<Vec<String>> = serde_json::from_value(r["tags"].clone()).unwrap();
    let parent = concord::chat::Target { id: r["id"].as_str().unwrap(), kind: 9, author: r["pubkey"].as_str().unwrap(), tags: &tags };
    let want: Vec<Vec<String>> = serde_json::from_value(v["comment_tags"].clone()).unwrap();
    assert_eq!(concord::chat::comment_tags(&parent), want);
}
