// Generates cross-implementation test vectors from Armada's own Concord code, so
// the Rust crate is checked against the implementation it must interoperate with.
//
//   bun tools/vectors/gen.ts > crates/concord/tests/vectors/armada.json
//
// ARMADA points at a checkout of the Armada client (default ~/Projects/armada).

import { finalizeEvent, getPublicKey } from "nostr-tools/pure";
import { encrypt as nip44Encrypt, getConversationKey } from "nostr-tools/nip44";
import { homedir } from "node:os";

const ARMADA = process.env.ARMADA ?? `${homedir()}/Projects/armada`;
// Vite injects this at build time; some transitive imports read it.
(globalThis as any).__ARMADA_BUILD_CONFIG__ = {};
const lib = (m: string) => import(`${ARMADA}/src/concord/lib/${m}.ts`);

const derive = await lib("derive");
const stream = await lib("stream");
const version = await lib("version");
const edition = await lib("edition");
const control = await lib("control");
const invite = await lib("invite");
const rekey = await lib("rekey");
const guestbook = await lib("guestbook");
const chat = await lib("chat");

const { bytesToHex, hexToBytes } = derive;
const h = (s: string) => hexToBytes(s);
const fill = (b: number) => new Uint8Array(32).fill(b);

const signer = (sk: Uint8Array) => ({ signEvent: async (t: any) => finalizeEvent(t, sk) });
const gk = (k: any) => ({ sk: bytesToHex(k.sk), pk: k.pk, conv_key: bytesToHex(k.convKey) });

const ownerSk = fill(0x11);
const owner = getPublicKey(ownerSk);
const aliceSk = fill(0x22);
const alice = getPublicKey(aliceSk);
const bobSk = fill(0x33);
const bob = getPublicKey(bobSk);
const ownerSalt = fill(0x44);
const communityId = derive.communityIdOf(h(owner), ownerSalt);
const root = fill(0x55);
const controlRoot = fill(0x66);
const channelId = fill(0x77);
const privateKey = fill(0x88);

const out: Record<string, unknown> = {};

out.keys = {
  owner_sk: bytesToHex(ownerSk), owner,
  alice_sk: bytesToHex(aliceSk), alice,
  bob_sk: bytesToHex(bobSk), bob,
  owner_salt: bytesToHex(ownerSalt),
  community_id: bytesToHex(communityId),
  community_root: bytesToHex(root),
  control_root: bytesToHex(controlRoot),
  channel_id: bytesToHex(channelId),
  private_channel_key: bytesToHex(privateKey),
};

out.derive = {
  channel_public_e0: gk(derive.channelGroupKey(root, channelId, 0)),
  channel_private_e3: gk(derive.channelGroupKey(privateKey, channelId, 3)),
  control_e0: gk(derive.controlGroupKey(root, communityId, 0)),
  control_signer_e0: gk(derive.controlSignerGroupKey(controlRoot, communityId, 0)),
  guestbook_e2: gk(derive.guestbookGroupKey(root, communityId, 2)),
  dissolved: gk(derive.dissolvedGroupKey(communityId)),
  channel_rekey_e4: gk(derive.channelRekeyGroupKey(root, channelId, 4)),
  base_rekey_e1: gk(derive.baseRekeyGroupKey(root, communityId, 1)),
  grant_locator_alice: bytesToHex(derive.grantLocator(communityId, h(alice))),
  pins_locator: bytesToHex(derive.pinsLocator(communityId, channelId)),
  banlist_locator: bytesToHex(derive.banlistLocator(communityId)),
  invite_links_locator_owner: bytesToHex(derive.inviteLinksLocator(communityId, h(owner))),
  signal_locator_pause: bytesToHex(derive.signalLocator(communityId, "pause")),
  recipient_locator: bytesToHex(derive.recipientLocator(h(owner), h(alice), new Uint8Array(32), 1)),
  invite_bundle_key: bytesToHex(derive.inviteBundleKey(new Uint8Array(16).fill(0x99))),
  epoch_key_commitment: bytesToHex(derive.epochKeyCommitment(7, root)),
};

out.edition_hash = {
  entity_id: bytesToHex(channelId),
  version: "2",
  prev: bytesToHex(fill(0xab)),
  content: '{"name":"général","private":false}',
  hash: bytesToHex(version.editionHash(channelId, 2n, fill(0xab), new TextEncoder().encode('{"name":"général","private":false}'))),
  hash_no_prev: bytesToHex(version.editionHash(channelId, 1n, undefined, new TextEncoder().encode("{}"))),
};

// A chat message wrapped by Armada, for the Rust side to open.
const chan = derive.channelGroupKey(root, channelId, 0);
const msgRumor = stream.buildRumor({
  kind: 9,
  content: "Hey chat! \"quoted\" \n émoji 🎉 </script>",
  tags: [...stream.channelBindingTags(bytesToHex(channelId), 0n), ["q", "ab".repeat(32), "", owner]],
  pubkey: alice,
  ms: 1_700_000_000_417,
});
const msgSeal = await stream.sealRumor(msgRumor, 20013, chan, signer(aliceSk));
const msgWrap = stream.wrapSeal(msgSeal, chan);
out.chat_wrap = { wrap: msgWrap, rumor: msgRumor };

// The Control Plane: owner genesis (metadata + #general), a role, a grant to Alice,
// a channel added by Alice under that grant, and a banlist naming Bob.
const controlRead = derive.controlGroupKey(root, communityId, 0);
const controlSigner = derive.controlSignerGroupKey(controlRoot, communityId, 0);
const controlWrite = { sk: controlSigner.sk, pk: controlSigner.pk, get convKey() { return controlRead.convKey; } };
const editions: any[] = [];
const publish = async (rumor: any, sk: Uint8Array) => {
  const wrap = await control.sealEdition(rumor, controlWrite, signer(sk));
  editions.push(wrap);
  return rumor;
};
const general = fill(0x01);
const random = fill(0x02);
const roleId = bytesToHex(fill(0x03));
await publish(control.buildMetadataEdition(communityId, { name: "Test Community", description: "desc", relays: ["wss://relay.example"] }, { actorPubkey: owner, version: 1n, createdAtSecs: 1_700_000_000 }), ownerSk);
const generalRumor = await publish(control.buildChannelEdition(general, { name: "general", private: false }, { actorPubkey: owner, version: 1n, createdAtSecs: 1_700_000_001 }), ownerSk);
await publish(control.buildRoleEdition({ roleId, name: "Admin", position: 1, permissions: (1n << 1n) | (1n << 0n), scope: { kind: "server" }, color: 0 }, { actorPubkey: owner, version: 1n, createdAtSecs: 1_700_000_002 }), ownerSk);
const grantRumor = control.buildGrantEdition(communityId, { member: alice, roleIds: [roleId] }, { actorPubkey: owner, version: 1n, createdAtSecs: 1_700_000_003 });
await publish(grantRumor, ownerSk);
const grantEid = derive.grantLocator(communityId, h(alice));
const grantHash = version.editionHash(grantEid, 1n, undefined, new TextEncoder().encode(grantRumor.content));
const authority = { entityId: grantEid, version: 1n, editionHash: grantHash };
await publish(control.buildChannelEdition(random, { name: "random", private: false, custom: { "armada.order": { position: 1 } } }, { actorPubkey: alice, version: 1n, createdAtSecs: 1_700_000_004, authority }), aliceSk);
// Alice renames #general (v2) — authorized by MANAGE_CHANNELS.
const generalHash = version.editionHash(general, 1n, undefined, new TextEncoder().encode(generalRumor.content));
await publish(control.buildChannelEdition(general, { name: "lobby", private: false }, { actorPubkey: alice, version: 2n, prevHash: generalHash, createdAtSecs: 1_700_000_005, authority }), aliceSk);
// Bob (no roles) tries to rename #random: must be dropped.
await publish(control.buildChannelEdition(random, { name: "pwned", private: false }, { actorPubkey: bob, version: 2n, prevHash: version.editionHash(random, 1n, undefined, new TextEncoder().encode('{"name":"random","private":false,"custom":{"armada.order":{"position":1}}}')), createdAtSecs: 1_700_000_006 }), bobSk);
await publish(control.buildBanlistEdition(communityId, [bob], { actorPubkey: owner, version: 1n, createdAtSecs: 1_700_000_007 }), ownerSk);

const community = {
  id: communityId, idHex: bytesToHex(communityId), owner, ownerSalt, root, rootEpoch: 0n,
  controlPk: controlSigner.pk, heldRoots: [{ epoch: 0n, key: root, controlPk: controlSigner.pk }],
  privateChannels: [], relays: [], name: "x",
};
const parsed = control.openControlWraps(editions, control.controlGroups(community));
const folded = control.foldControlState(parsed, communityId, owner);
out.control = {
  control_pk: controlSigner.pk,
  wraps: editions,
  expect: {
    name: folded.metadata?.name,
    channels: Object.fromEntries([...folded.channels].map(([id, c]: any) => [id, { name: c.name, private: c.isPrivate, deleted: c.deleted }])),
    banned: [...folded.banned],
    roles: folded.roster.roles.map((r: any) => r.roleId),
    grants: folded.roster.grants.map((g: any) => [g.member, g.roleIds]),
  },
};

// Invite links.
const token = new Uint8Array(16).fill(0x99);
const linkSignerSk = fill(0xaa);
const linkSigner = getPublicKey(linkSignerSk);
const bundle = {
  community_id: bytesToHex(communityId), owner, owner_salt: bytesToHex(ownerSalt),
  community_root: bytesToHex(root), root_epoch: 0, control_pk: controlSigner.pk,
  channels: [{ id: bytesToHex(channelId), key: bytesToHex(privateKey), epoch: 3, name: "secret" }],
  relays: ["wss://relay.example"], name: "Test Community", creator_npub: owner, label: "Reddit",
};
out.invite = {
  fragment_stock: invite.encodeFragment(token, invite.STOCK_RELAYS),
  fragment_custom: invite.encodeFragment(token, ["wss://relay.ditto.pub", "wss://relay.example.com", "ws://localhost:7777"]),
  url: invite.buildInviteUrl("https://armada.buzz", linkSigner, token, ["wss://relay.ditto.pub", "wss://relay.example.com"]),
  link_signer: linkSigner,
  token: bytesToHex(token),
  bundle_event: invite.buildBundleEvent(bundle, token, linkSignerSk),
  bundle,
};

// A base rekey (Refounding to epoch 1) by the owner, carrying blobs for Alice (member) and the owner (staff).
const newRoot = fill(0xbb);
const newControlRoot = fill(0xcc);
const newControlPk = derive.controlSignerGroupKey(newControlRoot, communityId, 1).pk;
const prevCommit = bytesToHex(derive.epochKeyCommitment(0, root));
const memberPlain = rekey.bytesToBase64(rekey.encodeWrappedBaseKey(1n, newRoot, h(newControlPk)));
const staffPlain = rekey.bytesToBase64(rekey.encodeWrappedBaseKey(1n, newRoot, h(newControlPk), newControlRoot));
const blobs = [
  { locator: rekey.myLocator(owner, alice, "0".repeat(64), 1n), wrapped: nip44Encrypt(memberPlain, getConversationKey(ownerSk, alice)) },
  { locator: rekey.myLocator(owner, owner, "0".repeat(64), 1n), wrapped: nip44Encrypt(staffPlain, getConversationKey(ownerSk, owner)) },
];
const rekeyRumors = rekey.buildRekeyRumors(owner, { scope: { kind: "root" }, newEpoch: 1n, prevEpoch: 0n, prevCommit }, blobs, 1_700_000_100_000);
const baseAddress = derive.baseRekeyGroupKey(root, communityId, 1);
out.rekey = {
  new_root: bytesToHex(newRoot),
  new_control_root: bytesToHex(newControlRoot),
  new_control_pk: newControlPk,
  prev_commit: prevCommit,
  wraps: await Promise.all(rekeyRumors.map(async (r: any) => stream.wrapSeal(await stream.sealRumor(r, 20013, baseAddress, signer(ownerSk)), baseAddress))),
};

// A Guestbook join by Alice and a thread reply.
const gb = derive.guestbookGroupKey(root, communityId, 0);
out.guestbook = {
  wrap: await guestbook.sealGuestbook(guestbook.buildJoinRumor(alice, 1_700_000_200_000, { creator: owner, label: "Reddit" }), gb, signer(aliceSk)),
};
out.comment_tags = chat.buildConcordCommentTags({ id: msgRumor.id, kind: 9, pubkey: alice, tags: msgRumor.tags });

console.log(JSON.stringify(out, null, 2));
