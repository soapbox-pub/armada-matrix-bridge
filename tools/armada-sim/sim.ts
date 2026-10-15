// A minimal Armada client for end-to-end testing the bridge, built on Armada's
// own Concord library so it speaks exactly what the app speaks.
//
//   bun tools/armada-sim/sim.ts create "Test Community"   # owner mints a community + invite link
//   bun tools/armada-sim/sim.ts say general "hello"       # post as the owner (or --as alice)
//   bun tools/armada-sim/sim.ts tail 30                   # print decrypted chat for 30 s
//   bun tools/armada-sim/sim.ts channel random            # add a channel
//
// State (keys!) lives in tools/armada-sim/state.json, which is gitignored.

import { finalizeEvent, generateSecretKey, getPublicKey } from "nostr-tools/pure";
import { homedir } from "node:os";
import { existsSync, readFileSync, writeFileSync } from "node:fs";

const ARMADA = process.env.ARMADA ?? `${homedir()}/Projects/armada`;
(globalThis as any).__ARMADA_BUILD_CONFIG__ = {};
const lib = (m: string) => import(`${ARMADA}/src/concord/lib/${m}.ts`);
const derive = await lib("derive");
const stream = await lib("stream");
const control = await lib("control");
const invite = await lib("invite");
const guestbook = await lib("guestbook");
const communityLib = await lib("community");
const { bytesToHex, hexToBytes } = derive;

const STATE = new URL("./state.json", import.meta.url).pathname;
const RELAYS = (process.env.RELAYS ?? "wss://relay.ditto.pub").split(",");

type State = {
  owner: string; alice: string; bob: string;
  community: { id: string; owner: string; ownerSalt: string; root: string; controlRoot: string; controlPk: string; relays: string[]; name: string };
  channels: Record<string, string>;
  versions: Record<string, number>;
  heads: Record<string, string>;
  link?: string;
};

const load = (): State => JSON.parse(readFileSync(STATE, "utf8"));
const save = (s: State) => writeFileSync(STATE, JSON.stringify(s, null, 2));
const signer = (sk: Uint8Array) => ({ signEvent: async (t: any) => finalizeEvent(t, sk) });

function communityOf(s: State) {
  const c = s.community;
  return {
    id: hexToBytes(c.id), idHex: c.id, owner: c.owner, ownerSalt: hexToBytes(c.ownerSalt), root: hexToBytes(c.root), rootEpoch: 0n,
    controlPk: c.controlPk, controlRoot: hexToBytes(c.controlRoot),
    heldRoots: [{ epoch: 0n, key: hexToBytes(c.root), controlPk: c.controlPk }], privateChannels: [], relays: c.relays, name: c.name,
  };
}

// ── A tiny relay client that answers NIP-42 for every stream key it holds ──
class Relay {
  ws: WebSocket;
  open: Promise<void>;
  keys: Uint8Array[] = [];
  handlers = new Map<string, (ev: any) => void>();
  oks = new Map<string, (ok: boolean, msg: string) => void>();
  challenge?: string;
  constructor(public url: string) {
    this.ws = new WebSocket(url);
    this.open = new Promise((res, rej) => { this.ws.onopen = () => res(); this.ws.onerror = rej; });
    this.ws.onmessage = (m) => {
      const msg = JSON.parse(String(m.data));
      if (msg[0] === "AUTH") { this.challenge = msg[1]; this.authAll(); }
      else if (msg[0] === "EVENT") this.handlers.get(msg[1])?.(msg[2]);
      else if (msg[0] === "OK") this.oks.get(msg[1])?.(msg[2], msg[3]);
      else if (msg[0] === "CLOSED" && String(msg[2]).includes("auth-required")) setTimeout(() => this.resub(msg[1]), 500);
    };
  }
  subs = new Map<string, any>();
  authAll() {
    if (!this.challenge) return;
    for (const sk of this.keys) {
      this.ws.send(JSON.stringify(["AUTH", finalizeEvent({ kind: 22242, created_at: Math.floor(Date.now() / 1000), content: "", tags: [["relay", this.url], ["challenge", this.challenge]] }, sk)]));
    }
  }
  resub(id: string) { const f = this.subs.get(id); if (f) this.ws.send(JSON.stringify(["REQ", id, f])); }
  sub(id: string, filter: any, on: (ev: any) => void) { this.subs.set(id, filter); this.handlers.set(id, on); this.ws.send(JSON.stringify(["REQ", id, filter])); }
  publish(ev: any): Promise<string> {
    return new Promise((res) => {
      const t = setTimeout(() => res("timeout"), 8000);
      this.oks.set(ev.id, (ok, msg) => { clearTimeout(t); if (!ok && msg.includes("auth-required")) { setTimeout(() => this.publish(ev).then(res), 800); } else res(ok ? "ok" : msg); });
      this.ws.send(JSON.stringify(["EVENT", ev]));
    });
  }
}

async function relays(keys: Uint8Array[]) {
  const rs = RELAYS.map((u) => new Relay(u));
  await Promise.all(rs.map((r) => r.open));
  for (const r of rs) { r.keys = keys; r.authAll(); }
  await new Promise((r) => setTimeout(r, 700));
  return rs;
}

async function publishAll(rs: Relay[], ev: any) {
  const results = await Promise.all(rs.map((r) => r.publish(ev)));
  console.error(`published ${ev.kind} ${ev.id.slice(0, 8)}: ${results.join(", ")}`);
}

function streamKeys(s: State) {
  const c = communityOf(s);
  const out: Uint8Array[] = [];
  for (const id of Object.values(s.channels)) out.push(derive.channelGroupKey(c.root, hexToBytes(id), 0).sk);
  out.push(derive.guestbookGroupKey(c.root, c.id, 0).sk);
  out.push(derive.controlSignerGroupKey(c.controlRoot, c.id, 0).sk);
  return out;
}

async function publishEdition(s: State, rs: Relay[], rumor: any) {
  const c = communityOf(s);
  const write = control.currentControlWriteGroup(c);
  await publishAll(rs, await control.sealEdition(rumor, write, signer(hexToBytes(s.owner))));
}

async function addChannel(s: State, rs: Relay[], name: string, extra: Record<string, unknown> = {}) {
  const id = bytesToHex(derive.random32());
  s.channels[name] = id;
  const meta = { name, private: false, ...extra };
  const rumor = control.buildChannelEdition(hexToBytes(id), meta, { actorPubkey: getPublicKey(hexToBytes(s.owner)), version: 1n });
  await publishEdition(s, rs, rumor);
  save(s);
}

const [cmd, ...args] = process.argv.slice(2);
const who = (s: State) => {
  const i = process.argv.indexOf("--as");
  return hexToBytes(i > 0 ? (s as any)[process.argv[i + 1]] : s.owner);
};

if (cmd === "create") {
  const ownerSk = generateSecretKey();
  const owner = getPublicKey(ownerSk);
  const { community } = communityLib.mintCommunity(args[0] ?? "Bridge Test", owner, RELAYS);
  const s: State = {
    owner: bytesToHex(ownerSk), alice: bytesToHex(generateSecretKey()), bob: bytesToHex(generateSecretKey()),
    community: { id: community.idHex, owner, ownerSalt: bytesToHex(community.ownerSalt), root: bytesToHex(community.root), controlRoot: bytesToHex(community.controlRoot), controlPk: community.controlPk, relays: RELAYS, name: community.name },
    channels: {}, versions: {}, heads: {},
  };
  save(s);
  const rs = await relays([ownerSk, ...streamKeys(s)]);
  await publishEdition(s, rs, control.buildMetadataEdition(community.id, { name: community.name, description: "A community for testing the Matrix bridge", relays: RELAYS }, { actorPubkey: owner, version: 1n }));
  await addChannel(s, rs, "general");
  await addChannel(s, rs, "random", { custom: { "armada.order": { position: 1 } } });
  const linkSigner = invite.mintLinkSigner();
  const token = invite.mintToken();
  const bundle = { community_id: community.idHex, owner, owner_salt: bytesToHex(community.ownerSalt), community_root: bytesToHex(community.root), root_epoch: 0, control_pk: community.controlPk, channels: [], relays: RELAYS, name: community.name, creator_npub: owner };
  await publishAll(rs, invite.buildBundleEvent(bundle, token, linkSigner.sk));
  s.link = invite.buildInviteUrl("https://armada.buzz", linkSigner.pk, token, RELAYS);
  save(s);
  for (const name of ["owner", "alice"] as const) {
    const sk = hexToBytes((s as any)[name]);
    const gb = derive.guestbookGroupKey(community.root, community.id, 0);
    await publishAll(rs, await guestbook.sealGuestbook(guestbook.buildJoinRumor(getPublicKey(sk), Date.now()), gb, signer(sk)));
    await publishAll(rs, finalizeEvent({ kind: 0, created_at: Math.floor(Date.now() / 1000), tags: [], content: JSON.stringify({ name: name === "owner" ? "Olivia Owner" : "Alice Armada" }) }, sk));
  }
  console.log(s.link);
  process.exit(0);
} else if (cmd === "channel") {
  const s = load();
  const rs = await relays([hexToBytes(s.owner), ...streamKeys(s)]);
  await addChannel(s, rs, args[0]);
  process.exit(0);
} else if (cmd === "say") {
  const s = load();
  const sk = who(s);
  const c = communityOf(s);
  const channelId = s.channels[args[0]];
  const group = derive.channelGroupKey(c.root, hexToBytes(channelId), 0);
  const rs = await relays([sk, ...streamKeys(s)]);
  const tags = [...stream.channelBindingTags(channelId, 0n)];
  const replyIdx = process.argv.indexOf("--reply");
  if (replyIdx > 0) tags.push(["q", process.argv[replyIdx + 1], "", process.argv[replyIdx + 2] ?? ""]);
  const imetaIdx = process.argv.indexOf("--imeta");
  if (imetaIdx > 0) tags.push(JSON.parse(process.argv[imetaIdx + 1]));
  const threadIdx = process.argv.indexOf("--thread");
  if (threadIdx > 0) tags.push(["K", "9"], ["E", process.argv[threadIdx + 1], "", process.argv[threadIdx + 2]], ["P", process.argv[threadIdx + 2]], ["k", "9"], ["e", process.argv[threadIdx + 1], "", process.argv[threadIdx + 2]], ["p", process.argv[threadIdx + 2]]);
  const rumor = stream.buildRumor({ kind: threadIdx > 0 ? 1111 : 9, content: args[1], tags, pubkey: getPublicKey(sk), ms: Date.now() });
  await publishAll(rs, stream.wrapSeal(await stream.sealRumor(rumor, 20013, group, signer(sk)), group));
  console.log(rumor.id);
  process.exit(0);
} else if (cmd === "tail") {
  const s = load();
  const c = communityOf(s);
  const rs = await relays(streamKeys(s));
  const groups = new Map<string, any>();
  for (const [name, id] of Object.entries(s.channels)) groups.set(derive.channelGroupKey(c.root, hexToBytes(id), 0).pk, { name, id, g: derive.channelGroupKey(c.root, hexToBytes(id), 0) });
  const seen = new Set<string>();
  for (const r of rs) {
    r.sub("tail", { kinds: [1059], authors: [...groups.keys()], since: Math.floor(Date.now() / 1000) - Number(args[1] ?? 600) }, (wrap) => {
      if (seen.has(wrap.id)) return;
      seen.add(wrap.id);
      const ch = groups.get(wrap.pubkey);
      try {
        const o = stream.openWrap(wrap, ch.g);
        const proxy = o.tags.find((t: string[]) => t[0] === "proxy")?.[1];
        console.log(JSON.stringify({ channel: ch.name, kind: o.kind, author: o.author.slice(0, 8), content: o.content, id: o.rumorId, tags: o.tags.filter((t: string[]) => !["channel", "epoch", "ms"].includes(t[0])), proxy }));
      } catch (e) { console.error("undecryptable", e); }
    });
  }
  setTimeout(() => process.exit(0), Number(args[0] ?? 20) * 1000);
} else {
  console.error("usage: create <name> | channel <name> | say <channel> <text> [--as alice] [--reply <id> <author>] | tail <secs> [lookback]");
  process.exit(1);
}
