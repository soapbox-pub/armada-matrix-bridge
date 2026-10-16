# armada-matrix-bridge

A Matrix appservice that bridges [Armada](https://armada.buzz) communities to
Matrix. Armada runs on [Concord](https://github.com/concord-protocol/concord):
serverless, end-to-end encrypted communities on Nostr. This bridge joins one
as a member and mirrors it into a Matrix space.

- **A community becomes a space; each channel becomes a room.** The space
  follows Armada as channels are created, renamed, reordered and deleted.
- **Everyone keeps their own identity.**
  - Each Armada member is a separate Matrix user (`@armada_npub1…`), with the
    name and picture from their profile.
  - Each Matrix user posts to Armada under their own Armada key. The key is
    derived from their MXID, so it's stable without being stored.
  - No messages arrive as "the bridge says X said Y".
- **Both sides must agree.**
  - Any Matrix user with an invite link can start a bridge.
  - Nothing crosses until someone in the Armada community who can manage
    channels approves it there.
  - Armada admins can scope or revoke the bridge at any time.
- **Matrix end-to-end encryption.** Every Armada member speaking in an
  encrypted room has their own cross-signed device.

## What is bridged

| Armada | Matrix |
|---|---|
| Message (kind 9), markdown, `nostr:` mentions | `m.text` with HTML and pills |
| Inline reply (NIP-C7 `q`) | Reply |
| Thread reply (kind 1111) | Thread |
| Attachment (NIP-92 `imeta`, client-encrypted) | `m.image` / `m.video` / `m.audio` / `m.file` (encrypted in encrypted rooms) |
| Reaction (kind 7), custom emoji (NIP-30) | `m.reaction`, inline emoticons |
| Edit (kind 3302) | `m.replace` |
| Delete (kind 5), by the author or a moderator | Redaction |
| Typing (kind 23311) | Typing |
| Poll (kind 1068) | Text summary |
| Disappearing messages (CORD-08) | Redacted on Matrix when they expire on Armada |
| Kick or ban of a member | Their Armada user is removed from the rooms |
| Channels, names, order, community name/description/icon | Rooms, names, space order, space name/topic/avatar |

Every Matrix → Armada message carries a NIP-48 `proxy` tag linking back to its
Matrix event, which Armada shows as a "via Matrix" pill.

Redactions only cross to Armada when someone redacts their own message. A
Matrix moderator has no authority over Armada history, so redacting someone
else's message only hides it on Matrix.

## Consent and privacy

Concord communities are end-to-end encrypted. Bridging copies their messages
onto a Matrix homeserver, so:

- **Approval happens on Armada.** Any Matrix user with an invite link can ask
  to bridge a community. `bridge <invite>` only joins the community and shows
  an approval code. Nothing is relayed in either direction until a member
  holding **Manage channels** (or the owner) posts `/bridge approve <code>` in
  one of its channels. Requests nobody approves within 7 days are dropped, and
  each Matrix user may have 3 waiting at once.
- **Private channels are opt-in.** Public channels are bridged after approval.
  A private channel is bridged only when an Armada admin runs `/bridge include`
  inside it. Its room topic warns that everyone in the room can read it.
- **Armada stays in control.**
  - `/bridge exclude` stops a channel and `/bridge revoke` stops everything.
  - Kicking the bridge's npub, banning it, removing it in a key rotation, or
    dissolving the community all stop the bridge too.
- **Matrix rooms are invite-only.** The space and its rooms are private, and
  portal rooms only admit members of the space.
- **What Matrix still sees.** In unencrypted rooms the homeserver stores
  plaintext. Set `[encryption] default = true` for new rooms, or enable
  encryption in a room.
- **What becomes public on Nostr:**
  - Matrix users' display names and avatars, as their puppets' kind 0 profiles;
  - the bot's profile, DM relay list (10050), and command manifest (10304).
  - Message content never leaves the encrypted Concord streams.

## Armada commands

Post these in any channel of a bridged community.

| Command | Who | Effect |
|---|---|---|
| `/bridge approve <code>` | Manage channels | Start bridging (the code is shown on Matrix) |
| `/bridge status` | Anyone | Show what is bridged |
| `/bridge include` | Manage channels | Bridge this channel (required for private channels) |
| `/bridge exclude` | Manage channels | Stop bridging this channel |
| `/bridge revoke` | Manage channels | Stop bridging the community |

## Matrix commands

Send these in a direct message with the bot. The `!armada` prefix is optional
there.

| Command | Who | Effect |
|---|---|---|
| `bridge <invite link>` | Anyone | Ask to bridge a community, or join its space if it is already bridged |
| `list` | Anyone | Bridged communities whose space you're in |
| `status <community>` | Space members | One community's state |
| `invite <community> <@user:server>` | Space members | Invite someone into its space |
| `unbridge <community>` | Managers | Stop bridging and leave the community |

`<community>` is the start of its id or its name. A community's **managers**
are whoever bridged it and anyone with power level 100 in its space. Other
people's communities are invisible: commands answer "No such community".

"Anyone" means anyone allowed by `[permissions]`, which also decides whose
messages are bridged at all. Users given `admin` there manage every community
from Matrix; most deployments need none.

## Operator commands

The bridge needs no Matrix admin account. Whoever runs it manages every
community from the host, over a Unix socket (`control_socket`, only usable by
the bridge's user and root):

```sh
armada-matrix-bridge -c config.toml list        # every community, with who requested it
armada-matrix-bridge -c config.toml status <community>
armada-matrix-bridge -c config.toml invite <community> @user:server
armada-matrix-bridge -c config.toml unbridge <community>
```

## Setup

You need a recent Synapse and PostgreSQL. Encryption also needs the
Synapse experimental features listed below.

```sh
cargo build --release
cp config.example.toml config.toml    # edit: homeserver, database, master_secret
./target/release/armada-matrix-bridge -c config.toml generate-registration
```

Add the registration file to Synapse:

```yaml
app_service_config_files:
  - /path/to/registration.yaml
# Only for [encryption] enabled = true:
experimental_features:
  msc2409_to_device_messages_enabled: true
  msc3202_transaction_extensions: true
  msc4190_enabled: true
```

Restart Synapse, then run the bridge:

```sh
./target/release/armada-matrix-bridge -c config.toml
```

Start a direct message with `@armadabot:your.server` and send it an Armada
invite link. `deploy/` has a systemd unit and a Dockerfile.

**Back up `master_secret` and `crypto/`.**

- `master_secret` derives every Matrix user's Armada identity and seals the
  community keys in the database.
- `crypto/` holds each bridged user's Matrix device. Losing it means new,
  unverified devices, and encrypted history the bridge can no longer read.

## How it works

The workspace has three crates.

- **`crates/concord`** is a sans-IO implementation of Concord: key derivation,
  stream wraps, the Control Plane fold (the owner-rooted roster, channels,
  banlist, pins, signals), invites, Direct Invites, rekeys and Refoundings, the
  guestbook, chat rumors and attachments.
  - It is a port of Armada's `src/concord/lib`.
  - It is tested against vectors produced by Armada's own TypeScript
    (`tools/vectors/gen.ts`), so it is byte-compatible with the app.
- **`crates/relay-pool`** is a Nostr relay pool.
  - It answers NIP-42 for every derived stream key, which relays that gate
    gift wraps require.
  - It keeps subscriptions alive across reconnects.
- **`crates/armada-matrix-bridge`** is the appservice. Each community is one actor
  task, so its Nostr traffic and its Matrix rooms are handled in a single order.
  - **Startup:** the bridge folds the stored Control Plane, subscribes to every
    plane it holds keys for, and reconciles the space with the fold.
  - **Rotations:** it follows Refoundings and private-channel rekeys as a
    member, adopting new keys when its blob is in a rotation and stopping when a
    rotation removes it. When the bridge is invited to private channels by
    Direct Invite, it adopts their keys.
  - **Storage:** community keys are kept in Postgres, sealed with AES-256-GCM.
    Control, guestbook and rekey wraps are stored as received (ciphertext) and
    re-folded on start. Chat is caught up from a per-relay cursor.

## Development

`dev/` has a local stack: Synapse and Postgres in Docker, plus helper scripts.

- `tools/armada-sim/sim.ts` creates and drives a real Armada community through
  Armada's own library.
- `crates/e2ee-probe` is an encrypting Matrix client.

See `dev/README.md`.

```sh
cargo test --workspace
cargo clippy --workspace --all-targets
bun tools/vectors/gen.ts > crates/concord/tests/vectors/armada.json   # run from an Armada checkout
```

## Not yet

- **Matrix polls:** Armada polls arrive as text, and votes aren't bridged.
- **Zaps, calendar events, voice/video calls and Mini Apps** aren't bridged.
- **Custom emoji from Matrix to Armada:** reactions bridge as text.
- **Double puppeting:** Matrix users posting under their own existing Armada
  key, instead of a derived one.
- **NIP-29 / Buzz:** relay-hosted groups aren't supported, only Concord.

## License

AGPL-3.0-only.
