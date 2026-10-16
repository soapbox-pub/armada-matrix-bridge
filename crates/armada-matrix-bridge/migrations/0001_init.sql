-- One row per Armada community the bridge has joined. `membership` holds the
-- community keys and is sealed under a key derived from the master secret.
CREATE TABLE communities (
    community_id    TEXT PRIMARY KEY,
    membership      BYTEA NOT NULL,
    -- pending: joined, waiting for an Armada admin's `/bridge approve`.
    -- active: bridged. revoked: an Armada admin or Matrix admin unbridged it.
    status          TEXT NOT NULL CHECK (status IN ('pending', 'active', 'revoked')),
    approval_code   TEXT,
    requested_by    TEXT NOT NULL,
    approved_by     TEXT,
    space_room_id   TEXT UNIQUE,
    -- The room where the requester manages this bridge (their DM with the bot).
    management_room TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Raw wraps of the planes that must be folded whole (control, guestbook, rekey).
-- They are relay ciphertext, so storing them adds no exposure.
CREATE TABLE plane_wraps (
    community_id TEXT NOT NULL REFERENCES communities ON DELETE CASCADE,
    plane        TEXT NOT NULL,
    wrap_id      TEXT NOT NULL,
    stream_pk    TEXT NOT NULL,
    created_at   BIGINT NOT NULL,
    event        JSONB NOT NULL,
    PRIMARY KEY (community_id, wrap_id)
);
CREATE INDEX plane_wraps_plane ON plane_wraps (community_id, plane);

-- One Matrix room per bridged channel.
CREATE TABLE portals (
    community_id TEXT NOT NULL REFERENCES communities ON DELETE CASCADE,
    channel_id   TEXT NOT NULL,
    room_id      TEXT NOT NULL UNIQUE,
    -- Private channels are bridged only when an Armada admin includes them;
    -- public ones unless excluded.
    enabled      BOOLEAN NOT NULL DEFAULT true,
    encrypted    BOOLEAN NOT NULL DEFAULT false,
    name         TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (community_id, channel_id)
);

-- Per-channel bridging decisions made before a portal exists.
CREATE TABLE channel_settings (
    community_id TEXT NOT NULL REFERENCES communities ON DELETE CASCADE,
    channel_id   TEXT NOT NULL,
    enabled      BOOLEAN NOT NULL,
    changed_by   TEXT NOT NULL,
    PRIMARY KEY (community_id, channel_id)
);

-- Rumor ↔ Matrix event. A long Armada message may split into several Matrix
-- events (`part`); attachments get their own parts too.
CREATE TABLE messages (
    room_id      TEXT NOT NULL,
    event_id     TEXT NOT NULL,
    community_id TEXT NOT NULL REFERENCES communities ON DELETE CASCADE,
    channel_id   TEXT NOT NULL,
    rumor_id     TEXT NOT NULL,
    part         INT NOT NULL DEFAULT 0,
    kind         INT NOT NULL,
    author       TEXT NOT NULL,
    -- 'armada' if it started on Armada, 'matrix' if on Matrix.
    origin       TEXT NOT NULL CHECK (origin IN ('armada', 'matrix')),
    -- The Matrix thread root this event belongs to, for replies in threads.
    thread_root  TEXT,
    expires_at   BIGINT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (room_id, event_id)
);
CREATE UNIQUE INDEX messages_rumor ON messages (community_id, rumor_id, part);

-- Reactions are separate because both sides key them by (target, reactor, key).
CREATE TABLE reactions (
    room_id         TEXT NOT NULL,
    event_id        TEXT NOT NULL,
    community_id    TEXT NOT NULL REFERENCES communities ON DELETE CASCADE,
    rumor_id        TEXT NOT NULL,
    target_rumor_id TEXT NOT NULL,
    author          TEXT NOT NULL,
    key             TEXT NOT NULL,
    origin          TEXT NOT NULL CHECK (origin IN ('armada', 'matrix')),
    PRIMARY KEY (room_id, event_id)
);
CREATE UNIQUE INDEX reactions_rumor ON reactions (community_id, rumor_id);

-- Armada members as Matrix users.
CREATE TABLE ghosts (
    pubkey        TEXT PRIMARY KEY,
    mxid          TEXT NOT NULL UNIQUE,
    registered    BOOLEAN NOT NULL DEFAULT false,
    displayname   TEXT,
    avatar_url    TEXT,
    avatar_mxc    TEXT,
    profile_at    BIGINT NOT NULL DEFAULT 0
);

-- Matrix users as Armada members. The key derives from the MXID; this table is
-- the reverse lookup (pubkey → MXID) plus what has been published for them.
CREATE TABLE puppets (
    pubkey       TEXT PRIMARY KEY,
    mxid         TEXT NOT NULL UNIQUE,
    profile_hash TEXT
);

CREATE TABLE puppet_joins (
    community_id TEXT NOT NULL REFERENCES communities ON DELETE CASCADE,
    pubkey       TEXT NOT NULL,
    root_epoch   BIGINT NOT NULL,
    PRIMARY KEY (community_id, pubkey, root_epoch)
);

-- Which bridge-owned users are joined to which rooms, to skip redundant joins.
CREATE TABLE room_members (
    room_id TEXT NOT NULL,
    mxid    TEXT NOT NULL,
    PRIMARY KEY (room_id, mxid)
);

-- Per-relay, per-subscription high-water marks for catching up after downtime.
CREATE TABLE cursors (
    scope      TEXT NOT NULL,
    relay      TEXT NOT NULL,
    newest     BIGINT NOT NULL,
    PRIMARY KEY (scope, relay)
);

-- Appservice transactions already processed (the homeserver retries).
CREATE TABLE transactions (
    txn_id     TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Direct Invites seen, so each is processed once.
CREATE TABLE direct_invites (
    wrap_id      TEXT PRIMARY KEY,
    community_id TEXT,
    inviter      TEXT,
    received_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Management rooms (DMs between a Matrix user and the bot).
CREATE TABLE management_rooms (
    room_id TEXT PRIMARY KEY,
    mxid    TEXT NOT NULL
);
