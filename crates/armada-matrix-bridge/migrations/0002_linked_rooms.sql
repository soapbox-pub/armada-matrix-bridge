-- space: the bot built a space and a room per channel (`bridge <invite link>`).
-- linked: the bot was invited on Armada, and existing Matrix rooms are linked to
-- channels one by one (`!armada link` + `/bridge link <code>`). It owns no rooms.
ALTER TABLE communities ADD COLUMN mode TEXT NOT NULL DEFAULT 'space' CHECK (mode IN ('space', 'linked'));

-- Codes `!armada link` hands out, redeemed with `/bridge link <code>` on Armada.
CREATE TABLE link_codes (
    code       TEXT PRIMARY KEY,
    room_id    TEXT NOT NULL,
    mxid       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Whether a management room is a DM (commands need no prefix there).
ALTER TABLE management_rooms ADD COLUMN direct BOOLEAN NOT NULL DEFAULT true;
