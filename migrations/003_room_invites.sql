-- Invite links for rooms
CREATE TABLE room_invites (
    id UUID PRIMARY KEY,
    room_id UUID NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    code TEXT NOT NULL UNIQUE,
    created_by UUID NOT NULL REFERENCES users(id),
    max_uses INT,
    use_count INT NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_room_invites_code ON room_invites (code);
CREATE INDEX idx_room_invites_room ON room_invites (room_id);
