-- Moat initial schema

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Custom enum for member roles
CREATE TYPE member_role AS ENUM ('admin', 'publisher', 'subscriber');

-- Users table: stores IdP-verified identities
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL,
    idp_provider TEXT NOT NULL,
    idp_subject TEXT NOT NULL,
    display_name TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (idp_provider, idp_subject)
);

CREATE INDEX idx_users_email ON users (email);

-- Rooms table: each room maps to a MoQ namespace prefix
CREATE TABLE rooms (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    namespace_prefix TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Room membership: who can access what, with which role
CREATE TABLE room_members (
    id UUID PRIMARY KEY,
    room_id UUID NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role member_role NOT NULL DEFAULT 'subscriber',
    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (room_id, user_id)
);

CREATE INDEX idx_room_members_room ON room_members (room_id);
CREATE INDEX idx_room_members_user ON room_members (user_id);
