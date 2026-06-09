-- Room visibility: public (anyone), authenticated (logged-in users only), private (members only)
CREATE TYPE room_visibility AS ENUM ('public', 'authenticated', 'private');

ALTER TABLE rooms ADD COLUMN visibility room_visibility NOT NULL DEFAULT 'public';
