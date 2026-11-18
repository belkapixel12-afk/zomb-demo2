-- ZOMB cloud config + email verification migration.
-- Run ONCE against the existing D1 database zomb-db.
-- Existing accounts are marked verified to avoid locking out current players.
ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS player_states (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  version INTEGER NOT NULL DEFAULT 1,
  state_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS player_states_updated_idx ON player_states(updated_at);

CREATE TABLE IF NOT EXISTS shared_configs (
  code TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  config_type TEXT NOT NULL CHECK(config_type IN ('controls','interface','lobby','music','profile')),
  name TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  downloads INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS shared_configs_owner_idx ON shared_configs(owner_id,updated_at);
CREATE INDEX IF NOT EXISTS shared_configs_type_idx ON shared_configs(config_type,created_at);

CREATE TABLE IF NOT EXISTS cloud_assets (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  object_key TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  content_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS cloud_assets_owner_idx ON cloud_assets(owner_id,created_at);

CREATE TABLE IF NOT EXISTS email_codes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  purpose TEXT NOT NULL CHECK(purpose IN ('verify')),
  code_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  used_at INTEGER,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS email_codes_user_purpose_idx ON email_codes(user_id,purpose,created_at);
CREATE INDEX IF NOT EXISTS email_codes_expiry_idx ON email_codes(expires_at);
