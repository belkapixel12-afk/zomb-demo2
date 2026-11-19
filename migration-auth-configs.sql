-- Execute ONCE after migration-stage33.sql. Back up the D1 database first.
-- Existing verified flags were set automatically, so every existing user gets
-- a new seven-day confirmation period starting from this migration.
CREATE TABLE IF NOT EXISTS zomb_migrations (name TEXT PRIMARY KEY, applied_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS auth_security (
 user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 account_kind TEXT NOT NULL DEFAULT 'email' CHECK(account_kind IN ('email','device','google')),
 deadline INTEGER,
 warning_shown INTEGER NOT NULL DEFAULT 0,
 google_sub TEXT UNIQUE,
 created_at INTEGER NOT NULL
);
INSERT OR IGNORE INTO auth_security(user_id,account_kind,deadline,created_at)
 SELECT id,'email',CAST(strftime('%s','now') AS INTEGER)*1000+604800000,created_at FROM users;
UPDATE users SET email_verified=0 WHERE id IN (SELECT user_id FROM auth_security WHERE account_kind='email' AND google_sub IS NULL) AND NOT EXISTS (SELECT 1 FROM zomb_migrations WHERE name='auth-configs-v1');
INSERT OR IGNORE INTO zomb_migrations VALUES ('auth-configs-v1',CAST(strftime('%s','now') AS INTEGER)*1000);
CREATE TABLE IF NOT EXISTS auth_limits (id TEXT PRIMARY KEY, bucket INTEGER NOT NULL, attempts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS device_keys (
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS google_flows (
 state_hash TEXT PRIMARY KEY, secret_hash TEXT NOT NULL, verifier TEXT NOT NULL, nonce TEXT NOT NULL,
 action TEXT NOT NULL, user_id TEXT, nickname TEXT, status TEXT NOT NULL DEFAULT 'pending',
 result_user_id TEXT, result_error TEXT, expires_at INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS shared_configs_all (
 code TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 config_type TEXT NOT NULL, name TEXT NOT NULL, payload_json TEXT NOT NULL,
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, downloads INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO shared_configs_all SELECT * FROM shared_configs;
CREATE INDEX IF NOT EXISTS shared_configs_all_owner_idx ON shared_configs_all(owner_id,updated_at);
