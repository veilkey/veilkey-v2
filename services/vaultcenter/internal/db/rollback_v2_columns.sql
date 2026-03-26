-- Rollback: Remove v2 path-based reference columns from token_refs
-- Safe for v1 data: these columns are empty ('') for all v1 records
--
-- Usage:
--   sqlite3 <db_path> < rollback_v2_columns.sql
--
-- WARNING: This will permanently remove v2 reference data.
-- Ensure no v2 refs are in active use before running.

BEGIN;

-- Drop indexes first
DROP INDEX IF EXISTS idx_token_refs_vault;
DROP INDEX IF EXISTS idx_token_refs_vault_path;

-- SQLite does not support DROP COLUMN before 3.35.0.
-- For older SQLite/SQLCipher, recreate the table without v2 columns.

CREATE TABLE token_refs_backup AS
SELECT
    ref_canonical,
    ref_family,
    ref_scope,
    ref_id,
    secret_name,
    agent_hash,
    plaintext_hash,
    ciphertext,
    version,
    status,
    expires_at,
    created_at
FROM token_refs;

DROP TABLE token_refs;

CREATE TABLE token_refs (
    ref_canonical TEXT PRIMARY KEY,
    ref_family    TEXT NOT NULL,
    ref_scope     TEXT NOT NULL,
    ref_id        TEXT NOT NULL,
    secret_name   TEXT NOT NULL DEFAULT '',
    agent_hash    TEXT DEFAULT '',
    plaintext_hash TEXT DEFAULT '',
    ciphertext    TEXT NOT NULL,
    version       INTEGER NOT NULL,
    status        TEXT DEFAULT 'temp',
    expires_at    DATETIME,
    created_at    DATETIME
);

INSERT INTO token_refs SELECT * FROM token_refs_backup;
DROP TABLE token_refs_backup;

-- Recreate v1 indexes
CREATE UNIQUE INDEX IF NOT EXISTS idx_token_refs_ref_canonical ON token_refs(ref_canonical);
CREATE INDEX IF NOT EXISTS idx_token_refs_family_scope ON token_refs(ref_family, ref_scope);
CREATE INDEX IF NOT EXISTS idx_token_refs_ref_id ON token_refs(ref_id);
CREATE INDEX IF NOT EXISTS idx_token_refs_secret_name ON token_refs(secret_name);
CREATE INDEX IF NOT EXISTS idx_token_refs_agent_hash ON token_refs(agent_hash);
CREATE INDEX IF NOT EXISTS idx_token_refs_plaintext_hash ON token_refs(plaintext_hash);
CREATE INDEX IF NOT EXISTS idx_token_refs_expires_at ON token_refs(expires_at);

COMMIT;
