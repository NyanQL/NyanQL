BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS oauth_refresh_token_families (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    client_id TEXT NOT NULL,
    resource TEXT NOT NULL,
    scope TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER)),
    FOREIGN KEY (user_id) REFERENCES oauth_users(id) ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64),
    family_id INTEGER NOT NULL,
    parent_id INTEGER,
    scope TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    revoked_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER)),
    FOREIGN KEY (family_id) REFERENCES oauth_refresh_token_families(id) ON DELETE CASCADE,
    FOREIGN KEY (parent_id) REFERENCES oauth_refresh_tokens(id) ON DELETE SET NULL
);

ALTER TABLE oauth_access_tokens
    ADD COLUMN refresh_family_id INTEGER
    REFERENCES oauth_refresh_token_families(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS oauth_refresh_token_families_client_idx
    ON oauth_refresh_token_families(client_id);
CREATE INDEX IF NOT EXISTS oauth_refresh_token_families_expiry_idx
    ON oauth_refresh_token_families(expires_at);
CREATE INDEX IF NOT EXISTS oauth_refresh_tokens_family_idx
    ON oauth_refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS oauth_refresh_tokens_expiry_idx
    ON oauth_refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS oauth_access_tokens_refresh_family_idx
    ON oauth_access_tokens(refresh_family_id);

-- v1/v2で登録済みのpublic clientも、新しいoffline-access profileへ揃える。
UPDATE oauth_clients
SET grant_types = '["authorization_code","refresh_token"]',
    scope = CASE
        WHEN instr(' ' || scope || ' ', ' offline_access ') = 0
            THEN trim(scope || ' offline_access')
        ELSE scope
    END,
    updated_at = CAST(strftime('%s', 'now') AS INTEGER);

INSERT OR IGNORE INTO oauth_schema_migrations(version) VALUES (3);

COMMIT;
