BEGIN IMMEDIATE;

-- 旧redirect URIポリシーで発行された可能性がある一時情報とtokenを無効化する。
DELETE FROM oauth_authorization_requests
WHERE NOT EXISTS (
    SELECT 1 FROM oauth_schema_migrations WHERE version = 2
);

DELETE FROM oauth_authorization_codes
WHERE NOT EXISTS (
    SELECT 1 FROM oauth_schema_migrations WHERE version = 2
);

UPDATE oauth_access_tokens
SET revoked_at = COALESCE(revoked_at, CAST(strftime('%s', 'now') AS INTEGER))
WHERE NOT EXISTS (
    SELECT 1 FROM oauth_schema_migrations WHERE version = 2
);

INSERT OR IGNORE INTO oauth_schema_migrations(version) VALUES (2);

COMMIT;
