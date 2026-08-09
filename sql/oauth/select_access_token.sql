SELECT
    at.id,
    at.token_hash,
    at.user_id,
    at.client_id,
    at.resource,
    at.scope,
    at.expires_at,
    at.refresh_family_id,
    u.username,
    u.display_name
FROM oauth_access_tokens AS at
JOIN oauth_users AS u ON u.id = at.user_id
JOIN oauth_clients AS c ON c.client_id = at.client_id
LEFT JOIN oauth_refresh_token_families AS rf ON rf.id = at.refresh_family_id
WHERE at.token_hash = /*token_hash*/ ''
  AND at.resource = /*resource*/ ''
  AND at.revoked_at IS NULL
  AND at.expires_at > CAST(strftime('%s', 'now') AS INTEGER)
  AND (at.refresh_family_id IS NULL OR (
      rf.revoked_at IS NULL
      AND rf.expires_at > CAST(strftime('%s', 'now') AS INTEGER)
  ))
  AND u.enabled = 1
  AND c.enabled = 1
LIMIT 1;
