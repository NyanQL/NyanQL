UPDATE oauth_refresh_tokens
SET consumed_at = CAST(strftime('%s', 'now') AS INTEGER)
WHERE id = /*refresh_token_id*/ 0
  AND consumed_at IS NULL
  AND revoked_at IS NULL
  AND expires_at > CAST(strftime('%s', 'now') AS INTEGER)
  AND EXISTS (
      SELECT 1
      FROM oauth_refresh_token_families AS rf
      JOIN oauth_users AS u ON u.id = rf.user_id
      JOIN oauth_clients AS c ON c.client_id = rf.client_id
      WHERE rf.id = oauth_refresh_tokens.family_id
        AND rf.revoked_at IS NULL
        AND rf.expires_at > CAST(strftime('%s', 'now') AS INTEGER)
        AND u.enabled = 1
        AND c.enabled = 1
  )
RETURNING id, family_id;
