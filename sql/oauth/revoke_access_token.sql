UPDATE oauth_access_tokens
SET revoked_at = COALESCE(revoked_at, CAST(strftime('%s', 'now') AS INTEGER))
WHERE token_hash = /*token_hash*/ ''
  AND client_id = /*client_id*/ ''
RETURNING id, refresh_family_id;
