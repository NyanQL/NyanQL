UPDATE oauth_refresh_tokens
SET revoked_at = COALESCE(revoked_at, CAST(strftime('%s', 'now') AS INTEGER))
WHERE family_id = /*family_id*/ 0;
