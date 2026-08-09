UPDATE oauth_refresh_token_families
SET revoked_at = COALESCE(revoked_at, CAST(strftime('%s', 'now') AS INTEGER))
WHERE id = /*family_id*/ 0
RETURNING id;
