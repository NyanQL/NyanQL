UPDATE oauth_access_tokens
SET revoked_at = COALESCE(revoked_at, CAST(strftime('%s', 'now') AS INTEGER))
WHERE refresh_family_id = /*family_id*/ 0;
