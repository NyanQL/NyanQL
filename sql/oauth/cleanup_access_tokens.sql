DELETE FROM oauth_access_tokens
WHERE expires_at < /*now*/ 0
   OR (revoked_at IS NOT NULL AND revoked_at < /*history_cutoff*/ 0);
