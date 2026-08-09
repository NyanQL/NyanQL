DELETE FROM oauth_refresh_tokens
WHERE family_id IN (
    SELECT id
    FROM oauth_refresh_token_families
    WHERE expires_at < /*now*/ 0
       OR (revoked_at IS NOT NULL AND revoked_at < /*history_cutoff*/ 0)
);
