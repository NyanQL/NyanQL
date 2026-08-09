DELETE FROM oauth_refresh_token_families
WHERE (expires_at < /*now*/ 0
       OR (revoked_at IS NOT NULL AND revoked_at < /*history_cutoff*/ 0))
  AND NOT EXISTS (
      SELECT 1
      FROM oauth_refresh_tokens AS rt
      WHERE rt.family_id = oauth_refresh_token_families.id
  )
  AND NOT EXISTS (
      SELECT 1
      FROM oauth_access_tokens AS at
      WHERE at.refresh_family_id = oauth_refresh_token_families.id
        AND at.revoked_at IS NULL
        AND at.expires_at >= /*now*/ 0
  );
