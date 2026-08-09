DELETE FROM oauth_authorization_codes
WHERE expires_at < /*now*/ 0
   OR (consumed_at IS NOT NULL AND consumed_at < /*history_cutoff*/ 0);
