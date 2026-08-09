DELETE FROM oauth_clients
WHERE created_at < /*client_cutoff*/ 0
  AND NOT EXISTS (
      SELECT 1
      FROM oauth_authorization_requests AS ar
      WHERE ar.client_id = oauth_clients.client_id
        AND ar.consumed_at IS NULL
        AND ar.expires_at >= /*now*/ 0
  )
  AND NOT EXISTS (
      SELECT 1
      FROM oauth_authorization_codes AS ac
      WHERE ac.client_id = oauth_clients.client_id
        AND ac.consumed_at IS NULL
        AND ac.expires_at >= /*now*/ 0
  )
  AND NOT EXISTS (
      SELECT 1
      FROM oauth_access_tokens AS at
      WHERE at.client_id = oauth_clients.client_id
        AND at.revoked_at IS NULL
        AND at.expires_at >= /*now*/ 0
  )
  AND NOT EXISTS (
      SELECT 1
      FROM oauth_refresh_token_families AS rf
      WHERE rf.client_id = oauth_clients.client_id
        AND rf.revoked_at IS NULL
        AND rf.expires_at >= /*now*/ 0
  );
