SELECT
    ar.id,
    ar.csrf_hash,
    ar.client_id,
    ar.redirect_uri,
    ar.resource,
    ar.scope,
    ar.state,
    ar.code_challenge,
    ar.code_challenge_method,
    ar.attempt_count,
    ar.expires_at,
    c.client_name
FROM oauth_authorization_requests AS ar
JOIN oauth_clients AS c ON c.client_id = ar.client_id
WHERE ar.request_hash = /*request_hash*/ ''
  AND ar.consumed_at IS NULL
  AND ar.expires_at > CAST(strftime('%s', 'now') AS INTEGER)
  AND ar.attempt_count < 5
  AND c.enabled = 1
LIMIT 1;
