SELECT
    ac.id,
    ac.user_id,
    ac.client_id,
    ac.redirect_uri,
    ac.resource,
    ac.scope,
    ac.code_challenge,
    ac.code_challenge_method,
    ac.expires_at
FROM oauth_authorization_codes AS ac
JOIN oauth_users AS u ON u.id = ac.user_id
JOIN oauth_clients AS c ON c.client_id = ac.client_id
WHERE ac.code_hash = /*code_hash*/ ''
  AND ac.consumed_at IS NULL
  AND ac.expires_at > CAST(strftime('%s', 'now') AS INTEGER)
  AND u.enabled = 1
  AND c.enabled = 1
LIMIT 1;
