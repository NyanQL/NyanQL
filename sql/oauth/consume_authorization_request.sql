UPDATE oauth_authorization_requests
SET consumed_at = CAST(strftime('%s', 'now') AS INTEGER)
WHERE id = /*request_id*/ 0
  AND consumed_at IS NULL
  AND expires_at > CAST(strftime('%s', 'now') AS INTEGER)
RETURNING id;
