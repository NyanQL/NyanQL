UPDATE oauth_authorization_requests
SET attempt_count = attempt_count + 1
WHERE id = /*request_id*/ 0
  AND consumed_at IS NULL
  AND expires_at > CAST(strftime('%s', 'now') AS INTEGER)
RETURNING attempt_count;
