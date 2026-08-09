UPDATE oauth_authorization_codes
SET consumed_at = CAST(strftime('%s', 'now') AS INTEGER)
WHERE id = /*code_id*/ 0
  AND consumed_at IS NULL
  AND expires_at > CAST(strftime('%s', 'now') AS INTEGER)
RETURNING id;
