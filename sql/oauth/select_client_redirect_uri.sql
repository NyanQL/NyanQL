SELECT
    c.client_id,
    c.client_name,
    c.scope,
    r.redirect_uri
FROM oauth_clients AS c
JOIN oauth_client_redirect_uris AS r ON r.client_id = c.client_id
WHERE c.client_id = /*client_id*/ ''
  AND r.redirect_uri = /*redirect_uri*/ ''
  AND c.enabled = 1
LIMIT 1;
