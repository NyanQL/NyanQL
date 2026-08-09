INSERT INTO oauth_clients (
    client_id,
    client_name,
    token_endpoint_auth_method,
    grant_types,
    response_types,
    scope
) SELECT
    /*client_id*/ '',
    /*client_name*/ '',
    'none',
    /*grant_types*/ '["authorization_code","refresh_token"]',
    '["code"]',
    /*scope*/ ''
WHERE (SELECT COUNT(*) FROM oauth_clients) < /*max_clients*/ 1000
RETURNING client_id, client_name, token_endpoint_auth_method, scope, created_at;
