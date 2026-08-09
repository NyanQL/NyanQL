INSERT INTO oauth_refresh_token_families (
    user_id,
    client_id,
    resource,
    scope,
    expires_at
) VALUES (
    /*user_id*/ 0,
    /*client_id*/ '',
    /*resource*/ '',
    /*scope*/ '',
    /*expires_at*/ 0
)
RETURNING id, expires_at;
