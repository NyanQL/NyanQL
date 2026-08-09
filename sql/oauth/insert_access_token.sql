INSERT INTO oauth_access_tokens (
    token_hash,
    user_id,
    client_id,
    resource,
    scope,
    expires_at,
    refresh_family_id
) VALUES (
    /*token_hash*/ '',
    /*user_id*/ 0,
    /*client_id*/ '',
    /*resource*/ '',
    /*scope*/ '',
    /*expires_at*/ 0,
    /*refresh_family_id*/ NULL
)
RETURNING id;
