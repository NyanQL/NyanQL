INSERT INTO oauth_authorization_codes (
    code_hash,
    user_id,
    client_id,
    redirect_uri,
    resource,
    scope,
    code_challenge,
    code_challenge_method,
    expires_at
) VALUES (
    /*code_hash*/ '',
    /*user_id*/ 0,
    /*client_id*/ '',
    /*redirect_uri*/ '',
    /*resource*/ '',
    /*scope*/ '',
    /*code_challenge*/ '',
    'S256',
    /*expires_at*/ 0
)
RETURNING id;
