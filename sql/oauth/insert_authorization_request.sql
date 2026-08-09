INSERT INTO oauth_authorization_requests (
    request_hash,
    csrf_hash,
    client_id,
    redirect_uri,
    resource,
    scope,
    state,
    code_challenge,
    code_challenge_method,
    expires_at
) VALUES (
    /*request_hash*/ '',
    /*csrf_hash*/ '',
    /*client_id*/ '',
    /*redirect_uri*/ '',
    /*resource*/ '',
    /*scope*/ '',
    /*state*/ '',
    /*code_challenge*/ '',
    'S256',
    /*expires_at*/ 0
)
RETURNING id;
