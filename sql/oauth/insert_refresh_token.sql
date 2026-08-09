INSERT INTO oauth_refresh_tokens (
    token_hash,
    family_id,
    parent_id,
    scope,
    expires_at
) VALUES (
    /*token_hash*/ '',
    /*family_id*/ 0,
    /*parent_id*/ NULL,
    /*scope*/ '',
    /*expires_at*/ 0
)
RETURNING id, family_id;
