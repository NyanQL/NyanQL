INSERT INTO oauth_consents (user_id, client_id, resource, scope)
VALUES (
    /*user_id*/ 0,
    /*client_id*/ '',
    /*resource*/ '',
    /*scope*/ ''
)
ON CONFLICT(user_id, client_id, resource) DO UPDATE SET
    scope = excluded.scope,
    updated_at = CAST(strftime('%s', 'now') AS INTEGER);
