SELECT
    rt.id,
    rt.token_hash,
    rt.family_id,
    rt.parent_id,
    rt.scope,
    rt.expires_at,
    rt.consumed_at,
    rt.revoked_at,
    rf.user_id,
    rf.client_id,
    rf.resource,
    rf.scope AS family_scope,
    rf.expires_at AS family_expires_at,
    rf.revoked_at AS family_revoked_at,
    u.enabled AS user_enabled,
    c.enabled AS client_enabled
FROM oauth_refresh_tokens AS rt
JOIN oauth_refresh_token_families AS rf ON rf.id = rt.family_id
JOIN oauth_users AS u ON u.id = rf.user_id
JOIN oauth_clients AS c ON c.client_id = rf.client_id
WHERE rt.token_hash = /*token_hash*/ ''
LIMIT 1;
