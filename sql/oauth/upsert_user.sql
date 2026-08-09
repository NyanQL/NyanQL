INSERT INTO oauth_users (
    username,
    password_hash,
    display_name,
    enabled,
    updated_at
) VALUES (
    /*username*/ '',
    /*password_hash*/ '',
    /*display_name*/ '',
    1,
    CAST(strftime('%s', 'now') AS INTEGER)
)
ON CONFLICT(username) DO UPDATE SET
    password_hash = excluded.password_hash,
    display_name = excluded.display_name,
    enabled = 1,
    updated_at = CAST(strftime('%s', 'now') AS INTEGER)
RETURNING id, username, display_name, enabled;
