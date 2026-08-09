SELECT id, username, password_hash, display_name
FROM oauth_users
WHERE username = /*username*/ '' COLLATE NOCASE
  AND enabled = 1
LIMIT 1;
