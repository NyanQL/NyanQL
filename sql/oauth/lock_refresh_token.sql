-- OAuth endpoint transactionの最初のDB操作としてwrite lockを取得する。
-- 同じrefresh tokenの並行rotationを直列化し、後続requestでreplayを検知できるようにする。
UPDATE oauth_refresh_tokens
SET token_hash = token_hash
WHERE token_hash = /*token_hash*/ ''
RETURNING id;
