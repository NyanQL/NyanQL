function oauthCleanupRowsAffected(result) {
  if (!result || typeof result.rowsAffected !== 'number') {
    return 0;
  }
  return result.rowsAffected;
}

function oauthCleanupMain() {
  const settings = (typeof nyanRuntimeSettings === 'object' && nyanRuntimeSettings) || {};
  const retentionDays = settings.retentionDays;
  const clientRetentionDays = settings.clientRetentionDays;
  if (typeof retentionDays !== 'number' || Math.floor(retentionDays) !== retentionDays ||
      retentionDays < 1 || retentionDays > 365 ||
      typeof clientRetentionDays !== 'number' || Math.floor(clientRetentionDays) !== clientRetentionDays ||
      clientRetentionDays < 30 || clientRetentionDays > 3650) {
    throw new Error('OAuth cleanup retention settings are invalid');
  }

  const now = Math.floor(Date.now() / 1000);
  const historyCutoff = now - (retentionDays * 86400);
  const clientCutoff = now - (clientRetentionDays * 86400);
  const removedRequests = nyanRunSQL('./sql/oauth/cleanup_authorization_requests.sql', {
    now: now,
    history_cutoff: historyCutoff
  });
  const removedCodes = nyanRunSQL('./sql/oauth/cleanup_authorization_codes.sql', {
    now: now,
    history_cutoff: historyCutoff
  });
  const removedTokens = nyanRunSQL('./sql/oauth/cleanup_access_tokens.sql', {
    now: now,
    history_cutoff: historyCutoff
  });
  // consumed tokenはfamilyが有効な間は保持し、replay検知能力を失わない。
  const removedRefreshTokens = nyanRunSQL('./sql/oauth/cleanup_refresh_tokens.sql', {
    now: now,
    history_cutoff: historyCutoff
  });
  const removedRefreshFamilies = nyanRunSQL('./sql/oauth/cleanup_refresh_token_families.sql', {
    now: now,
    history_cutoff: historyCutoff
  });
  const removedClients = nyanRunSQL('./sql/oauth/cleanup_clients.sql', {
    now: now,
    client_cutoff: clientCutoff
  });

  return JSON.stringify({
    authorizationRequests: oauthCleanupRowsAffected(removedRequests),
    authorizationCodes: oauthCleanupRowsAffected(removedCodes),
    accessTokens: oauthCleanupRowsAffected(removedTokens),
    refreshTokens: oauthCleanupRowsAffected(removedRefreshTokens),
    refreshTokenFamilies: oauthCleanupRowsAffected(removedRefreshFamilies),
    clients: oauthCleanupRowsAffected(removedClients)
  });
}

oauthCleanupMain();
