function oauthTokenResponse(status, payload) {
  return JSON.stringify({
    status: status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      Pragma: 'no-cache'
    },
    body: JSON.stringify(payload)
  });
}

function oauthTokenError(error, description) {
  const payload = { error: error };
  if (description) {
    payload.error_description = description;
  }
  return oauthTokenResponse(400, payload);
}

function oauthTokenFirst(rows) {
  return Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
}

function oauthTokenScalar(object, key) {
  if (!object || typeof object[key] === 'undefined' || object[key] === null) {
    return '';
  }
  if (Array.isArray(object[key])) {
    return object[key].length === 1 && typeof object[key][0] === 'string' ? object[key][0] : null;
  }
  return typeof object[key] === 'string' ? object[key] : String(object[key]);
}

function oauthTokenLifetime(value, defaultValue, minimum, maximum) {
  const parsed = Number(value || defaultValue);
  return Number.isFinite(parsed) && Math.floor(parsed) === parsed && parsed >= minimum && parsed <= maximum
    ? parsed
    : defaultValue;
}

function oauthTokenValidScopeToken(scope) {
  if (typeof scope !== 'string' || scope.length === 0 || scope.length > 256) {
    return false;
  }
  for (let index = 0; index < scope.length; index += 1) {
    const code = scope.charCodeAt(index);
    if (code < 0x21 || code > 0x7e || code === 0x22 || code === 0x5c) {
      return false;
    }
  }
  return true;
}

function oauthTokenScopeList(scopeText) {
  if (typeof scopeText !== 'string' || !scopeText.trim()) {
    return [];
  }
  const values = scopeText.trim().split(/\s+/);
  const unique = [];
  for (let index = 0; index < values.length; index += 1) {
    if (!oauthTokenValidScopeToken(values[index]) || unique.indexOf(values[index]) >= 0) {
      return null;
    }
    unique.push(values[index]);
  }
  return unique;
}

function oauthTokenIsScopeSubset(requested, granted) {
  for (let index = 0; index < requested.length; index += 1) {
    if (granted.indexOf(requested[index]) < 0) {
      return false;
    }
  }
  return true;
}

function oauthTokenRevokeFamily(familyID) {
  nyanRunSQL('./sql/oauth/revoke_refresh_token_family.sql', {
    family_id: familyID
  });
  nyanRunSQL('./sql/oauth/revoke_refresh_tokens_in_family.sql', {
    family_id: familyID
  });
  nyanRunSQL('./sql/oauth/revoke_access_tokens_in_refresh_family.sql', {
    family_id: familyID
  });
}

function oauthTokenInsertAccessToken(grant, scope, expiresAt, refreshFamilyID) {
  const accessToken = 'nyan_at_' + nyanCrypto.randomBase64URL(32);
  nyanRunSQL('./sql/oauth/insert_access_token.sql', {
    token_hash: nyanCrypto.sha256Hex(accessToken),
    user_id: grant.user_id,
    client_id: grant.client_id,
    resource: grant.resource,
    scope: scope,
    expires_at: expiresAt,
    refresh_family_id: refreshFamilyID
  });
  return accessToken;
}

function oauthTokenAuthorizationCode(form, settings) {
  const code = oauthTokenScalar(form, 'code');
  const clientID = oauthTokenScalar(form, 'client_id');
  const redirectURI = oauthTokenScalar(form, 'redirect_uri');
  const verifier = oauthTokenScalar(form, 'code_verifier');
  const resource = oauthTokenScalar(form, 'resource');

  if (!code || !clientID || !redirectURI || !verifier || !resource) {
    return oauthTokenError('invalid_request', 'required token request parameters are missing');
  }
  if (code.length > 256 || clientID.length > 256 || redirectURI.length > 2048 || resource.length > 2048) {
    return oauthTokenError('invalid_request', 'token request parameter is too long');
  }
  if (resource !== settings.resource) {
    return oauthTokenError('invalid_target', 'resource is invalid');
  }
  if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) {
    return oauthTokenError('invalid_grant', 'authorization code is invalid');
  }

  const authorizationCode = oauthTokenFirst(nyanRunSQL('./sql/oauth/select_authorization_code.sql', {
    code_hash: nyanCrypto.sha256Hex(code)
  }));
  if (!authorizationCode ||
      String(authorizationCode.client_id) !== clientID ||
      String(authorizationCode.redirect_uri) !== redirectURI ||
      String(authorizationCode.resource) !== resource ||
      String(authorizationCode.code_challenge_method) !== 'S256') {
    return oauthTokenError('invalid_grant', 'authorization code is invalid');
  }

  const computedChallenge = nyanCrypto.sha256Base64URL(verifier);
  if (!nyanCrypto.timingSafeEqual(String(authorizationCode.code_challenge), computedChallenge)) {
    return oauthTokenError('invalid_grant', 'authorization code is invalid');
  }

  const consumed = oauthTokenFirst(nyanRunSQL('./sql/oauth/consume_authorization_code.sql', {
    code_id: authorizationCode.id
  }));
  if (!consumed) {
    return oauthTokenError('invalid_grant', 'authorization code is invalid');
  }

  const accessTokenLifetime = oauthTokenLifetime(settings.accessTokenLifetimeSeconds, 3600, 300, 86400);
  const grantedScopes = oauthTokenScopeList(String(authorizationCode.scope));
  if (!grantedScopes || grantedScopes.length === 0) {
    return oauthTokenResponse(500, { error: 'server_error' });
  }

  let refreshToken = '';
  let refreshFamilyID = null;
  if (grantedScopes.indexOf('offline_access') >= 0) {
    const refreshTokenLifetime = oauthTokenLifetime(
      settings.refreshTokenLifetimeSeconds,
      7776000,
      86400,
      31536000
    );
    const refreshExpiresAt = Math.floor(Date.now() / 1000) + refreshTokenLifetime;
    const family = oauthTokenFirst(nyanRunSQL('./sql/oauth/insert_refresh_token_family.sql', {
      user_id: authorizationCode.user_id,
      client_id: authorizationCode.client_id,
      resource: authorizationCode.resource,
      scope: authorizationCode.scope,
      expires_at: refreshExpiresAt
    }));
    if (!family) {
      return oauthTokenResponse(500, { error: 'server_error' });
    }
    refreshFamilyID = family.id;
    refreshToken = 'nyan_rt_' + nyanCrypto.randomBase64URL(48);
    nyanRunSQL('./sql/oauth/insert_refresh_token.sql', {
      token_hash: nyanCrypto.sha256Hex(refreshToken),
      family_id: refreshFamilyID,
      parent_id: null,
      scope: authorizationCode.scope,
      expires_at: refreshExpiresAt
    });
  }

  const accessToken = oauthTokenInsertAccessToken(
    authorizationCode,
    String(authorizationCode.scope),
    Math.floor(Date.now() / 1000) + accessTokenLifetime,
    refreshFamilyID
  );
  const payload = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: accessTokenLifetime,
    scope: String(authorizationCode.scope)
  };
  if (refreshToken) {
    payload.refresh_token = refreshToken;
  }
  return oauthTokenResponse(200, payload);
}

function oauthTokenRefresh(form, settings) {
  const presentedToken = oauthTokenScalar(form, 'refresh_token');
  const clientID = oauthTokenScalar(form, 'client_id');
  const requestedResource = oauthTokenScalar(form, 'resource');
  const requestedScopeText = oauthTokenScalar(form, 'scope');
  if (!presentedToken || !clientID || presentedToken.length > 256 || clientID.length > 256 ||
      (requestedResource && requestedResource.length > 2048) ||
      (requestedScopeText && requestedScopeText.length > 2048)) {
    return oauthTokenError('invalid_request', 'refresh_token and client_id are required');
  }
  if (requestedResource && requestedResource !== settings.resource) {
    return oauthTokenError('invalid_target', 'resource is invalid');
  }

  const presentedHash = nyanCrypto.sha256Hex(presentedToken);
  // SQLiteのdeferred transactionを最初にwrite transactionへ昇格させる。
  // rotation同士を直列化し、同じtokenの並行再利用でもfamily失効を確実にcommitする。
  nyanRunSQL('./sql/oauth/lock_refresh_token.sql', {
    token_hash: presentedHash
  });
  const refreshGrant = oauthTokenFirst(nyanRunSQL('./sql/oauth/select_refresh_token.sql', {
    token_hash: presentedHash
  }));
  if (!refreshGrant || !nyanCrypto.timingSafeEqual(String(refreshGrant.token_hash), presentedHash)) {
    return oauthTokenError('invalid_grant', 'refresh token is invalid');
  }

  const familyID = refreshGrant.family_id;
  if (refreshGrant.consumed_at !== null && typeof refreshGrant.consumed_at !== 'undefined') {
    oauthTokenRevokeFamily(familyID);
    return oauthTokenError('invalid_grant', 'refresh token is invalid');
  }

  const now = Math.floor(Date.now() / 1000);
  if (String(refreshGrant.client_id) !== clientID ||
      String(refreshGrant.resource) !== settings.resource ||
      Number(refreshGrant.user_enabled) !== 1 ||
      Number(refreshGrant.client_enabled) !== 1 ||
      (refreshGrant.revoked_at !== null && typeof refreshGrant.revoked_at !== 'undefined') ||
      (refreshGrant.family_revoked_at !== null && typeof refreshGrant.family_revoked_at !== 'undefined') ||
      Number(refreshGrant.expires_at) <= now ||
      Number(refreshGrant.family_expires_at) <= now) {
    return oauthTokenError('invalid_grant', 'refresh token is invalid');
  }

  const grantedScopes = oauthTokenScopeList(String(refreshGrant.scope));
  const requestedScopes = requestedScopeText ? oauthTokenScopeList(requestedScopeText) : grantedScopes;
  if (!grantedScopes || !requestedScopes || requestedScopes.length === 0 ||
      !oauthTokenIsScopeSubset(requestedScopes, grantedScopes)) {
    return oauthTokenError('invalid_scope', 'scope exceeds the original authorization grant');
  }

  const consumed = oauthTokenFirst(nyanRunSQL('./sql/oauth/consume_refresh_token.sql', {
    refresh_token_id: refreshGrant.id
  }));
  if (!consumed) {
    oauthTokenRevokeFamily(familyID);
    return oauthTokenError('invalid_grant', 'refresh token is invalid');
  }

  const rotatedScope = requestedScopes.join(' ');
  const nextRefreshToken = 'nyan_rt_' + nyanCrypto.randomBase64URL(48);
  nyanRunSQL('./sql/oauth/insert_refresh_token.sql', {
    token_hash: nyanCrypto.sha256Hex(nextRefreshToken),
    family_id: familyID,
    parent_id: refreshGrant.id,
    scope: String(refreshGrant.family_scope),
    expires_at: refreshGrant.family_expires_at
  });

  const configuredAccessTokenLifetime = oauthTokenLifetime(
    settings.accessTokenLifetimeSeconds,
    3600,
    300,
    86400
  );
  const accessTokenLifetime = Math.min(
    configuredAccessTokenLifetime,
    Number(refreshGrant.family_expires_at) - now
  );
  if (accessTokenLifetime < 1) {
    return oauthTokenError('invalid_grant', 'refresh token is invalid');
  }
  const accessToken = oauthTokenInsertAccessToken(
    refreshGrant,
    rotatedScope,
    now + accessTokenLifetime,
    familyID
  );
  return oauthTokenResponse(200, {
    access_token: accessToken,
    refresh_token: nextRefreshToken,
    token_type: 'Bearer',
    expires_in: accessTokenLifetime,
    scope: rotatedScope
  });
}

function oauthTokenMain() {
  const request = (typeof nyanRequest === 'object' && nyanRequest) || {};
  const form = request.form && typeof request.form === 'object' ? request.form : {};
  const settings = (typeof nyanRuntimeSettings === 'object' && nyanRuntimeSettings) || {};
  if (typeof settings.resource !== 'string' || !settings.resource ||
      typeof nyanCrypto !== 'object' ||
      typeof nyanCrypto.randomBase64URL !== 'function' ||
      typeof nyanCrypto.sha256Hex !== 'function' ||
      typeof nyanCrypto.sha256Base64URL !== 'function' ||
      typeof nyanCrypto.timingSafeEqual !== 'function') {
    return oauthTokenResponse(500, { error: 'server_error' });
  }

  const grantType = oauthTokenScalar(form, 'grant_type');
  if (grantType === 'authorization_code') {
    return oauthTokenAuthorizationCode(form, settings);
  }
  if (grantType === 'refresh_token') {
    return oauthTokenRefresh(form, settings);
  }
  return oauthTokenError('unsupported_grant_type', 'grant_type is not supported');
}

oauthTokenMain();
