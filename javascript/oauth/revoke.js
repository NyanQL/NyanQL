function oauthRevokeResponse(status, payload) {
  return JSON.stringify({
    status: status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      Pragma: 'no-cache'
    },
    body: payload ? JSON.stringify(payload) : ''
  });
}

function oauthRevokeScalar(object, key) {
  if (!object || typeof object[key] === 'undefined' || object[key] === null) {
    return '';
  }
  if (Array.isArray(object[key])) {
    return object[key].length === 1 && typeof object[key][0] === 'string' ? object[key][0] : null;
  }
  return typeof object[key] === 'string' ? object[key] : String(object[key]);
}

function oauthRevokeFirst(rows) {
  return Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
}

function oauthRevokeFamily(familyID) {
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

function oauthRevokeMain() {
  const request = (typeof nyanRequest === 'object' && nyanRequest) || {};
  const form = request.form && typeof request.form === 'object' ? request.form : {};
  const token = oauthRevokeScalar(form, 'token');
  const clientID = oauthRevokeScalar(form, 'client_id');
  const tokenTypeHint = oauthRevokeScalar(form, 'token_type_hint');

  if (typeof nyanCrypto !== 'object' ||
      typeof nyanCrypto.sha256Hex !== 'function' ||
      typeof nyanCrypto.timingSafeEqual !== 'function') {
    return oauthRevokeResponse(500, { error: 'server_error' });
  }
  if (!token || !clientID || token.length > 256 || clientID.length > 256) {
    return oauthRevokeResponse(400, {
      error: 'invalid_request',
      error_description: 'token and client_id are required'
    });
  }
  const tokenHash = nyanCrypto.sha256Hex(token);
  const accessToken = oauthRevokeFirst(nyanRunSQL('./sql/oauth/revoke_access_token.sql', {
    token_hash: tokenHash,
    client_id: clientID
  }));
  if (accessToken && accessToken.refresh_family_id !== null &&
      typeof accessToken.refresh_family_id !== 'undefined') {
    oauthRevokeFamily(accessToken.refresh_family_id);
  }

  // token_type_hintはあくまでhintなので、未知の値や誤ったhintでも両方を探索する。
  const refreshToken = oauthRevokeFirst(nyanRunSQL('./sql/oauth/select_refresh_token.sql', {
    token_hash: tokenHash
  }));
  if (refreshToken && String(refreshToken.client_id) === clientID &&
      nyanCrypto.timingSafeEqual(String(refreshToken.token_hash), tokenHash)) {
    oauthRevokeFamily(refreshToken.family_id);
  }

  // RFC 7009 requires the same successful response for unknown and revoked tokens.
  return oauthRevokeResponse(200, null);
}

oauthRevokeMain();
