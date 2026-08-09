function oauthAuthorizeEnvelope(status, headers, body) {
  const responseHeaders = headers || {};
  if (!responseHeaders['Cache-Control']) {
    responseHeaders['Cache-Control'] = 'no-store';
  }
  return JSON.stringify({ status: status, headers: responseHeaders, body: body || '' });
}

function oauthAuthorizeJSON(status, error, description) {
  const payload = { error: error };
  if (description) {
    payload.error_description = description;
  }
  return oauthAuthorizeEnvelope(status, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    Pragma: 'no-cache'
  }, JSON.stringify(payload));
}

function oauthAuthorizeFirst(rows) {
  return Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
}

function oauthAuthorizeScalar(object, key) {
  if (!object || typeof object[key] === 'undefined' || object[key] === null) {
    return '';
  }
  if (Array.isArray(object[key])) {
    return object[key].length === 1 && typeof object[key][0] === 'string' ? object[key][0] : null;
  }
  return typeof object[key] === 'string' ? object[key] : String(object[key]);
}

function oauthAuthorizeEscape(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function oauthAuthorizeOrigin(uri) {
  if (typeof uri !== 'string' || /[\u0000-\u0020\u007f\\]/.test(uri)) {
    return '';
  }
  const match = /^(https?):\/\/((?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:.]+\])(?::([0-9]{1,5}))?)(?:[\/?#]|$)/.exec(uri);
  if (!match) {
    return '';
  }
  if (match[3] && (Number(match[3]) < 1 || Number(match[3]) > 65535)) {
    return '';
  }
  return match[1].toLowerCase() + '://' + match[2].toLowerCase();
}

function oauthAuthorizeURL(redirectURI, values) {
  const parts = [];
  const keys = Object.keys(values);
  for (let i = 0; i < keys.length; i += 1) {
    const key = keys[i];
    if (typeof values[key] === 'undefined' || values[key] === null || values[key] === '') {
      continue;
    }
    parts.push(encodeURIComponent(key) + '=' + encodeURIComponent(String(values[key])));
  }
  if (parts.length === 0) {
    return redirectURI;
  }
  return redirectURI + (redirectURI.indexOf('?') >= 0 ? '&' : '?') + parts.join('&');
}

function oauthAuthorizeRedirectError(redirectURI, state, error, description) {
  return oauthAuthorizeEnvelope(302, {
    Location: oauthAuthorizeURL(redirectURI, {
      error: error,
      error_description: description,
      state: state
    }),
    'Cache-Control': 'no-store'
  }, '');
}

function oauthAuthorizeScopes(scopeText, supportedScopes, clientScopes) {
  const requested = typeof scopeText === 'string' && scopeText.trim()
    ? scopeText.trim().split(/\s+/)
    : clientScopes.slice();
  const unique = [];
  for (let i = 0; i < requested.length; i += 1) {
    const scope = requested[i];
    if (!scope || supportedScopes.indexOf(scope) < 0 || clientScopes.indexOf(scope) < 0) {
      return null;
    }
    if (unique.indexOf(scope) < 0) {
      unique.push(scope);
    }
  }
  return unique;
}

function oauthAuthorizeLoopbackAuthority(authority) {
  let host = authority;
  const colon = authority.lastIndexOf(':');
  if (authority.charAt(0) === '[') {
    const bracket = authority.indexOf(']');
    if (bracket < 0) {
      return false;
    }
    host = authority.slice(1, bracket);
    const suffix = authority.slice(bracket + 1);
    if (suffix && !/^:\d{1,5}$/.test(suffix)) {
      return false;
    }
    if (suffix && (Number(suffix.slice(1)) < 1 || Number(suffix.slice(1)) > 65535)) {
      return false;
    }
  } else if (colon >= 0) {
    if (authority.indexOf(':') !== colon || !/^\d{1,5}$/.test(authority.slice(colon + 1))) {
      return false;
    }
    if (Number(authority.slice(colon + 1)) < 1 || Number(authority.slice(colon + 1)) > 65535) {
      return false;
    }
    host = authority.slice(0, colon);
  }
  host = host.toLowerCase();
  return host === 'localhost' || host === '127.0.0.1' || host === '::1';
}

function oauthAuthorizeAllowedRedirectURI(uri, settings) {
  if (typeof uri !== 'string' || uri.length < 10 || uri.length > 2048 ||
      /[\u0000-\u0020\u007f\\]/.test(uri) || uri.indexOf('#') >= 0) {
    return false;
  }
  const match = /^(https?):\/\/([^\/?#]+)(\/[^#]*)?$/.exec(uri);
  if (!match || match[2].indexOf('@') >= 0) {
    return false;
  }
  if (match[1].toLowerCase() === 'http') {
    return settings.allowLoopbackRedirects === true && oauthAuthorizeLoopbackAuthority(match[2]);
  }
  const exact = Array.isArray(settings.redirectURIAllowlist) ? settings.redirectURIAllowlist : [];
  if (exact.indexOf(uri) >= 0) {
    return true;
  }
  const prefixes = Array.isArray(settings.redirectURIAllowedPrefixes)
    ? settings.redirectURIAllowedPrefixes
    : [];
  for (let i = 0; i < prefixes.length; i += 1) {
    const prefix = prefixes[i];
    if (typeof prefix !== 'string' || !/^https:\/\/[^\/?#]+\/[^?#]*\/$/.test(prefix) ||
        uri.indexOf(prefix) !== 0) {
      continue;
    }
    if (/^[A-Za-z0-9._~-]{1,256}$/.test(uri.slice(prefix.length))) {
      return true;
    }
  }
  return false;
}

function oauthAuthorizeLoginHTML(requestID, clientID, clientName, redirectURI, scope, errorMessage, formAction) {
  const error = errorMessage
    ? '<p role="alert">' + oauthAuthorizeEscape(errorMessage) + '</p>'
    : '';
  return '<!doctype html>' +
    '<html lang="ja"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>NyanQL authorization</title></head><body>' +
    '<main><h1>NyanQLへの接続を許可</h1>' + error +
    '<p>未検証のクライアント表示名: <strong>' + oauthAuthorizeEscape(clientName) + '</strong></p>' +
    '<p>クライアントID: <code>' + oauthAuthorizeEscape(clientID) + '</code></p>' +
    '<p>認可後のリダイレクト先: <code>' + oauthAuthorizeEscape(redirectURI) + '</code></p>' +
    '<p>権限: <code>' + oauthAuthorizeEscape(scope) + '</code></p>' +
    '<form method="post" action="' + oauthAuthorizeEscape(formAction) + '">' +
    '<input type="hidden" name="request_id" value="' + oauthAuthorizeEscape(requestID) + '">' +
    '<p><label>ユーザー名 <input name="username" autocomplete="username" required maxlength="128"></label></p>' +
    '<p><label>パスワード <input type="password" name="password" autocomplete="current-password" required maxlength="1024"></label></p>' +
    '<p><button type="submit" name="decision" value="allow">許可</button> ' +
    '<button type="submit" name="decision" value="deny" formnovalidate>拒否</button></p>' +
    '</form></main></body></html>';
}

function oauthAuthorizeCSRFCookieName(requestID) {
  return 'nyan_oauth_csrf_' + nyanCrypto.sha256Hex(requestID).slice(0, 32);
}

function oauthAuthorizeHTMLResponse(requestID, csrfToken, clientID, clientName, redirectURI, scope, errorMessage, settings) {
  const cookiePath = typeof settings.authorizationCookiePath === 'string' && settings.authorizationCookiePath
    ? settings.authorizationCookiePath
    : '/oauth/authorize';
  const redirectOrigin = oauthAuthorizeOrigin(redirectURI);
  const formActionPolicy = "form-action 'self'" + (redirectOrigin ? ' ' + redirectOrigin : '');
  return oauthAuthorizeEnvelope(200, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    Pragma: 'no-cache',
    // Chromium also applies form-action to the cross-origin 303 callback redirect.
    // Allow only the origin of the redirect URI already validated for this request.
    'Content-Security-Policy': "default-src 'none'; " + formActionPolicy + "; base-uri 'none'; frame-ancestors 'none'",
    // no-referrer makes Chromium serialize Origin as "null" for this POST.
    // strict-origin keeps the tuple Origin while omitting the authorization query.
    'Referrer-Policy': 'strict-origin',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Set-Cookie': oauthAuthorizeCSRFCookieName(requestID) + '=' + csrfToken +
      '; Path=' + cookiePath + '; Max-Age=600; HttpOnly; Secure; SameSite=Lax'
  }, oauthAuthorizeLoginHTML(
    requestID,
    clientID,
    clientName,
    redirectURI,
    scope,
    errorMessage,
    settings.authorizationEndpoint
  ));
}

function oauthAuthorizeClearCookie(requestID, settings) {
  const cookiePath = typeof settings.authorizationCookiePath === 'string' && settings.authorizationCookiePath
    ? settings.authorizationCookiePath
    : '/oauth/authorize';
  return oauthAuthorizeCSRFCookieName(requestID) + '=; Path=' + cookiePath +
    '; Max-Age=0; HttpOnly; Secure; SameSite=Lax';
}

function oauthAuthorizeGET(request, settings) {
  const query = request.query && typeof request.query === 'object' ? request.query : {};
  const clientID = oauthAuthorizeScalar(query, 'client_id');
  const redirectURI = oauthAuthorizeScalar(query, 'redirect_uri');
  const responseType = oauthAuthorizeScalar(query, 'response_type');
  const resource = oauthAuthorizeScalar(query, 'resource');
  const scopeText = oauthAuthorizeScalar(query, 'scope');
  const state = oauthAuthorizeScalar(query, 'state');
  const challenge = oauthAuthorizeScalar(query, 'code_challenge');
  const challengeMethod = oauthAuthorizeScalar(query, 'code_challenge_method');

  if (!clientID || !redirectURI || clientID.length > 256 || redirectURI.length > 2048) {
    return oauthAuthorizeJSON(400, 'invalid_request', 'client_id and redirect_uri are required');
  }
  const client = oauthAuthorizeFirst(nyanRunSQL('./sql/oauth/select_client_redirect_uri.sql', {
    client_id: clientID,
    redirect_uri: redirectURI
  }));
  if (!client) {
    return oauthAuthorizeJSON(400, 'invalid_request', 'client or redirect_uri is invalid');
  }
  // DB内に旧ポリシーで登録されたURIが残っていても、現在の許可設定を必ず再評価する。
  if (!oauthAuthorizeAllowedRedirectURI(redirectURI, settings)) {
    return oauthAuthorizeJSON(400, 'invalid_request', 'client or redirect_uri is invalid');
  }
  if (responseType !== 'code') {
    return oauthAuthorizeRedirectError(redirectURI, state, 'unsupported_response_type', 'only code is supported');
  }
  if (!resource || resource !== settings.resource) {
    return oauthAuthorizeRedirectError(redirectURI, state, 'invalid_target', 'resource is invalid');
  }
  if (typeof state !== 'string' || state.length > 1024) {
    return oauthAuthorizeRedirectError(redirectURI, '', 'invalid_request', 'state is invalid');
  }
  if (challengeMethod !== 'S256' || typeof challenge !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) {
    return oauthAuthorizeRedirectError(redirectURI, state, 'invalid_request', 'PKCE S256 is required');
  }
  const supportedScopes = settings.scopes;
  const clientScopes = typeof client.scope === 'string' ? client.scope.split(/\s+/) : [];
  const scopes = oauthAuthorizeScopes(scopeText, supportedScopes, clientScopes);
  if (!scopes || scopes.length === 0) {
    return oauthAuthorizeRedirectError(redirectURI, state, 'invalid_scope', 'scope is invalid');
  }

  const requestID = 'nyan_ar_' + nyanCrypto.randomBase64URL(32);
  const csrfToken = nyanCrypto.randomBase64URL(32);
  nyanRunSQL('./sql/oauth/insert_authorization_request.sql', {
    request_hash: nyanCrypto.sha256Hex(requestID),
    csrf_hash: nyanCrypto.sha256Hex(csrfToken),
    client_id: clientID,
    redirect_uri: redirectURI,
    resource: resource,
    scope: scopes.join(' '),
    state: state,
    code_challenge: challenge,
    expires_at: Math.floor(Date.now() / 1000) + 600
  });

  return oauthAuthorizeHTMLResponse(
    requestID,
    csrfToken,
    client.client_id,
    client.client_name,
    client.redirect_uri,
    scopes.join(' '),
    '',
    settings
  );
}

function oauthAuthorizePOST(request, settings) {
  const form = request.form && typeof request.form === 'object' ? request.form : {};
  const requestID = oauthAuthorizeScalar(form, 'request_id');
  const decision = oauthAuthorizeScalar(form, 'decision');
  const username = oauthAuthorizeScalar(form, 'username');
  const password = oauthAuthorizeScalar(form, 'password');
  const cookies = request.cookies && typeof request.cookies === 'object' ? request.cookies : {};
  const csrfCookieName = requestID ? oauthAuthorizeCSRFCookieName(requestID) : '';
  const csrfToken = csrfCookieName && typeof cookies[csrfCookieName] === 'string'
    ? cookies[csrfCookieName]
    : '';

  if (!requestID || requestID.length > 256 || !csrfToken || csrfToken.length > 256) {
    return oauthAuthorizeJSON(400, 'invalid_request', 'authorization request is invalid or expired');
  }
  const authRequest = oauthAuthorizeFirst(nyanRunSQL('./sql/oauth/select_authorization_request.sql', {
    request_hash: nyanCrypto.sha256Hex(requestID)
  }));
  if (!authRequest || !nyanCrypto.timingSafeEqual(
    String(authRequest.csrf_hash),
    nyanCrypto.sha256Hex(csrfToken)
  )) {
    return oauthAuthorizeJSON(400, 'invalid_request', 'authorization request is invalid or expired');
  }

  if (decision === 'deny') {
    const denied = oauthAuthorizeFirst(nyanRunSQL('./sql/oauth/consume_authorization_request.sql', {
      request_id: authRequest.id
    }));
    if (!denied) {
      return oauthAuthorizeJSON(400, 'invalid_request', 'authorization request is invalid or expired');
    }
    const denial = JSON.parse(oauthAuthorizeRedirectError(
      authRequest.redirect_uri,
      authRequest.state,
      'access_denied',
      'the resource owner denied the request'
    ));
    // A form POST must never be replayed when the browser follows the callback.
    denial.status = 303;
    denial.headers['Set-Cookie'] = oauthAuthorizeClearCookie(requestID, settings);
    return JSON.stringify(denial);
  }
  if (decision !== 'allow' || !username || typeof password !== 'string') {
    return oauthAuthorizeHTMLResponse(
      requestID,
      csrfToken,
      authRequest.client_id,
      authRequest.client_name,
      authRequest.redirect_uri,
      authRequest.scope,
      'ユーザー名とパスワードを入力してください。',
      settings
    );
  }

  const normalizedUsername = typeof username === 'string' ? username.trim() : '';
  const credentialsHaveValidLength = normalizedUsername.length >= 1 &&
    normalizedUsername.length <= 128 &&
    password.length >= 1 && password.length <= 1024;
  const user = credentialsHaveValidLength
    ? oauthAuthorizeFirst(nyanRunSQL('./sql/oauth/select_user_by_username.sql', {
      username: normalizedUsername
    }))
    : null;
  // 存在しないユーザーでも同じArgon2id処理を行い、ユーザー列挙の時間差を抑える。
  const passwordHash = user && typeof user.password_hash === 'string'
    ? user.password_hash
    : settings.dummyPasswordHash;
  const hashMatches = typeof nyanPassword === 'object' &&
    typeof nyanPassword.verify === 'function' &&
    nyanPassword.verify(credentialsHaveValidLength ? password : '', passwordHash);
  const passwordOK = credentialsHaveValidLength && !!user && hashMatches;
  if (!passwordOK) {
    nyanRunSQL('./sql/oauth/increment_authorization_attempt.sql', {
      request_id: authRequest.id
    });
    return oauthAuthorizeHTMLResponse(
      requestID,
      csrfToken,
      authRequest.client_id,
      authRequest.client_name,
      authRequest.redirect_uri,
      authRequest.scope,
      'ユーザー名またはパスワードが正しくありません。',
      settings
    );
  }

  const consumed = oauthAuthorizeFirst(nyanRunSQL('./sql/oauth/consume_authorization_request.sql', {
    request_id: authRequest.id
  }));
  if (!consumed) {
    return oauthAuthorizeJSON(400, 'invalid_request', 'authorization request is invalid or expired');
  }
  nyanRunSQL('./sql/oauth/upsert_consent.sql', {
    user_id: user.id,
    client_id: authRequest.client_id,
    resource: authRequest.resource,
    scope: authRequest.scope
  });

  const authorizationCode = 'nyan_ac_' + nyanCrypto.randomBase64URL(32);
  nyanRunSQL('./sql/oauth/insert_authorization_code.sql', {
    code_hash: nyanCrypto.sha256Hex(authorizationCode),
    user_id: user.id,
    client_id: authRequest.client_id,
    redirect_uri: authRequest.redirect_uri,
    resource: authRequest.resource,
    scope: authRequest.scope,
    code_challenge: authRequest.code_challenge,
    expires_at: Math.floor(Date.now() / 1000) + 300
  });

  // 303 explicitly changes the form POST into a GET to the ChatGPT callback.
  return oauthAuthorizeEnvelope(303, {
    Location: oauthAuthorizeURL(authRequest.redirect_uri, {
      code: authorizationCode,
      state: authRequest.state
    }),
    'Cache-Control': 'no-store',
    'Set-Cookie': oauthAuthorizeClearCookie(requestID, settings)
  }, '');
}

function oauthAuthorizeMain() {
  const request = (typeof nyanRequest === 'object' && nyanRequest) || {};
  const settings = (typeof nyanRuntimeSettings === 'object' && nyanRuntimeSettings) || {};
  if (typeof settings.resource !== 'string' || !settings.resource ||
      typeof settings.authorizationEndpoint !== 'string' || !settings.authorizationEndpoint ||
      !Array.isArray(settings.scopes) || settings.scopes.length === 0 ||
      typeof settings.dummyPasswordHash !== 'string' ||
      !/^\$argon2id\$v=19\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/.test(settings.dummyPasswordHash) ||
      typeof nyanCrypto !== 'object' ||
      typeof nyanCrypto.randomBase64URL !== 'function' ||
      typeof nyanCrypto.sha256Hex !== 'function' ||
      typeof nyanCrypto.timingSafeEqual !== 'function') {
    return oauthAuthorizeJSON(500, 'server_error', 'authorization server is not configured');
  }
  const method = typeof request.method === 'string' ? request.method.toUpperCase() : '';
  if (method === 'GET') {
    return oauthAuthorizeGET(request, settings);
  }
  if (method === 'POST') {
    return oauthAuthorizePOST(request, settings);
  }
  return oauthAuthorizeJSON(405, 'invalid_request', 'method is not allowed');
}

oauthAuthorizeMain();
