function oauthVerifyFirst(rows) {
  return Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
}

function oauthVerifyUniqueStrings(values) {
  if (!Array.isArray(values)) {
    return [];
  }
  const result = [];
  for (let i = 0; i < values.length; i += 1) {
    if (typeof values[i] === 'string' && values[i] && result.indexOf(values[i]) < 0) {
      result.push(values[i]);
    }
  }
  return result;
}

function oauthVerifyRequiredScopes(input) {
  if (Array.isArray(input.mcp_required_scopes)) {
    return oauthVerifyUniqueStrings(input.mcp_required_scopes);
  }
  if (Array.isArray(input.requiredScopes)) {
    return oauthVerifyUniqueStrings(input.requiredScopes);
  }
  if (Array.isArray(input.required_scopes)) {
    return oauthVerifyUniqueStrings(input.required_scopes);
  }
  const schemes = Array.isArray(input.mcp_security_schemes)
    ? input.mcp_security_schemes
    : (Array.isArray(input.securitySchemes)
    ? input.securitySchemes
    : (Array.isArray(input.security_schemes) ? input.security_schemes : []));
  const required = [];
  for (let i = 0; i < schemes.length; i += 1) {
    const scheme = schemes[i];
    if (!scheme || scheme.type !== 'oauth2' || !Array.isArray(scheme.scopes)) {
      continue;
    }
    for (let j = 0; j < scheme.scopes.length; j += 1) {
      const scope = scheme.scopes[j];
      if (typeof scope === 'string' && scope && required.indexOf(scope) < 0) {
        required.push(scope);
      }
    }
  }
  return required;
}

function oauthVerifyHeader(input, request) {
  if (typeof input.authorization === 'string') {
    return input.authorization;
  }
  if (typeof input.authorizationHeader === 'string') {
    return input.authorizationHeader;
  }
  if (typeof input.authorization_header === 'string') {
    return input.authorization_header;
  }
  const headers = request.headers && typeof request.headers === 'object' ? request.headers : {};
  return typeof headers.authorization === 'string' ? headers.authorization : '';
}

function oauthVerifyChallenge(metadataURL, error, description, scope) {
  let challenge = 'Bearer resource_metadata="' + metadataURL + '"';
  if (error) {
    challenge += ', error="' + error + '"';
  }
  if (description) {
    challenge += ', error_description="' + description + '"';
  }
  if (scope) {
    challenge += ', scope="' + scope + '"';
  }
  return challenge;
}

function oauthVerifyDenied(status, challenge) {
  return JSON.stringify({
    allow: false,
    status: status,
    headers: {
      'WWW-Authenticate': challenge
    },
    mcpMeta: {
      'mcp/www_authenticate': [challenge]
    }
  });
}

function oauthVerifyMain() {
  const input = (typeof nyanAllParams === 'object' && nyanAllParams) || {};
  const request = (typeof nyanRequest === 'object' && nyanRequest) || {};
  const settings = (typeof nyanRuntimeSettings === 'object' && nyanRuntimeSettings) || {};
  if (typeof settings.resource !== 'string' || !settings.resource ||
      typeof settings.protectedResourceMetadata !== 'string' ||
      !/^https:\/\/[^\s"']+$/.test(settings.protectedResourceMetadata) ||
      typeof nyanCrypto !== 'object' ||
      typeof nyanCrypto.sha256Hex !== 'function' ||
      typeof nyanCrypto.timingSafeEqual !== 'function') {
    return JSON.stringify({ allow: false, status: 500, headers: {}, mcpMeta: {} });
  }

  const standardChallenge = oauthVerifyChallenge(
    settings.protectedResourceMetadata,
    'invalid_token',
    'Authentication is required',
    ''
  );
  const inputResource = typeof input.mcp_resource === 'string'
    ? input.mcp_resource
    : (typeof input.resource === 'string'
    ? input.resource
    : (typeof input.canonicalResource === 'string' ? input.canonicalResource : ''));
  if (inputResource !== settings.resource) {
    return oauthVerifyDenied(401, oauthVerifyChallenge(
      settings.protectedResourceMetadata,
      'invalid_token',
      'The access token is invalid for this resource',
      ''
    ));
  }

  const authorization = oauthVerifyHeader(input, request);
  const match = /^Bearer ([A-Za-z0-9._~-]{20,256})$/.exec(authorization);
  if (!match) {
    return oauthVerifyDenied(401, standardChallenge);
  }

  const tokenHash = nyanCrypto.sha256Hex(match[1]);
  const token = oauthVerifyFirst(nyanRunSQL('./sql/oauth/select_access_token.sql', {
    token_hash: tokenHash,
    resource: settings.resource
  }));
  if (!token || !nyanCrypto.timingSafeEqual(String(token.token_hash), tokenHash)) {
    return oauthVerifyDenied(401, oauthVerifyChallenge(
      settings.protectedResourceMetadata,
      'invalid_token',
      'The access token is invalid or expired',
      ''
    ));
  }

  const grantedScopes = typeof token.scope === 'string' && token.scope
    ? token.scope.split(/\s+/)
    : [];
  const requiredScopes = oauthVerifyRequiredScopes(input);
  for (let i = 0; i < requiredScopes.length; i += 1) {
    if (grantedScopes.indexOf(requiredScopes[i]) < 0) {
      return oauthVerifyDenied(403, oauthVerifyChallenge(
        settings.protectedResourceMetadata,
        'insufficient_scope',
        'The access token does not grant the required scope',
        requiredScopes.join(' ')
      ));
    }
  }

  return JSON.stringify({
    allow: true,
    status: 200,
    headers: {},
    principal: {
      userId: token.user_id,
      username: token.username,
      displayName: token.display_name,
      clientId: token.client_id
    },
    scopes: grantedScopes,
    mcpMeta: {}
  });
}

oauthVerifyMain();
