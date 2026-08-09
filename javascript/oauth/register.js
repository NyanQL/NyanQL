function oauthRegisterResponse(status, payload) {
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

function oauthRegisterError(description) {
  return oauthRegisterResponse(400, {
    error: 'invalid_client_metadata',
    error_description: description
  });
}

function oauthRegisterFirst(rows) {
  return Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
}

function oauthRegisterStringArray(value, defaultValue) {
  if (typeof value === 'undefined' || value === null) {
    return defaultValue.slice();
  }
  if (!Array.isArray(value)) {
    return null;
  }
  const result = [];
  for (let i = 0; i < value.length; i += 1) {
    if (typeof value[i] !== 'string') {
      return null;
    }
    result.push(value[i]);
  }
  return result;
}

function oauthRegisterGrantTypes(values) {
  if (!Array.isArray(values) || values.length < 1 || values.length > 2) {
    return null;
  }
  const unique = [];
  for (let index = 0; index < values.length; index += 1) {
    if ((values[index] !== 'authorization_code' && values[index] !== 'refresh_token') ||
        unique.indexOf(values[index]) >= 0) {
      return null;
    }
    unique.push(values[index]);
  }
  if (unique.indexOf('authorization_code') < 0) {
    return null;
  }
  // この認可サーバのpublic client profileはoffline accessを常に利用可能にする。
  return ['authorization_code', 'refresh_token'];
}

function oauthRegisterCodeResponseTypes(values) {
  return Array.isArray(values) && values.length === 1 && values[0] === 'code';
}

function oauthRegisterLoopbackAuthority(authority) {
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

function oauthRegisterValidRedirectURI(uri) {
  if (typeof uri !== 'string' || uri.length < 10 || uri.length > 2048) {
    return false;
  }
  if (/[\u0000-\u0020\u007f\\]/.test(uri) || uri.indexOf('#') >= 0) {
    return false;
  }
  const match = /^(https?):\/\/([^\/?#]+)(\/[^#]*)?$/.exec(uri);
  if (!match || match[2].indexOf('@') >= 0) {
    return false;
  }
  const scheme = match[1].toLowerCase();
  if (scheme === 'https') {
    return match[2].length > 0;
  }
  return scheme === 'http' && oauthRegisterLoopbackAuthority(match[2]);
}

function oauthRegisterAllowedRedirectURI(uri, settings) {
  if (!oauthRegisterValidRedirectURI(uri)) {
    return false;
  }
  if (/^http:/.test(uri)) {
    return settings.allowLoopbackRedirects === true;
  }
  const exact = Array.isArray(settings.redirectURIAllowlist)
    ? settings.redirectURIAllowlist
    : [];
  if (exact.indexOf(uri) >= 0) {
    return true;
  }
  const prefixes = Array.isArray(settings.redirectURIAllowedPrefixes)
    ? settings.redirectURIAllowedPrefixes
    : [];
  for (let i = 0; i < prefixes.length; i += 1) {
    const prefix = prefixes[i];
    if (typeof prefix !== 'string' || !/^https:\/\/[^\/?#]+\/[^?#]*\/$/.test(prefix)) {
      continue;
    }
    if (uri.indexOf(prefix) !== 0) {
      continue;
    }
    const callbackID = uri.slice(prefix.length);
    if (/^[A-Za-z0-9._~-]{1,256}$/.test(callbackID)) {
      return true;
    }
  }
  return false;
}

function oauthRegisterScopes(scopeValue, supportedScopes) {
  const requested = typeof scopeValue === 'string' && scopeValue.trim()
    ? scopeValue.trim().split(/\s+/)
    : supportedScopes.slice();
  const unique = [];
  for (let i = 0; i < requested.length; i += 1) {
    const scope = requested[i];
    if (!scope || supportedScopes.indexOf(scope) < 0 || unique.indexOf(scope) >= 0) {
      return null;
    }
    unique.push(scope);
  }
  if (supportedScopes.indexOf('offline_access') >= 0 && unique.indexOf('offline_access') < 0) {
    unique.push('offline_access');
  }
  return unique;
}

function oauthRegisterMain() {
  const request = (typeof nyanRequest === 'object' && nyanRequest) || {};
  const input = (request.json && typeof request.json === 'object') ? request.json : null;
  const settings = (typeof nyanRuntimeSettings === 'object' && nyanRuntimeSettings) || {};
  const supportedScopes = Array.isArray(settings.scopes) ? settings.scopes : [];
  const maxClients = settings.maxClients;

  if (!input || supportedScopes.length === 0 || typeof maxClients !== 'number' ||
      !isFinite(maxClients) || Math.floor(maxClients) !== maxClients ||
      maxClients < 1 || maxClients > 100000) {
    return oauthRegisterError('JSON client metadata is required');
  }

  const redirectURIs = oauthRegisterStringArray(input.redirect_uris, []);
  if (!redirectURIs || redirectURIs.length === 0 || redirectURIs.length > 20) {
    return oauthRegisterError('redirect_uris must contain between 1 and 20 values');
  }
  const uniqueRedirectURIs = [];
  for (let i = 0; i < redirectURIs.length; i += 1) {
    if (!oauthRegisterAllowedRedirectURI(redirectURIs[i], settings)) {
      return oauthRegisterError('redirect_uris contains an unsupported URI');
    }
    if (uniqueRedirectURIs.indexOf(redirectURIs[i]) >= 0) {
      return oauthRegisterError('redirect_uris contains a duplicate URI');
    }
    uniqueRedirectURIs.push(redirectURIs[i]);
  }

  const requestedGrantTypes = oauthRegisterStringArray(
    input.grant_types,
    ['authorization_code', 'refresh_token']
  );
  const grantTypes = oauthRegisterGrantTypes(requestedGrantTypes);
  const responseTypes = oauthRegisterStringArray(input.response_types, ['code']);
  const authMethod = typeof input.token_endpoint_auth_method === 'undefined'
    ? 'none'
    : input.token_endpoint_auth_method;
  if (!grantTypes) {
    return oauthRegisterError('only authorization_code and refresh_token are supported');
  }
  if (!oauthRegisterCodeResponseTypes(responseTypes)) {
    return oauthRegisterError('only the code response type is supported');
  }
  if (authMethod !== 'none') {
    return oauthRegisterError('only public clients are supported');
  }

  const clientName = typeof input.client_name === 'string' && input.client_name.trim()
    ? input.client_name.trim()
    : 'Dynamic client';
  if (clientName.length > 256 || /[\u0000-\u001f\u007f]/.test(clientName)) {
    return oauthRegisterError('client_name is invalid');
  }
  const scopes = oauthRegisterScopes(input.scope, supportedScopes);
  if (!scopes || scopes.length === 0) {
    return oauthRegisterError('scope contains an unsupported value');
  }
  if (typeof nyanCrypto !== 'object' || typeof nyanCrypto.randomBase64URL !== 'function') {
    return oauthRegisterResponse(500, { error: 'server_error' });
  }

  const clientID = 'nyan_client_' + nyanCrypto.randomBase64URL(24);
  const clientRows = nyanRunSQL('./sql/oauth/insert_client.sql', {
    client_id: clientID,
    client_name: clientName,
    grant_types: JSON.stringify(grantTypes),
    scope: scopes.join(' '),
    max_clients: maxClients
  });
  const client = oauthRegisterFirst(clientRows);
  if (!client) {
    return oauthRegisterResponse(503, {
      error: 'server_error',
      error_description: 'dynamic client registration capacity has been reached'
    });
  }
  for (let i = 0; i < uniqueRedirectURIs.length; i += 1) {
    nyanRunSQL('./sql/oauth/insert_client_redirect_uri.sql', {
      client_id: clientID,
      redirect_uri: uniqueRedirectURIs[i]
    });
  }

  return oauthRegisterResponse(201, {
    client_id: clientID,
    client_id_issued_at: Number(client.created_at),
    client_name: clientName,
    redirect_uris: uniqueRedirectURIs,
    grant_types: grantTypes,
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
    scope: scopes.join(' ')
  });
}

oauthRegisterMain();
