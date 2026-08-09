function oauthAuthorizationServerMetadataMain() {
  const settings = (typeof nyanRuntimeSettings === 'object' && nyanRuntimeSettings) || {};
  const required = [
    'issuer',
    'authorizationEndpoint',
    'tokenEndpoint',
    'registrationEndpoint',
    'revocationEndpoint'
  ];
  for (let i = 0; i < required.length; i += 1) {
    if (typeof settings[required[i]] !== 'string' || settings[required[i]].length === 0) {
      return JSON.stringify({
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-store'
        },
        body: JSON.stringify({ error: 'server_error' })
      });
    }
  }
  if (!Array.isArray(settings.scopes) || settings.scopes.length === 0) {
    return JSON.stringify({
      status: 500,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store'
      },
      body: JSON.stringify({ error: 'server_error' })
    });
  }

  return JSON.stringify({
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store'
    },
    body: JSON.stringify({
      issuer: settings.issuer,
      authorization_endpoint: settings.authorizationEndpoint,
      token_endpoint: settings.tokenEndpoint,
      registration_endpoint: settings.registrationEndpoint,
      revocation_endpoint: settings.revocationEndpoint,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_methods_supported: ['none'],
      code_challenge_methods_supported: ['S256'],
      scopes_supported: settings.scopes
    })
  });
}

oauthAuthorizationServerMetadataMain();
