function oauthProtectedResourceMetadataMain() {
  const settings = (typeof nyanRuntimeSettings === 'object' && nyanRuntimeSettings) || {};
  const resource = typeof settings.resource === 'string' ? settings.resource : '';
  const issuer = typeof settings.issuer === 'string' ? settings.issuer : '';
  const scopes = Array.isArray(settings.scopes) ? settings.scopes : [];

  if (!resource || !issuer || scopes.length === 0) {
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
      resource: resource,
      authorization_servers: [issuer],
      scopes_supported: scopes,
      bearer_methods_supported: ['header']
    })
  });
}

oauthProtectedResourceMetadataMain();
