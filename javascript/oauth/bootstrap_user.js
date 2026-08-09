function oauthBootstrapJSON(status, payload) {
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

function oauthBootstrapFirst(rows) {
  return Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
}

function oauthBootstrapUserMain() {
  const request = (typeof nyanRequest === 'object' && nyanRequest) || {};
  const input = (request.json && typeof request.json === 'object')
    ? request.json
    : ((request.form && typeof request.form === 'object') ? request.form : {});
  const username = typeof input.username === 'string' ? input.username.trim() : '';
  const password = typeof input.password === 'string' ? input.password : '';
  const displayName = typeof input.display_name === 'string'
    ? input.display_name.trim()
    : (typeof input.displayName === 'string' ? input.displayName.trim() : '');

  if (username.length < 3 || username.length > 128 || /[\u0000-\u001f\u007f]/.test(username)) {
    return oauthBootstrapJSON(400, {
      error: 'invalid_request',
      error_description: 'username is invalid'
    });
  }
  if (password.length < 12 || password.length > 1024) {
    return oauthBootstrapJSON(400, {
      error: 'invalid_request',
      error_description: 'password must contain between 12 and 1024 characters'
    });
  }
  if (displayName.length > 256 || /[\u0000-\u001f\u007f]/.test(displayName)) {
    return oauthBootstrapJSON(400, {
      error: 'invalid_request',
      error_description: 'display_name is invalid'
    });
  }
  if (typeof nyanPassword !== 'object' || typeof nyanPassword.hash !== 'function') {
    return oauthBootstrapJSON(500, { error: 'server_error' });
  }

  const passwordHash = nyanPassword.hash(password);
  const rows = nyanRunSQL('./sql/oauth/upsert_user.sql', {
    username: username,
    password_hash: passwordHash,
    display_name: displayName
  });
  const user = oauthBootstrapFirst(rows);
  if (!user) {
    return oauthBootstrapJSON(500, { error: 'server_error' });
  }

  return oauthBootstrapJSON(200, {
    success: true,
    user: {
      id: user.id,
      username: user.username,
      display_name: user.display_name,
      enabled: Number(user.enabled) === 1
    }
  });
}

oauthBootstrapUserMain();
