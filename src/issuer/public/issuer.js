const byId = (id) => document.getElementById(id);
let session = null;

function notice(id, message, tone = 'info') {
  const target = byId(id);
  target.textContent = message;
  target.dataset.tone = tone;
  target.hidden = !message;
}

function utcSeconds(seconds) {
  return new Date(seconds * 1000).toLocaleString(undefined, { timeZone: 'UTC', dateStyle: 'medium', timeStyle: 'short' }) + ' UTC';
}

async function api(path, { method = 'GET', body } = {}) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (session && method !== 'GET') headers['X-CSRF-Token'] = session.csrfToken;
  const response = await fetch(path, { method, credentials: 'same-origin', headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  const data = await response.json().catch(() => null);
  if (!response.ok) throw new Error(data?.code ?? `HTTP ${response.status}`);
  return data;
}

function setSession(value) {
  session = value?.role === 'issuer_admin' ? value : null;
  byId('login-panel').hidden = !!session;
  byId('workspace').hidden = !session;
  byId('logout').hidden = !session;
  byId('session-label').textContent = session ? 'issuer admin · signed in' : 'Not signed in';
}

function randomSalt() {
  const bytes = crypto.getRandomValues(new Uint8Array(31));
  let number = 0n;
  for (const byte of bytes) number = (number << 8n) + BigInt(byte);
  return number.toString();
}

function downloadCredential(credential) {
  const bytes = new Blob([`${JSON.stringify(credential, null, 2)}\n`], { type: 'application/json' });
  const url = URL.createObjectURL(bytes);
  const link = document.createElement('a');
  link.href = url;
  link.download = `zk-access-credential-${credential.credentialId}.json`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function loadRecords() {
  try {
    const { credentials } = await api('/api/credentials');
    const target = byId('records-body');
    target.replaceChildren();
    notice('records-feedback', credentials.length ? '' : 'No credentials issued yet.');
    for (const credential of credentials) {
      const row = document.createElement('tr');
      for (const value of [credential.credentialId, utcSeconds(credential.issuedAt), utcSeconds(credential.expiresAt), credential.status]) {
        const td = document.createElement('td'); td.textContent = value; row.append(td);
      }
      const action = document.createElement('td');
      if (credential.status === 'active') {
        const button = document.createElement('button');
        button.type = 'button'; button.className = 'button secondary'; button.textContent = 'Revoke';
        button.addEventListener('click', async () => {
          if (!window.confirm(`Revoke credential ${credential.credentialId}? This prevents future allows.`)) return;
          try {
            await api(`/api/credentials/${encodeURIComponent(credential.credentialId)}/revoke`, { method: 'POST' });
            notice('records-feedback', 'Credential revoked.');
            await loadRecords();
          } catch (error) { notice('records-feedback', `Revocation failed: ${error.message}`, 'error'); }
        });
        action.append(button);
      }
      row.append(action); target.append(row);
    }
  } catch (error) { notice('records-feedback', `Could not load issuance records: ${error.message}`, 'error'); }
}

async function loadIssuerUsers() {
  try {
    const { users } = await api('/api/users');
    const target = byId('issuer-users-body');
    target.replaceChildren();
    for (const user of users) {
      const row = document.createElement('tr');
      for (const value of [user.username, user.disabled ? 'Disabled' : 'Active']) {
        const td = document.createElement('td'); td.textContent = value; row.append(td);
      }
      const action = document.createElement('td');
      if (user.accountId !== session.accountId) {
        const button = document.createElement('button');
        button.type = 'button'; button.className = 'button secondary';
        button.textContent = user.disabled ? 'Enable' : 'Disable';
        button.addEventListener('click', async () => {
          try {
            await api(`/api/users/${encodeURIComponent(user.accountId)}`, {
              method: 'PATCH', body: { disabled: !user.disabled },
            });
            await loadIssuerUsers();
          } catch (error) { notice('issuer-users-feedback', `User update failed: ${error.message}`, 'error'); }
        });
        action.append(button);
      }
      row.append(action); target.append(row);
    }
    notice('issuer-users-feedback', users.length ? '' : 'No issuer admins found.');
  } catch (error) { notice('issuer-users-feedback', `Could not load issuer users: ${error.message}`, 'error'); }
}

byId('login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const value = await api('/api/session/login', { method: 'POST',
      body: { username: byId('username').value, password: byId('password').value } });
    byId('password').value = '';
    if (value.role !== 'issuer_admin') throw new Error('AUTH_DENIED');
    setSession(value);
    await loadRecords();
    await loadIssuerUsers();
  } catch {
    byId('password').value = '';
    notice('login-feedback', 'Sign-in failed. Check your issuer-admin credentials.', 'error');
  }
});

byId('logout').addEventListener('click', async () => {
  try { await api('/api/session/logout', { method: 'POST' }); }
  finally { setSession(null); byId('birth-date').value = ''; }
});

byId('issue-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const birthDate = byId('birth-date').value;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(birthDate)) {
    notice('issue-feedback', 'Enter a real calendar date.', 'error');
    return;
  }
  const button = event.submitter;
  button.disabled = true;
  try {
    const credential = await api('/api/credentials', { method: 'POST',
      body: { version: '1', birthDate, salt: randomSalt() } });
    downloadCredential(credential);
    byId('birth-date').value = '';
    notice('issue-feedback', `Credential ${credential.credentialId} issued and downloaded.`);
    await loadRecords();
  } catch (error) { notice('issue-feedback', `Issuance failed: ${error.message}`, 'error'); }
  finally { button.disabled = false; }
});

byId('issuer-user-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    await api('/api/users', { method: 'POST', body: {
      username: byId('issuer-username').value,
      password: byId('issuer-password').value,
      role: 'issuer_admin',
    } });
    byId('issuer-username').value = '';
    byId('issuer-password').value = '';
    notice('issuer-users-feedback', 'Issuer admin created.');
    await loadIssuerUsers();
  } catch (error) {
    byId('issuer-password').value = '';
    notice('issuer-users-feedback', `Could not create issuer admin: ${error.message}`, 'error');
  }
});

api('/api/session').then((value) => {
  setSession(value);
  if (session) { loadRecords(); loadIssuerUsers(); }
}).catch(() => setSession(null));
