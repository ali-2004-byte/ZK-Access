// Shared HTTP test helpers: accounts with cached password records, a loopback server, and a cookie-keeping client.
import { once } from 'node:events';
import { hashPassword } from '../src/auth/password.mjs';

const records = {};

// Insert an account with a cached scrypt record so each password is hashed once per run.
export async function addAccount(db, id, username, password, role) {
  records[password] ??= await hashPassword(password);
  db.prepare('INSERT INTO accounts (id, username_normalized, password_record, role, created_at_unix) VALUES (?, ?, ?, ?, ?)')
    .run(id, username, records[password], role, 1);
}

// Start a service on an ephemeral loopback port, run the callback, then close it.
export async function withServer(app, run) {
  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    await run(`http://127.0.0.1:${server.address().port}`);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
  }
}

// Minimal browser stand-in that keeps one cookie and the last CSRF token.
export function browser(origin) {
  const client = { cookie: null, csrfToken: null, setCookie: null };
  client.request = async (method, route, body, { csrf = true, contentType = 'application/json' } = {}) => {
    const headers = {};
    if (client.cookie) headers.cookie = client.cookie;
    if (csrf && client.csrfToken) headers['x-csrf-token'] = client.csrfToken;
    if (body !== undefined) headers['content-type'] = contentType;
    const response = await fetch(`${origin}${route}`, {
      method, headers, body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
    });
    const setCookie = response.headers.get('set-cookie');
    if (setCookie) {
      client.setCookie = setCookie;
      const pair = setCookie.split(';', 1)[0];
      client.cookie = pair.endsWith('=') ? null : pair;
    }
    const text = await response.text();
    const json = text ? JSON.parse(text) : null;
    if (json?.csrfToken) client.csrfToken = json.csrfToken;
    return { status: response.status, json, headers: response.headers };
  };
  client.login = (username, password) => client.request('POST', '/api/session/login', { username, password });
  return client;
}
