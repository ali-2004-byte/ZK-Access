// User management handlers; each service's admin manages accounts only in its own database.
import { randomUUID } from 'node:crypto';
import { createAuditEvent } from '../contracts/audit-event.mjs';
import { sendApiError } from '../contracts/error-codes.mjs';
import { hasExactKeys, strictJsonBody } from '../http/json-body.mjs';
import { hashPassword } from './password.mjs';
import { normalizeUsername } from './username.mjs';

const MANAGED_ROLES = Object.freeze({ app: ['operator', 'viewer'], issuer: ['issuer_admin'] });
const ACCOUNT_ID = /^[A-Za-z0-9_-]{1,64}$/;

// Shape returned to the admin; never includes the password record.
function publicAccount(row) {
  return {
    accountId: row.id,
    username: row.username_normalized,
    role: row.role,
    disabled: row.disabled === 1,
    createdAt: row.created_at_unix,
  };
}

// Build list, create, and update handlers for one service.
export function createUserHandlers({ service, db, sessions, audit, now = Date.now }) {
  const roles = MANAGED_ROLES[service];
  if (!roles) throw new TypeError('Unknown user service');
  const listAll = db.prepare(
    'SELECT id, username_normalized, role, disabled, created_at_unix FROM accounts ORDER BY created_at_unix, id');
  const findOne = db.prepare(
    'SELECT id, username_normalized, role, disabled, created_at_unix FROM accounts WHERE id = ?');
  const insert = db.prepare(
    'INSERT INTO accounts (id, username_normalized, password_record, role, created_at_unix) VALUES (?, ?, ?, ?, ?)');
  const update = db.prepare('UPDATE accounts SET role = ?, disabled = ? WHERE id = ?');

  // Append a users.* audit event for the acting admin.
  async function record(request, type, context) {
    await audit(createAuditEvent({
      service, type, actor: { kind: 'account', ...request.auth }, outcome: 'success', context, occurredAt: now(),
    }));
  }

  // List every account in this service.
  function listUsers(_request, response) {
    response.json({ users: listAll.all().map(publicAccount) });
  }

  // Create one account with a managed role and a fresh scrypt record.
  async function createUserHandler(request, response) {
    const body = request.jsonBody;
    let username;
    let passwordRecord;
    try {
      if (!hasExactKeys(body, ['username', 'password', 'role']) || !roles.includes(body.role)) {
        throw new TypeError('Invalid user body');
      }
      username = normalizeUsername(body.username);
      passwordRecord = await hashPassword(body.password);
    } catch {
      sendApiError(response, 'MALFORMED_INPUT');
      return;
    }
    const id = randomUUID();
    try {
      insert.run(id, username, passwordRecord, body.role, Math.floor(now() / 1000));
    } catch (error) {
      if (/UNIQUE/.test(error.message)) {
        sendApiError(response, 'CONFLICT');
        return;
      }
      throw error;
    }
    await record(request, 'users.created', { targetAccountId: id, role: body.role });
    response.status(201).json(publicAccount(findOne.get(id)));
  }

  // Change a managed account's role or disabled flag; admins cannot change themselves.
  async function updateUserHandler(request, response) {
    const body = request.jsonBody;
    const accountId = request.params.accountId;
    if (!ACCOUNT_ID.test(accountId) || !hasExactKeys(body, [], ['role', 'disabled']) ||
        Object.keys(body).length === 0 ||
        (Object.hasOwn(body, 'role') && !roles.includes(body.role)) ||
        (Object.hasOwn(body, 'disabled') && typeof body.disabled !== 'boolean')) {
      sendApiError(response, 'MALFORMED_INPUT');
      return;
    }
    const target = findOne.get(accountId);
    if (!target || !roles.includes(target.role)) {
      sendApiError(response, 'NOT_FOUND');
      return;
    }
    if (target.id === request.auth.accountId) {
      sendApiError(response, 'CONFLICT');
      return;
    }
    const role = body.role ?? target.role;
    const disabled = body.disabled ?? target.disabled === 1;
    update.run(role, disabled ? 1 : 0, target.id);
    sessions.endAllForAccount(target.id);
    await record(request, 'users.updated', { targetAccountId: target.id, role, note: disabled ? 'disabled' : 'enabled' });
    response.json(publicAccount(findOne.get(target.id)));
  }

  return {
    listUsers,
    createUser: [...strictJsonBody(1024), createUserHandler],
    updateUser: [...strictJsonBody(256), updateUserHandler],
  };
}
