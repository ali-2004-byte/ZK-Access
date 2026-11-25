// Issuer endpoint table: only issuer accounts reach issuance and revocation.
export const ISSUER_ENDPOINTS = Object.freeze([
  { name: 'login', method: 'POST', path: '/api/session/login', public: true },
  { name: 'logout', method: 'POST', path: '/api/session/logout', action: null },
  { name: 'currentSession', method: 'GET', path: '/api/session', action: null },
  { name: 'issueCredential', method: 'POST', path: '/api/credentials', action: 'issue_credential' },
  { name: 'revokeCredential', method: 'POST', path: '/api/credentials/:credentialId/revoke', action: 'revoke_credential' },
].map(Object.freeze));
