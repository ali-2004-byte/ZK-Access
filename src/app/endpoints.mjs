// App endpoint table: each route names the role-matrix action that guards it.
export const APP_ENDPOINTS = Object.freeze([
  { name: 'login', method: 'POST', path: '/api/session/login', public: true },
  { name: 'logout', method: 'POST', path: '/api/session/logout', action: null },
  { name: 'currentSession', method: 'GET', path: '/api/session', action: null },
  { name: 'issueChallenge', method: 'POST', path: '/api/challenges', action: 'request_challenge' },
  { name: 'submitVerification', method: 'POST', path: '/api/verifications', action: 'submit_proof' },
  { name: 'listResults', method: 'GET', path: '/api/results', action: 'view_results' },
  { name: 'getResult', method: 'GET', path: '/api/results/:resultId', action: 'view_results' },
  { name: 'exportReport', method: 'GET', path: '/api/reports/export', action: 'export_report' },
  { name: 'getRules', method: 'GET', path: '/api/rules', action: 'configure_rules' },
  { name: 'updateRules', method: 'PUT', path: '/api/rules', action: 'configure_rules' },
  { name: 'listAuditEvents', method: 'GET', path: '/api/audit-events', action: 'review_audit' },
  { name: 'listUsers', method: 'GET', path: '/api/users', action: 'manage_users' },
  { name: 'createUser', method: 'POST', path: '/api/users', action: 'manage_users' },
  { name: 'updateUser', method: 'PATCH', path: '/api/users/:accountId', action: 'manage_users' },
].map(Object.freeze));
