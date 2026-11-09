const APP_ACTIONS = Object.freeze({
  admin: new Set(['configure_rules', 'review_audit', 'view_results', 'export_report', 'manage_users']),
  operator: new Set(['request_challenge', 'submit_proof', 'view_results', 'export_report']),
  viewer: new Set(['view_results']),
});

const ISSUER_ACTIONS = Object.freeze({
  issuer_admin: new Set(['issue_credential', 'revoke_credential']),
});

/** Use only a role loaded from a server-side session, never a client-supplied role. */
export function mayUseAppAction(role, action) {
  return Object.hasOwn(APP_ACTIONS, role) && APP_ACTIONS[role].has(action);
}

/** The issuer service has its own login and does not share app roles. */
export function mayUseIssuerAction(role, action) {
  return Object.hasOwn(ISSUER_ACTIONS, role) && ISSUER_ACTIONS[role].has(action);
}
