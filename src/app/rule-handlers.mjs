// Admin rule configuration: minimum age and challenge lifetime, with confirmation for high-impact changes.
import { createAuditEvent } from '../contracts/audit-event.mjs';
import { sendApiError } from '../contracts/error-codes.mjs';
import { hasExactKeys, strictJsonBody } from '../http/json-body.mjs';

export const RULE_LIMITS = Object.freeze({ minimumAge: [13, 25], challengeLifetimeSeconds: [60, 900] });

// Public view of the active rule.
function ruleView(rule) {
  return {
    ruleName: rule.name,
    ruleVersion: rule.version,
    minimumAge: rule.minimumAge,
    challengeLifetimeSeconds: rule.challengeLifetimeSeconds,
    updatedAt: rule.updatedAt,
  };
}

// True when the integer lies inside the configured range for that setting.
function inRange(value, [low, high]) {
  return Number.isSafeInteger(value) && value >= low && value <= high;
}

// Build get and update handlers; existing challenges keep the rule stored when they were issued.
export function createRuleHandlers({ records, audit, now = Date.now }) {
  // Append a rules.changed event for the acting admin.
  async function record(request, outcome, code, context) {
    await audit(createAuditEvent({
      service: 'app', type: 'rules.changed', actor: { kind: 'account', ...request.auth }, outcome, code, context,
      occurredAt: now(),
    }));
  }

  // Return the active rule.
  function getRules(_request, response) {
    response.json(ruleView(records.activeRule()));
  }

  // Apply a new rule version; lowering the age or lengthening challenges needs confirm: true.
  async function updateHandler(request, response) {
    const body = request.jsonBody;
    if (!hasExactKeys(body, ['minimumAge', 'challengeLifetimeSeconds', 'confirm']) || typeof body.confirm !== 'boolean' ||
        !inRange(body.minimumAge, RULE_LIMITS.minimumAge) ||
        !inRange(body.challengeLifetimeSeconds, RULE_LIMITS.challengeLifetimeSeconds)) {
      sendApiError(response, 'MALFORMED_INPUT');
      return;
    }
    const current = records.activeRule();
    if (body.minimumAge === current.minimumAge && body.challengeLifetimeSeconds === current.challengeLifetimeSeconds) {
      response.json(ruleView(current));
      return;
    }
    const note = `minimumAge=${body.minimumAge} challengeLifetimeSeconds=${body.challengeLifetimeSeconds}`;
    const highImpact = body.minimumAge < current.minimumAge ||
      body.challengeLifetimeSeconds > current.challengeLifetimeSeconds;
    if (highImpact && !body.confirm) {
      await record(request, 'denied', 'CONFIRMATION_REQUIRED',
        { ruleName: current.name, ruleVersion: current.version, confirmed: false, note });
      sendApiError(response, 'CONFIRMATION_REQUIRED');
      return;
    }
    if (!records.updateRule(current, body, now())) {
      sendApiError(response, 'CONFLICT');
      return;
    }
    const updated = records.activeRule();
    await record(request, 'success', null, {
      ruleName: updated.name, ruleVersion: updated.version, previousRuleVersion: current.version,
      confirmed: body.confirm, note,
    });
    response.json(ruleView(updated));
  }

  return { getRules, updateRules: [...strictJsonBody(256), updateHandler] };
}
