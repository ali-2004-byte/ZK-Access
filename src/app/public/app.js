import { birthDateNumberForProof, parsePrivateCredentialJson } from '/shared/credential-json.mjs';
import { formatVerificationOutcome, loadVerifiedArtifacts, runBrowserProofWorkflow } from '/prover-client.mjs';
import { apiJson, byId, initResultControls, loadResults, requireRole, ROLE_PATHS, setNotice, utcTime } from '/ui-common.mjs';

const page = document.body.dataset.page;

async function initLogin() {
  try {
    const session = await apiJson('/api/session');
    if (ROLE_PATHS[session.role]) { location.replace(ROLE_PATHS[session.role]); return; }
  } catch { /* No active app session. */ }
  byId('login-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const feedback = byId('feedback');
    try {
      const username = byId('username').value;
      const password = byId('password').value;
      const session = await apiJson('/api/session/login', { method: 'POST', body: { username, password } });
      byId('password').value = '';
      location.replace(ROLE_PATHS[session.role] ?? '/');
    } catch (error) {
      byId('password').value = '';
      setNotice(feedback, error.message === 'RATE_LIMITED' ? 'Sign-in temporarily limited. Try again later.' : 'Sign-in failed. Check your credentials.', 'error');
    }
  });
}

function displayOutcome(outcome, result) {
  const lines = [outcome.title, outcome.detail];
  if (outcome.reasonCode) lines.push(`Reason: ${outcome.reasonCode}`);
  if (outcome.code) lines.push(`Code: ${outcome.code}`);
  if (result?.decision) lines.push(`Decision: ${result.decision}`);
  if (result?.ruleName) lines.push(`Rule: ${result.ruleName} · version ${result.ruleVersion}`);
  if (result?.nonceStatus) lines.push(`Nonce: ${result.nonceStatus}`);
  if (result?.credentialExpiryStatus) lines.push(`Credential expiry: ${result.credentialExpiryStatus}`);
  if (Number.isInteger(result?.proofGenerationMs)) lines.push(`Proof generation: ${result.proofGenerationMs} ms`);
  if (Number.isInteger(result?.verificationMs)) lines.push(`Verification: ${result.verificationMs} ms`);
  if (Number.isInteger(result?.proofSizeBytes)) lines.push(`Proof size: ${result.proofSizeBytes} bytes`);
  setNotice(byId('outcome-box'), lines.join('\n'), outcome.ok ? 'allow' : outcome.category === 'unavailable' ? 'warn' : 'deny');
}

async function submitRetry(submission, csrfToken) {
  const response = await fetch('/api/verifications', {
    method: 'POST', credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
    body: JSON.stringify(submission),
  });
  const body = await response.json().catch(() => null);
  return { outcome: formatVerificationOutcome(response.status, body), body };
}

async function initOperator(session) {
  const state = { credential: null, artifactsPromise: null, retrySubmission: null };
  const summary = byId('credential-summary');
  const prove = byId('prove-submit');
  const retry = byId('retry-submit');
  const fileInput = byId('credential-file');
  const textInput = byId('credential-json');

  function importText(text) {
    try {
      const credential = parsePrivateCredentialJson(text);
      state.credential = credential;
      state.retrySubmission = null;
      retry.hidden = true;
      setNotice(summary, `Imported credential ${credential.credentialId} from ${credential.issuerName}. Private values remain in this browser session.`);
      prove.disabled = false;
      return true;
    } catch {
      state.credential = null;
      prove.disabled = true;
      setNotice(summary, 'Invalid private credential. Check the nine-field JSON format, calendar date, and 4 KB limit.', 'error');
      return false;
    }
  }

  fileInput.addEventListener('change', async () => {
    const file = fileInput.files?.[0];
    if (!file) return;
    if (file.size > 4096) {
      state.credential = null; prove.disabled = true;
      setNotice(summary, 'Credential file exceeds the 4 KB limit.', 'error');
      fileInput.value = '';
      return;
    }
    try { importText(await file.text()); textInput.value = ''; }
    catch { state.credential = null; prove.disabled = true; setNotice(summary, 'Could not read the credential file.', 'error'); }
    finally { fileInput.value = ''; }
  });
  byId('import-text').addEventListener('click', () => { if (importText(textInput.value)) textInput.value = ''; });

  prove.addEventListener('click', async () => {
    if (!state.credential) return;
    prove.disabled = true;
    retry.hidden = true;
    state.retrySubmission = null;
    setNotice(byId('outcome-box'), 'Loading proof artifacts and generating the proof…');
    try {
      state.artifactsPromise ??= loadVerifiedArtifacts();
      let artifacts;
      try { artifacts = await state.artifactsPromise; }
      catch (error) { state.artifactsPromise = null; throw error; }
      const run = await runBrowserProofWorkflow({
        credential: state.credential, csrfToken: session.csrfToken,
        encodeBirthDateNumber: birthDateNumberForProof, artifacts,
      });
      displayOutcome(run.outcome, run.responseBody);
      if (run.outcome.reasonCode === 'ISSUER_UNAVAILABLE' && run.submission) {
        state.retrySubmission = run.submission;
        retry.hidden = false;
      }
      await loadResults('operator');
    } catch {
      setNotice(byId('outcome-box'), 'Proof generation failed. Check the credential and try again with a new challenge.', 'error');
    } finally { prove.disabled = !state.credential; }
  });

  retry.addEventListener('click', async () => {
    if (!state.retrySubmission) return;
    retry.disabled = true;
    try {
      const response = await submitRetry(state.retrySubmission, session.csrfToken);
      displayOutcome(response.outcome, response.body);
      if (response.outcome.reasonCode !== 'ISSUER_UNAVAILABLE') {
        state.retrySubmission = null;
        retry.hidden = true;
      }
      await loadResults('operator');
    } catch { setNotice(byId('outcome-box'), 'Could not retry verification. Check the service connection.', 'error'); }
    finally { retry.disabled = false; }
  });
}

async function loadRule() {
  const rule = await apiJson('/api/rules');
  byId('rule-current').textContent = `${rule.ruleName} · version ${rule.ruleVersion} · updated ${utcTime(rule.updatedAt)}`;
  byId('minimum-age').value = rule.minimumAge;
  byId('challenge-seconds').value = rule.challengeLifetimeSeconds;
  return rule;
}

async function loadUsers() {
  const { users } = await apiJson('/api/users');
  const target = byId('users-body');
  target.replaceChildren();
  for (const user of users) {
    const row = document.createElement('tr');
    for (const value of [user.username, user.role, user.disabled ? 'Disabled' : 'Active']) {
      const td = document.createElement('td'); td.textContent = value; row.append(td);
    }
    if (user.role !== 'admin') {
      const td = document.createElement('td');
      const button = document.createElement('button');
      button.className = 'button secondary'; button.type = 'button';
      button.textContent = user.disabled ? 'Enable' : 'Disable';
      button.addEventListener('click', async () => {
        try {
          await apiJson(`/api/users/${encodeURIComponent(user.accountId)}`, {
            method: 'PATCH', body: { disabled: !user.disabled }, csrfToken: currentSession.csrfToken,
          });
          await loadUsers();
        } catch (error) { setNotice(byId('user-feedback'), `User update failed: ${error.message}`, 'error'); }
      });
      td.append(button); row.append(td);
    }
    target.append(row);
  }
}

async function loadAudit() {
  try {
    const { events } = await apiJson('/api/audit-events?limit=50');
    const target = byId('audit-body'); target.replaceChildren();
    for (const event of events) {
      const row = document.createElement('tr');
      for (const value of [utcTime(event.occurredAt), event.type, event.outcome, event.code ?? '—']) {
        const td = document.createElement('td'); td.textContent = value; row.append(td);
      }
      target.append(row);
    }
    setNotice(byId('audit-feedback'), events.length ? '' : 'No audit events yet.');
  } catch (error) { setNotice(byId('audit-feedback'), `Could not load audit events: ${error.message}`, 'error'); }
}

let currentSession;
async function initAdmin(session) {
  currentSession = session;
  let rule;
  try { rule = await loadRule(); }
  catch (error) { setNotice(byId('rule-feedback'), `Could not load rule: ${error.message}`, 'error'); }
  byId('rule-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const minimumAge = Number(byId('minimum-age').value);
    const challengeLifetimeSeconds = Number(byId('challenge-seconds').value);
    const highImpact = rule && (minimumAge < rule.minimumAge || challengeLifetimeSeconds > rule.challengeLifetimeSeconds);
    const confirm = !highImpact || window.confirm('This change lowers the age threshold or lengthens the challenge lifetime. Apply it?');
    if (!confirm) return;
    try {
      rule = await apiJson('/api/rules', { method: 'PUT', csrfToken: session.csrfToken,
        body: { minimumAge, challengeLifetimeSeconds, confirm: highImpact } });
      await loadRule();
      setNotice(byId('rule-feedback'), `Rule saved as version ${rule.ruleVersion}.`);
      await loadAudit();
    } catch (error) { setNotice(byId('rule-feedback'), `Rule update failed: ${error.message}`, 'error'); }
  });
  byId('user-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    try {
      await apiJson('/api/users', { method: 'POST', csrfToken: session.csrfToken,
        body: { username: byId('new-username').value, password: byId('new-password').value, role: byId('new-role').value } });
      byId('new-password').value = '';
      byId('new-username').value = '';
      setNotice(byId('user-feedback'), 'User created.');
      await loadUsers(); await loadAudit();
    } catch (error) {
      byId('new-password').value = '';
      setNotice(byId('user-feedback'), `User creation failed: ${error.message}`, 'error');
    }
  });
  try { await loadUsers(); }
  catch (error) { setNotice(byId('user-feedback'), `Could not load users: ${error.message}`, 'error'); }
  await loadAudit();
}

async function main() {
  if (page === 'login') { await initLogin(); return; }
  if (!Object.hasOwn(ROLE_PATHS, page)) return;
  const session = await requireRole(page);
  if (!session) return;
  initResultControls(page);
  await loadResults(page);
  if (page === 'operator') await initOperator(session);
  if (page === 'admin') await initAdmin(session);
}

main().catch(() => { const feedback = byId('feedback') ?? byId('results-feedback'); setNotice(feedback, 'The page could not load. Refresh to retry.', 'error'); });
