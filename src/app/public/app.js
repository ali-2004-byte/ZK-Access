// DOM controller for the operator browser proof generation page.
import { birthDateNumberForProof, parsePrivateCredentialJson } from '/shared/credential-json.mjs';
import { formatVerificationOutcome, loadVerifiedArtifacts, runBrowserProofWorkflow } from '/prover-client.mjs';

const state = {
  csrfToken: null,
  role: null,
  credential: null,
  artifactsPromise: null,
};

const sessionStatus = document.getElementById('session-status');
const loginForm = document.getElementById('login-form');
const credentialInput = document.getElementById('credential-file');
const credentialText = document.getElementById('credential-json');
const credentialSummary = document.getElementById('credential-summary');
const proveButton = document.getElementById('prove-submit');
const outcomeBox = document.getElementById('outcome-box');

function setOutcome(outcome, extra = null) {
  outcomeBox.hidden = false;
  outcomeBox.dataset.category = outcome.category;
  const lines = [`${outcome.title}: ${outcome.detail}`];
  if (outcome.reasonCode) lines.push(`Reason code: ${outcome.reasonCode}`);
  if (outcome.code) lines.push(`Error code: ${outcome.code}`);
  if (extra?.decision) lines.push(`Decision: ${extra.decision}`);
  if (extra?.nonceStatus) lines.push(`Nonce status: ${extra.nonceStatus}`);
  if (extra?.credentialExpiryStatus) lines.push(`Credential expiry: ${extra.credentialExpiryStatus}`);
  if (Number.isInteger(extra?.proofGenerationMs)) lines.push(`Proof generation: ${extra.proofGenerationMs} ms`);
  if (Number.isInteger(extra?.verificationMs)) lines.push(`Verification: ${extra.verificationMs} ms`);
  if (Number.isInteger(extra?.proofSizeBytes)) lines.push(`Proof size: ${extra.proofSizeBytes} bytes`);
  outcomeBox.textContent = lines.join('\n');
}

async function refreshSession() {
  const response = await fetch('/api/session', { credentials: 'same-origin' });
  if (!response.ok) {
    state.csrfToken = null;
    state.role = null;
    sessionStatus.textContent = 'Not signed in. Sign in with an operator account to request challenges and verify proofs.';
    proveButton.disabled = true;
    return;
  }
  const session = await response.json();
  state.csrfToken = session.csrfToken;
  state.role = session.role;
  sessionStatus.textContent = `Signed in (${session.role}).`;
  proveButton.disabled = !state.credential || session.role !== 'operator';
}

function importCredentialText(text) {
  try {
    const parsed = parsePrivateCredentialJson(text);
    state.credential = parsed;
    credentialSummary.textContent = `Imported credential ${parsed.credentialId} (${parsed.issuerName}). Private birthDate and salt stay in browser memory only.`;
    proveButton.disabled = state.role !== 'operator';
  } catch (error) {
    state.credential = null;
    credentialSummary.textContent = `Invalid private credential JSON: ${error.message}`;
    proveButton.disabled = true;
  }
}

loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  const response = await fetch('/api/session/login', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    setOutcome(formatVerificationOutcome(response.status, body));
    return;
  }
  document.getElementById('password').value = '';
  await refreshSession();
});

credentialInput.addEventListener('change', async () => {
  const file = credentialInput.files?.[0];
  if (!file) return;
  const text = await file.text();
  credentialText.value = '';
  importCredentialText(text);
});

document.getElementById('import-text').addEventListener('click', () => {
  importCredentialText(credentialText.value);
});

proveButton.addEventListener('click', async () => {
  if (!state.credential) return;
  proveButton.disabled = true;
  try {
    state.artifactsPromise ??= loadVerifiedArtifacts();
    const artifacts = await state.artifactsPromise;
    const result = await runBrowserProofWorkflow({
      credential: state.credential,
      csrfToken: state.csrfToken,
      encodeBirthDateNumber: birthDateNumberForProof,
      artifacts,
    });
    setOutcome(result.outcome, result.responseBody);
  } catch (error) {
    setOutcome({
      category: 'invalid',
      title: 'Proof generation failed',
      detail: error?.message || 'Unable to generate proof for this credential and challenge.',
    });
  } finally {
    proveButton.disabled = !state.credential || state.role !== 'operator';
  }
});

refreshSession();
