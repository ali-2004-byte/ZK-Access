export const ROLE_PATHS = Object.freeze({ admin: '/admin', operator: '/operator', viewer: '/viewer' });

export function byId(id) { return document.getElementById(id); }

export function setNotice(element, message, tone = 'info') {
  if (!element) return;
  element.textContent = message;
  element.dataset.tone = tone;
  element.hidden = !message;
}

export function utcTime(milliseconds) {
  if (!Number.isFinite(milliseconds)) return '—';
  return new Date(milliseconds).toLocaleString(undefined, { timeZone: 'UTC', dateStyle: 'medium', timeStyle: 'short' }) + ' UTC';
}

export async function apiJson(path, { method = 'GET', body, csrfToken } = {}) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
  const response = await fetch(path, {
    method, credentials: 'same-origin', headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    const error = new Error(data?.code ?? data?.reasonCode ?? `HTTP ${response.status}`);
    error.status = response.status;
    throw error;
  }
  return data;
}

export async function requireRole(page) {
  let session;
  try { session = await apiJson('/api/session'); }
  catch { location.replace('/'); return null; }
  const destination = ROLE_PATHS[session.role];
  if (!destination) { location.replace('/'); return null; }
  if (page !== session.role) { location.replace(destination); return null; }
  const label = byId('session-label');
  if (label) label.textContent = `${session.role} · signed in`;
  byId('logout')?.addEventListener('click', async () => {
    try { await apiJson('/api/session/logout', { method: 'POST', csrfToken: session.csrfToken }); }
    finally { location.replace('/'); }
  });
  return session;
}

function cell(row, value) {
  const td = document.createElement('td');
  td.textContent = String(value ?? '—');
  row.append(td);
  return td;
}

function metric(id, value) { if (byId(id)) byId(id).textContent = String(value); }

function drawBars(results) {
  const target = byId('decision-bars');
  if (!target) return;
  target.replaceChildren();
  const total = results.length;
  for (const decision of ['allow', 'deny']) {
    const count = results.filter((result) => result.decision === decision).length;
    const group = document.createElement('div');
    const label = document.createElement('div');
    label.className = 'bar-label';
    const name = document.createElement('span'); name.textContent = decision === 'allow' ? 'Allow' : 'Deny';
    const value = document.createElement('span'); value.textContent = `${count} of ${total}`;
    label.append(name, value);
    const track = document.createElement('div'); track.className = 'bar-track';
    const fill = document.createElement('div'); fill.className = `bar-fill ${decision}`;
    fill.style.width = `${total ? count / total * 100 : 0}%`;
    track.append(fill); group.append(label, track); target.append(group);
  }
}

function drawPerformance(results) {
  const target = byId('performance-summary');
  if (!target) return;
  target.replaceChildren();
  for (const [field, label, unit] of [
    ['proofGenerationMs', 'Browser proof generation', 'ms'],
    ['verificationMs', 'Server proof verification', 'ms'],
    ['proofSizeBytes', 'Proof JSON size', 'bytes'],
    ['decisionLatencyMs', 'Decision latency', 'ms'],
  ]) {
    const values = results.map((row) => row[field]).filter(Number.isFinite);
    const card = document.createElement('div');
    const name = document.createElement('p'); name.className = 'metric-label'; name.textContent = label;
    const number = document.createElement('div'); number.className = 'metric';
    number.textContent = values.length ? `${Math.round(values.reduce((sum, value) => sum + value, 0) / values.length)} ${unit}` : '—';
    const foot = document.createElement('p'); foot.className = 'metric-foot';
    foot.textContent = `${values.length} displayed result${values.length === 1 ? '' : 's'} with this measurement`;
    card.append(name, number, foot); target.append(card);
  }
}

const DETAIL_FIELDS = [
  ['decision', 'Decision'], ['reasonCode', 'Reason'], ['ruleName', 'Rule'],
  ['ruleVersion', 'Rule version'], ['nonceStatus', 'Nonce status'],
  ['verifiedAt', 'Verified at'], ['credentialId', 'Credential ID'],
  ['issuerName', 'Issuer'], ['credentialExpiryStatus', 'Credential expiry'],
  ['proofSizeBytes', 'Proof size (bytes)'], ['proofGenerationMs', 'Proof generation (ms)'],
  ['verificationMs', 'Verification (ms)'], ['decisionLatencyMs', 'Decision latency (ms)'],
];

function showDetail(result, role) {
  const target = byId('result-detail');
  if (!target) return;
  target.replaceChildren();
  const heading = document.createElement('h3'); heading.textContent = 'Result evidence';
  const list = document.createElement('dl'); list.className = 'detail';
  for (const [key, label] of DETAIL_FIELDS) {
    if (role === 'viewer' && ['proofSizeBytes', 'proofGenerationMs', 'verificationMs', 'decisionLatencyMs'].includes(key)) continue;
    if (!Object.hasOwn(result, key)) continue;
    const dt = document.createElement('dt'); dt.textContent = label;
    const dd = document.createElement('dd');
    dd.textContent = key === 'verifiedAt' ? utcTime(result[key]) : String(result[key] ?? '—');
    list.append(dt, dd);
  }
  const action = document.createElement('p');
  action.className = 'muted';
  action.textContent = result.decision === 'allow' ? 'This request met the recorded rule.' :
    result.reasonCode === 'ISSUER_UNAVAILABLE' ? 'Retry while the challenge is still valid.' :
      'Review the reason code and request a new challenge if another attempt is needed.';
  target.append(heading, list, action);
  target.hidden = false;
}

export function resultQuery() {
  const params = new URLSearchParams();
  const decision = byId('filter-decision')?.value;
  const reason = byId('filter-reason')?.value.trim().toUpperCase();
  if (decision) params.set('decision', decision);
  if (reason) params.set('reasonCode', reason);
  return params.toString();
}

export async function loadResults(role) {
  const feedback = byId('results-feedback');
  const target = byId('results-body');
  try {
    const query = resultQuery();
    const { results } = await apiJson(`/api/results${query ? `?${query}` : ''}`);
    target.replaceChildren();
    metric('result-count', results.length);
    metric('allow-count', results.filter((row) => row.decision === 'allow').length);
    metric('deny-count', results.filter((row) => row.decision === 'deny').length);
    drawBars(results);
    drawPerformance(results);
    setNotice(feedback, results.length ? '' : 'No results match these filters.');
    byId('result-detail').hidden = true;
    for (const result of results) {
      const row = document.createElement('tr');
      cell(row, utcTime(result.verifiedAt));
      const status = cell(row, result.decision); status.className = `status ${result.decision}`;
      cell(row, result.reasonCode);
      cell(row, `${result.ruleName} · v${result.ruleVersion}`);
      cell(row, result.credentialId);
      const action = document.createElement('td');
      const button = document.createElement('button');
      button.type = 'button'; button.className = 'button secondary'; button.textContent = 'Details';
      button.addEventListener('click', () => showDetail(result, role));
      action.append(button); row.append(action); target.append(row);
    }
  } catch (error) {
    setNotice(feedback, `Could not load results: ${error.message}`, 'error');
  }
}

export function initResultControls(role) {
  byId('result-filters')?.addEventListener('submit', (event) => { event.preventDefault(); loadResults(role); });
  if (role === 'viewer') return;
  for (const format of ['json', 'csv']) {
    byId(`export-${format}`)?.addEventListener('click', async () => {
      const feedback = byId('results-feedback');
      try {
        const params = new URLSearchParams(resultQuery());
        params.set('format', format);
        const response = await fetch(`/api/reports/export?${params}`, { credentials: 'same-origin' });
        if (!response.ok) {
          const body = await response.json().catch(() => null);
          throw new Error(body?.code ?? `HTTP ${response.status}`);
        }
        const url = URL.createObjectURL(await response.blob());
        const link = document.createElement('a');
        link.href = url; link.download = `zk-access-report.${format}`;
        link.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        setNotice(feedback, `${format.toUpperCase()} report downloaded.`);
      } catch (error) { setNotice(feedback, `Export failed: ${error.message}`, 'error'); }
    });
  }
}
