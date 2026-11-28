// Plain-JS browser proof workflow: keeps birthDate and salt in memory and submits only public proof material.
export const PUBLIC_SIGNAL_ORDER = Object.freeze(['requestTag', 'commitment', 'cutoff', 'challengeHash']);

const OUTCOME_MESSAGES = Object.freeze({
  PROOF_VALID: ['valid', 'Verification allowed', 'The zero-knowledge proof, issuer signature, and credential status are valid.'],
  PROOF_INVALID: ['invalid', 'Verification denied', 'The zero-knowledge proof did not verify for this challenge.'],
  SIGNALS_MISMATCH: ['invalid', 'Verification denied', 'The proof public signals did not match the issued challenge.'],
  SIGNATURE_INVALID: ['invalid', 'Verification denied', 'The issuer Ed25519 signature failed verification.'],
  CREDENTIAL_EXPIRED: ['expired', 'Credential expired', 'The credential validity period has expired.'],
  CREDENTIAL_REVOKED: ['invalid', 'Credential revoked', 'The issuer reports that this credential has been revoked.'],
  CREDENTIAL_UNKNOWN: ['invalid', 'Credential unknown', 'The issuer has no matching active record for this credential.'],
  CHALLENGE_EXPIRED: ['expired', 'Challenge expired', 'The five-minute challenge expired before verification completed. Request a new challenge.'],
  CHALLENGE_REPLAYED: ['replayed', 'Challenge already used', 'This one-time challenge has already been consumed. Request a new challenge.'],
  ISSUER_UNAVAILABLE: ['unavailable', 'Issuer unavailable', 'The issuer status service is unavailable. Your challenge remains unused; retry before it expires.'],
  MALFORMED_INPUT: ['malformed', 'Malformed request', 'The request failed strict schema validation.'],
  PRIVATE_FIELD_SUBMITTED: ['malformed', 'Private field rejected', 'Private witness fields must never be sent to the verifier.'],
  CSRF_INVALID: ['denied', 'CSRF check failed', 'Session CSRF token was missing or invalid. Refresh the session and retry.'],
  AUTH_REQUIRED: ['denied', 'Sign-in required', 'Please sign in as an operator before generating or submitting proofs.'],
  AUTH_DENIED: ['denied', 'Access denied', 'Your current role is not permitted to perform this action.'],
  RATE_LIMITED: ['denied', 'Rate limited', 'Too many challenge requests. Wait a moment before trying again.'],
  CHALLENGE_NOT_FOUND: ['malformed', 'Challenge not found', 'The challenge ID does not match this session and credential.'],
  PAYLOAD_TOO_LARGE: ['malformed', 'Request too large', 'The verification payload exceeded the 16 KB limit.'],
});

/** Extract only the six public credential fields allowed in POST /api/verifications. */
export function publicCredentialFromPrivate(credential) {
  return Object.freeze({
    credentialId: credential.credentialId,
    commitment: credential.commitment,
    issuedAt: credential.issuedAt,
    expiresAt: credential.expiresAt,
    issuerName: credential.issuerName,
    signature: credential.signature,
  });
}

/** Assemble the circuit witness strictly in browser memory. */
export function buildProofWitness(credential, challenge, encodeBirthDateNumber) {
  return {
    birthDate: String(encodeBirthDateNumber(credential)),
    salt: credential.salt,
    commitment: credential.commitment,
    cutoff: String(challenge.cutoff),
    challengeHash: String(challenge.challengeHash),
  };
}

/** Build the strict POST /api/verifications payload with no private fields. */
export function buildVerificationSubmission({
  challengeId,
  credential,
  proof,
  publicSignals,
  proofGenerationMs = null,
}) {
  if (!Array.isArray(publicSignals) || publicSignals.length !== 4) {
    throw new TypeError('publicSignals must contain exactly 4 elements in order: requestTag, commitment, cutoff, challengeHash');
  }
  const submission = {
    version: '1',
    challengeId,
    credential: publicCredentialFromPrivate(credential),
    proof,
    publicSignals: publicSignals.map(String),
  };
  if (Number.isSafeInteger(proofGenerationMs) && proofGenerationMs >= 0 && proofGenerationMs <= 600_000) {
    submission.clientMeasurements = { proofGenerationMs };
  }
  return submission;
}

export async function sha256HexBrowser(buffer) {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/** Fetch committed proving artifacts and verify their SHA-256 hashes against /zk/manifest.json. */
export async function loadVerifiedArtifacts({
  fetchImpl = globalThis.fetch,
  manifestUrl = '/zk/manifest.json',
  wasmUrl = '/zk/age18.wasm',
  zkeyUrl = '/zk/age18_final.zkey',
} = {}) {
  const [manifestRes, wasmRes, zkeyRes] = await Promise.all([
    fetchImpl(manifestUrl),
    fetchImpl(wasmUrl),
    fetchImpl(zkeyUrl),
  ]);
  if (!manifestRes.ok || !wasmRes.ok || !zkeyRes.ok) {
    throw new Error('Failed to load committed Groth16 browser artifacts');
  }
  const manifest = await manifestRes.json();
  const [wasmBuf, zkeyBuf] = await Promise.all([wasmRes.arrayBuffer(), zkeyRes.arrayBuffer()]);
  const [wasmHash, zkeyHash] = await Promise.all([sha256HexBrowser(wasmBuf), sha256HexBrowser(zkeyBuf)]);
  if (wasmHash !== manifest?.artifacts?.['age18.wasm']) {
    throw new Error('Browser age18.wasm hash mismatch against manifest.json');
  }
  if (zkeyHash !== manifest?.artifacts?.['age18_final.zkey']) {
    throw new Error('Browser age18_final.zkey hash mismatch against manifest.json');
  }
  return {
    manifest,
    wasmBytes: new Uint8Array(wasmBuf),
    zkeyBytes: new Uint8Array(zkeyBuf),
  };
}

/** Map any verifier HTTP status and JSON body into a safe UI outcome without private data. */
export function formatVerificationOutcome(httpStatus, body) {
  const key = body?.reasonCode ?? body?.code ?? null;
  const entry = key && Object.hasOwn(OUTCOME_MESSAGES, key) ? OUTCOME_MESSAGES[key] : null;
  if (entry) {
    const [category, title, detail] = entry;
    return {
      ok: key === 'PROOF_VALID',
      category,
      title,
      detail,
      reasonCode: body?.reasonCode ?? null,
      code: body?.code ?? null,
      httpStatus,
    };
  }
  return {
    ok: false,
    category: 'error',
    title: 'Verification error',
    detail: `Unexpected verifier response (HTTP ${httpStatus}).`,
    reasonCode: body?.reasonCode ?? null,
    code: body?.code ?? null,
    httpStatus,
  };
}

async function postJson(fetchImpl, url, body, csrfToken) {
  const headers = { 'Content-Type': 'application/json' };
  if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
  const response = await fetchImpl(url, {
    method: 'POST',
    credentials: 'same-origin',
    headers,
    body: JSON.stringify(body),
  });
  let parsed = null;
  try {
    parsed = await response.json();
  } catch {
    parsed = null;
  }
  return { status: response.status, body: parsed };
}

/** Execute challenge request -> in-browser Groth16 proof -> public verification submission. */
export async function runBrowserProofWorkflow({
  credential,
  csrfToken,
  encodeBirthDateNumber,
  fetchImpl = globalThis.fetch,
  groth16 = globalThis.snarkjs?.groth16,
  now = () => performance.now(),
  verifyArtifacts = true,
  artifacts = null,
}) {
  if (!credential || typeof credential !== 'object') {
    throw new TypeError('Imported private credential is required');
  }
  if (!groth16 || typeof groth16.fullProve !== 'function') {
    throw new Error('snarkjs groth16 prover is not loaded');
  }

  const challengeRes = await postJson(fetchImpl, '/api/challenges', {
    credentialId: credential.credentialId,
  }, csrfToken);
  if (challengeRes.status !== 201) {
    return {
      stage: 'challenge',
      challenge: null,
      submission: null,
      responseStatus: challengeRes.status,
      responseBody: challengeRes.body,
      outcome: formatVerificationOutcome(challengeRes.status, challengeRes.body),
    };
  }

  const challenge = challengeRes.body;
  const loaded = artifacts ?? (verifyArtifacts
    ? await loadVerifiedArtifacts({ fetchImpl })
    : { wasmBytes: '/zk/age18.wasm', zkeyBytes: '/zk/age18_final.zkey' });

  const witness = buildProofWitness(credential, challenge, encodeBirthDateNumber);
  const started = now();
  const { proof, publicSignals } = await groth16.fullProve(witness, loaded.wasmBytes, loaded.zkeyBytes);
  const proofGenerationMs = Math.max(0, Math.round(now() - started));

  if (!Array.isArray(publicSignals) || publicSignals.length !== 4 ||
      publicSignals[1] !== credential.commitment ||
      publicSignals[2] !== String(challenge.cutoff) ||
      publicSignals[3] !== String(challenge.challengeHash)) {
    throw new Error('Generated publicSignals do not match expected contract order and challenge bindings');
  }

  const submission = buildVerificationSubmission({
    challengeId: challenge.challengeId,
    credential,
    proof,
    publicSignals,
    proofGenerationMs,
  });

  const verifyRes = await postJson(fetchImpl, '/api/verifications', submission, csrfToken);
  return {
    stage: 'verification',
    challenge,
    submission,
    responseStatus: verifyRes.status,
    responseBody: verifyRes.body,
    outcome: formatVerificationOutcome(verifyRes.status, verifyRes.body),
  };
}
