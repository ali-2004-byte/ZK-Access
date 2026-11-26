// End-to-end issuance and verification tests with real Ed25519 signatures and Groth16 proofs.
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import test from 'node:test';
import { groth16 } from 'snarkjs';
import { checkIssuerStatus } from '../src/app/issuer-status-client.mjs';
import { closeProofEngine } from '../src/app/proof-engine.mjs';
import { createApp } from '../src/app/server.mjs';
import { parsePrivateCredentialJson } from '../src/credential-json.mjs';
import { signCredentialFields, verifyCredentialFields } from '../src/credential-signing.mjs';
import { openServiceDatabase } from '../src/db/service-database.mjs';
import { createIssuer } from '../src/issuer/server.mjs';
import { requestTag } from '../src/zk/poseidon.mjs';
import { addAccount, browser, withServer } from './http-helpers.mjs';

const identifierKey = randomBytes(32);
const serviceToken = randomBytes(32).toString('base64url');
const { privateKey: signingKey, publicKey: trustedIssuerKey } = generateKeyPairSync('ed25519');
const PASSWORD = 'synthetic-demo-password';
const BIRTH_DATE = '2008-11-09';
const SALT = '123456789';
const WASM = new URL('../zk/artifacts/age18.wasm', import.meta.url).pathname;
const ZKEY = new URL('../zk/artifacts/age18_final.zkey', import.meta.url).pathname;
const DUMMY_PROOF = {
  pi_a: ['1', '2', '1'], pi_b: [['3', '4'], ['5', '6'], ['1', '0']], pi_c: ['7', '8', '1'],
  protocol: 'groth16', curve: 'bn128',
};

test.after(closeProofEngine);

// Run both services against in-memory databases with a shared, movable clock and a switchable issuer link.
async function withSystem(run, { start = Date.UTC(2026, 10, 9, 12) } = {}) {
  const clock = { now: start, issuerDown: false };
  const now = () => clock.now;
  const issuerDb = openServiceDatabase('issuer', { file: ':memory:' });
  const appDb = openServiceDatabase('app', { file: ':memory:' });
  await addAccount(issuerDb, 'issuer-admin-1', 'issuer1', PASSWORD, 'issuer_admin');
  await addAccount(appDb, 'operator-1', 'operator1', PASSWORD, 'operator');
  await addAccount(appDb, 'viewer-1', 'viewer1', PASSWORD, 'viewer');
  await withServer(createIssuer({ db: issuerDb, identifierKey, signingKey, serviceToken, now }), async (issuerOrigin) => {
    const checkStatus = (credential) => (clock.issuerDown ? 'unavailable' :
      checkIssuerStatus(credential, { serviceToken, issuerOrigin }));
    const app = createApp({ db: appDb, identifierKey, trustedIssuerKey, checkStatus, now });
    await withServer(app, async (appOrigin) => {
      const issuerAdmin = browser(issuerOrigin);
      await issuerAdmin.login('issuer1', PASSWORD);
      const operator = browser(appOrigin);
      await operator.login('operator1', PASSWORD);
      await run({ clock, issuerDb, appDb, issuerAdmin, operator, appOrigin, issuerOrigin });
    });
  });
}

// Issue a credential through the issuer API and return the downloaded private file.
async function issue(issuerAdmin, birthDate = BIRTH_DATE, salt = SALT) {
  const response = await issuerAdmin.request('POST', '/api/credentials', { version: '1', birthDate, salt });
  assert.equal(response.status, 201);
  return response.json;
}

// The six public credential fields the browser may send to the app.
function publicCredential(file) {
  const { credentialId, commitment, issuedAt, expiresAt, issuerName, signature } = file;
  return { credentialId, commitment, issuedAt, expiresAt, issuerName, signature };
}

// Generate a real proof in place of the browser.
async function prove(file, challenge) {
  return groth16.fullProve({
    birthDate: file.birthDate.replaceAll('-', ''), salt: file.salt, commitment: file.commitment,
    cutoff: challenge.cutoff, challengeHash: challenge.challengeHash,
  }, WASM, ZKEY, undefined, undefined, { singleThread: true });
}

// Correct public signals with a placeholder proof, for checks decided before proof verification.
function unprovenSubmission(file, challenge) {
  return {
    version: '1',
    challengeId: challenge.challengeId,
    credential: publicCredential(file),
    proof: DUMMY_PROOF,
    publicSignals: [requestTag(challenge.challengeHash, file.commitment), file.commitment, challenge.cutoff,
      challenge.challengeHash],
  };
}

// Request a challenge for a credential as the operator.
async function requestChallenge(operator, credentialId) {
  const response = await operator.request('POST', '/api/challenges', { credentialId });
  assert.equal(response.status, 201);
  return response.json;
}

// Current state of a stored challenge.
function stateOf(appDb, challengeId) {
  return appDb.prepare('SELECT state FROM challenges WHERE challenge_id = ?').get(challengeId).state;
}

test('issuer signs a nine-field private file and keeps no birth date, salt, or body', async () => {
  await withSystem(async ({ issuerDb, issuerAdmin }) => {
    const file = await issue(issuerAdmin);
    assert.deepEqual(Object.keys(file), ['version', 'credentialId', 'birthDate', 'salt', 'commitment', 'issuedAt',
      'expiresAt', 'issuerName', 'signature']);
    assert.ok(parsePrivateCredentialJson(JSON.stringify(file)));
    assert.equal(Number(file.expiresAt) - Number(file.issuedAt), 90 * 24 * 60 * 60);
    const fields = [file.credentialId, file.commitment, file.issuedAt, file.expiresAt, file.issuerName];
    assert.equal(verifyCredentialFields(fields, Buffer.from(file.signature, 'base64url'), trustedIssuerKey), true);

    const columns = issuerDb.prepare('SELECT * FROM credentials').get();
    assert.deepEqual(Object.keys(columns), ['credential_id', 'commitment', 'signature', 'issued_at_unix',
      'expires_at_unix', 'issued_by', 'status']);
    for (const table of ['credentials', 'audit_events', 'sessions', 'accounts']) {
      const dump = JSON.stringify(issuerDb.prepare(`SELECT * FROM ${table}`).all());
      assert.equal(dump.includes(BIRTH_DATE) || dump.includes('20081109') || dump.includes(SALT), false, table);
    }

    for (const bad of [{ birthDate: '2008-02-30' }, { birthDate: '2026-11-10' }, { salt: '-1' }, { extra: 'x' }]) {
      const response = await issuerAdmin.request('POST', '/api/credentials', { version: '1', birthDate: BIRTH_DATE, salt: SALT, ...bad });
      assert.deepEqual(response.json, { code: 'MALFORMED_INPUT' }, JSON.stringify(bad));
    }
    const rejected = issuerDb.prepare("SELECT context_json FROM audit_events WHERE type = 'credential.issue_rejected'").all();
    assert.equal(rejected.length, 4);
    assert.ok(rejected.every((row) => row.context_json === '{}'));
    assert.equal((await issuerAdmin.request('GET', '/api/credentials')).json.credentials[0].status, 'active');
  });
});

test('a valid proof is allowed once, keeps its issue-day cutoff across midnight, and replay is denied', async () => {
  await withSystem(async ({ clock, appDb, issuerAdmin, operator, appOrigin }) => {
    const file = await issue(issuerAdmin);
    const challenge = await requestChallenge(operator, file.credentialId);
    assert.equal(challenge.cutoff, '20081109');
    const { proof, publicSignals } = await prove(file, challenge);
    clock.now += 2 * 60_000;
    const submission = {
      version: '1', challengeId: challenge.challengeId, credential: publicCredential(file), proof, publicSignals,
      clientMeasurements: { proofGenerationMs: 950 },
    };
    const allowed = await operator.request('POST', '/api/verifications', submission);
    assert.equal(allowed.status, 200);
    assert.equal(allowed.json.decision, 'allow');
    assert.equal(allowed.json.reasonCode, 'PROOF_VALID');
    assert.equal(allowed.json.nonceStatus, 'fresh');
    assert.equal(allowed.json.proofGenerationMs, 950);
    assert.ok(allowed.json.proofSizeBytes > 0);
    assert.ok(Number.isInteger(allowed.json.verificationMs));
    assert.equal(stateOf(appDb, challenge.challengeId), 'used');

    const replay = await operator.request('POST', '/api/verifications', submission);
    assert.equal(replay.json.reasonCode, 'CHALLENGE_REPLAYED');
    assert.equal(replay.json.nonceStatus, 'replayed');
    assert.equal(replay.json.verificationMs, null);

    const viewer = browser(appOrigin);
    await viewer.login('viewer1', PASSWORD);
    const history = await viewer.request('GET', '/api/results');
    assert.deepEqual(history.json.results.map((result) => result.reasonCode), ['CHALLENGE_REPLAYED', 'PROOF_VALID']);
    assert.equal(Object.hasOwn(history.json.results[0], 'verificationMs'), false);

    const stored = JSON.stringify([
      appDb.prepare('SELECT * FROM verification_results').all(),
      appDb.prepare('SELECT * FROM audit_events').all(),
    ]);
    for (const secret of [file.commitment, file.signature, file.salt, BIRTH_DATE]) {
      assert.equal(stored.includes(secret), false);
    }
  }, { start: Date.UTC(2026, 10, 9, 23, 59) });
});

test('concurrent submissions of one challenge produce exactly one allow', async () => {
  await withSystem(async ({ appDb, issuerAdmin, operator }) => {
    const file = await issue(issuerAdmin);
    const challenge = await requestChallenge(operator, file.credentialId);
    const { proof, publicSignals } = await prove(file, challenge);
    const submission = { version: '1', challengeId: challenge.challengeId, credential: publicCredential(file), proof, publicSignals };
    const responses = await Promise.all([1, 2, 3].map(() => operator.request('POST', '/api/verifications', submission)));
    const codes = responses.map((response) => response.json.reasonCode).sort();
    assert.deepEqual(codes, ['CHALLENGE_REPLAYED', 'CHALLENGE_REPLAYED', 'PROOF_VALID']);
    assert.equal(appDb.prepare('SELECT COUNT(*) AS n FROM verification_results').get().n, 3);
  });
});

test('issuer outage fails closed with 503 and leaves the challenge retryable', async () => {
  await withSystem(async ({ clock, appDb, issuerAdmin, operator }) => {
    const file = await issue(issuerAdmin);
    const challenge = await requestChallenge(operator, file.credentialId);
    const { proof, publicSignals } = await prove(file, challenge);
    const submission = { version: '1', challengeId: challenge.challengeId, credential: publicCredential(file), proof, publicSignals };
    clock.issuerDown = true;
    const down = await operator.request('POST', '/api/verifications', submission);
    assert.equal(down.status, 503);
    assert.equal(down.json.reasonCode, 'ISSUER_UNAVAILABLE');
    assert.equal(stateOf(appDb, challenge.challengeId), 'issued');
    clock.issuerDown = false;
    const retry = await operator.request('POST', '/api/verifications', submission);
    assert.equal(retry.json.reasonCode, 'PROOF_VALID');
  });
});

test('definitive failures deny with a safe reason and consume the challenge', async () => {
  await withSystem(async ({ appDb, issuerAdmin, operator }) => {
    const file = await issue(issuerAdmin);
    const forgedId = randomBytes(16).toString('base64url');
    const fields = [forgedId, file.commitment, file.issuedAt, file.expiresAt, file.issuerName];
    const unknownFile = { ...file, credentialId: forgedId, signature: signCredentialFields(fields, signingKey).toString('base64url') };
    const cases = [
      ['SIGNALS_MISMATCH', file, (body) => { body.publicSignals[2] = '20081108'; }],
      ['SIGNATURE_INVALID', file, (body) => { body.credential.expiresAt = String(Number(file.expiresAt) + 1); }],
      ['CREDENTIAL_UNKNOWN', unknownFile, () => {}],
      ['PROOF_INVALID', file, () => {}],
    ];
    for (const [expected, credential, mutate] of cases) {
      const challenge = await requestChallenge(operator, credential.credentialId);
      const body = unprovenSubmission(credential, challenge);
      mutate(body);
      const response = await operator.request('POST', '/api/verifications', body);
      assert.equal(response.status, 200, expected);
      assert.equal(response.json.reasonCode, expected);
      assert.equal(response.json.decision, 'deny');
      assert.equal(stateOf(appDb, challenge.challengeId), 'used', expected);
    }
    assert.equal((await issuerAdmin.request('POST', `/api/credentials/${file.credentialId}/revoke`)).json.status, 'revoked');
    const challenge = await requestChallenge(operator, file.credentialId);
    const revoked = await operator.request('POST', '/api/verifications', unprovenSubmission(file, challenge));
    assert.equal(revoked.json.reasonCode, 'CREDENTIAL_REVOKED');
    assert.equal(stateOf(appDb, challenge.challengeId), 'used');
  });
});

test('early rejections are audited and leave the challenge unused', async () => {
  await withSystem(async ({ appDb, issuerAdmin, operator, appOrigin }) => {
    const file = await issue(issuerAdmin);
    const challenge = await requestChallenge(operator, file.credentialId);
    const valid = unprovenSubmission(file, challenge);

    const leaked = structuredClone(valid);
    leaked.credential.birthDate = BIRTH_DATE;
    assert.deepEqual((await operator.request('POST', '/api/verifications', leaked)).json, { code: 'PRIVATE_FIELD_SUBMITTED' });
    assert.deepEqual((await operator.request('POST', '/api/verifications', '{"version":"1","version":"1"}')).json,
      { code: 'MALFORMED_INPUT' });
    const otherCredential = { ...valid, credential: { ...valid.credential, credentialId: 'someone-else' } };
    assert.deepEqual((await operator.request('POST', '/api/verifications', otherCredential)).json, { code: 'CHALLENGE_NOT_FOUND' });

    const otherSession = browser(appOrigin);
    await otherSession.login('operator1', PASSWORD);
    assert.deepEqual((await otherSession.request('POST', '/api/verifications', valid)).json, { code: 'CHALLENGE_NOT_FOUND' });
    assert.deepEqual((await operator.request('POST', '/api/verifications', valid, { csrf: false })).json, { code: 'CSRF_INVALID' });

    assert.equal(stateOf(appDb, challenge.challengeId), 'issued');
    const rejected = appDb.prepare("SELECT code, context_json FROM audit_events WHERE type = 'verification.rejected'").all();
    assert.deepEqual(rejected.map((row) => row.code),
      ['PRIVATE_FIELD_SUBMITTED', 'MALFORMED_INPUT', 'CHALLENGE_NOT_FOUND', 'CHALLENGE_NOT_FOUND']);
    assert.ok(rejected.every((row) => !row.context_json.includes(BIRTH_DATE)));
  });
});

test('expired challenges and expired credentials are denied', async () => {
  await withSystem(async ({ clock, appDb, issuerAdmin, operator }) => {
    const file = await issue(issuerAdmin);
    const challenge = await requestChallenge(operator, file.credentialId);
    clock.now += 5 * 60_000;
    const late = await operator.request('POST', '/api/verifications', unprovenSubmission(file, challenge));
    assert.equal(late.json.reasonCode, 'CHALLENGE_EXPIRED');
    assert.equal(late.json.nonceStatus, 'expired');
    assert.equal(stateOf(appDb, challenge.challengeId), 'expired');

    clock.now += 91 * 24 * 60 * 60_000;
    await operator.login('operator1', PASSWORD);
    const fresh = await requestChallenge(operator, file.credentialId);
    const old = await operator.request('POST', '/api/verifications', unprovenSubmission(file, fresh));
    assert.equal(old.json.reasonCode, 'CREDENTIAL_EXPIRED');
    assert.equal(old.json.credentialExpiryStatus, 'expired');
    assert.equal(stateOf(appDb, fresh.challengeId), 'used');
  });
});

test('challenge issuance is rate limited and a crashed claim recovers on restart', async () => {
  await withSystem(async ({ appDb, operator }) => {
    for (let index = 0; index < 10; index++) await requestChallenge(operator, 'synthetic-1');
    assert.deepEqual((await operator.request('POST', '/api/challenges', { credentialId: 'synthetic-1' })).json,
      { code: 'RATE_LIMITED' });
    assert.deepEqual((await operator.request('POST', '/api/challenges', { credentialId: 'bad id' })).json,
      { code: 'MALFORMED_INPUT' });
    appDb.exec("UPDATE challenges SET state = 'verifying' WHERE rowid = 1");
    createApp({ db: appDb, identifierKey, trustedIssuerKey });
    assert.equal(appDb.prepare("SELECT COUNT(*) AS n FROM challenges WHERE state = 'verifying'").get().n, 0);
  });
});
