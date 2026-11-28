// Focused tests for B3: static asset allowlist, artifact manifest integrity, browser proof workflow, CSRF, and outcomes.
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import test from 'node:test';
import { groth16 } from 'snarkjs';
import { checkIssuerStatus } from '../src/app/issuer-status-client.mjs';
import { closeProofEngine } from '../src/app/proof-engine.mjs';
import {
  buildProofWitness,
  buildVerificationSubmission,
  formatVerificationOutcome,
  loadVerifiedArtifacts,
  PUBLIC_SIGNAL_ORDER,
  runBrowserProofWorkflow,
} from '../src/app/public/prover-client.mjs';
import { createApp } from '../src/app/server.mjs';
import { birthDateNumberForProof, parsePrivateCredentialJson } from '../src/credential-json.mjs';
import { openServiceDatabase } from '../src/db/service-database.mjs';
import { createIssuer } from '../src/issuer/server.mjs';
import { verifyCommittedArtifacts } from '../src/zk/artifacts.mjs';
import { addAccount, browser, withServer } from './http-helpers.mjs';

const identifierKey = randomBytes(32);
const serviceToken = randomBytes(32).toString('base64url');
const { privateKey: signingKey, publicKey: trustedIssuerKey } = generateKeyPairSync('ed25519');
const PASSWORD = 'synthetic-demo-password';
const BIRTH_DATE = '2008-11-09';
const SALT = '987654321';

test.after(closeProofEngine);

test('committed Groth16 artifacts match zk/artifacts/manifest.json', () => {
  const { manifest, checked } = verifyCommittedArtifacts();
  assert.equal(manifest.ceremony, 'local single-party demo');
  assert.deepEqual(Object.keys(checked).sort(), ['age18.wasm', 'age18_final.zkey', 'verification_key.json']);
});

test('app serves allowlisted browser/ZK assets with exact hashes and blocks sensitive paths', async () => {
  const app = createApp();
  await withServer(app, async (appOrigin) => {
    const allowed = [
      ['/', 'text/html'],
      ['/app.js', 'text/javascript'],
      ['/prover-client.mjs', 'text/javascript'],
      ['/vendor/snarkjs.min.js', 'text/javascript'],
      ['/shared/credential-json.mjs', 'text/javascript'],
      ['/zk/manifest.json', 'application/json'],
      ['/zk/age18.wasm', 'application/wasm'],
      ['/zk/age18_final.zkey', 'application/octet-stream'],
    ];
    for (const [route, expectedType] of allowed) {
      const response = await fetch(`${appOrigin}${route}`);
      assert.equal(response.status, 200, route);
      assert.ok(response.headers.get('content-type')?.includes(expectedType), route);
      assert.equal(response.headers.get('x-content-type-options'), 'nosniff', route);
    }

    const manifest = await (await fetch(`${appOrigin}/zk/manifest.json`)).json();
    const wasmBytes = Buffer.from(await (await fetch(`${appOrigin}/zk/age18.wasm`)).arrayBuffer());
    const zkeyBytes = Buffer.from(await (await fetch(`${appOrigin}/zk/age18_final.zkey`)).arrayBuffer());
    assert.equal(createHash('sha256').update(wasmBytes).digest('hex'), manifest.artifacts['age18.wasm']);
    assert.equal(createHash('sha256').update(zkeyBytes).digest('hex'), manifest.artifacts['age18_final.zkey']);

    const blocked = [
      '/.local/app/config.json',
      '/.local/app/app.sqlite',
      '/.local/issuer/signing-private.pem',
      '/src/app/server.mjs',
      '/zk/artifacts/verification_key.json',
      '/package.json',
      '/../package.json',
    ];
    for (const route of blocked) {
      const response = await fetch(`${appOrigin}${route}`);
      assert.equal(response.status, 404, route);
      assert.deepEqual(await response.json(), { code: 'NOT_FOUND' }, route);
    }
  });
});

test('browser submission excludes birthDate and salt and preserves publicSignals order', () => {
  assert.deepEqual(PUBLIC_SIGNAL_ORDER, ['requestTag', 'commitment', 'cutoff', 'challengeHash']);
  const credential = parsePrivateCredentialJson(JSON.stringify({
    version: '1',
    credentialId: 'synthetic-b3',
    birthDate: BIRTH_DATE,
    salt: SALT,
    commitment: '123456',
    issuedAt: '1794268800',
    expiresAt: '1802044800',
    issuerName: 'ZK Access Demo Issuer',
    signature: Buffer.alloc(64, 0x33).toString('base64url'),
  }));
  const witness = buildProofWitness(credential, { cutoff: '20081109', challengeHash: '77' }, birthDateNumberForProof);
  assert.equal(witness.birthDate, '20081109');
  assert.equal(witness.salt, SALT);

  const submission = buildVerificationSubmission({
    challengeId: 'ch-1',
    credential,
    proof: { pi_a: ['1', '2', '1'], pi_b: [['3', '4'], ['5', '6'], ['1', '0']], pi_c: ['7', '8', '1'], protocol: 'groth16', curve: 'bn128' },
    publicSignals: ['999', '123456', '20081109', '77'],
    proofGenerationMs: 420,
  });
  const serialized = JSON.stringify(submission);
  assert.equal(serialized.includes('birthDate'), false);
  assert.equal(serialized.includes('salt'), false);
  assert.equal(serialized.includes(BIRTH_DATE), false);
  assert.equal(serialized.includes(SALT), false);
  assert.deepEqual(Object.keys(submission.credential), ['credentialId', 'commitment', 'issuedAt', 'expiresAt', 'issuerName', 'signature']);
  assert.deepEqual(submission.publicSignals, ['999', '123456', '20081109', '77']);
});

test('browser proof workflow integrates end-to-end with CSRF, artifact verification, and safe outcomes', async () => {
  const clock = { now: Date.UTC(2026, 10, 9, 12), issuerDown: false };
  const now = () => clock.now;
  const issuerDb = openServiceDatabase('issuer', { file: ':memory:' });
  const appDb = openServiceDatabase('app', { file: ':memory:' });
  await addAccount(issuerDb, 'issuer-admin-1', 'issuer1', PASSWORD, 'issuer_admin');
  await addAccount(appDb, 'operator-1', 'operator1', PASSWORD, 'operator');

  await withServer(createIssuer({ db: issuerDb, identifierKey, signingKey, serviceToken, now }), async (issuerOrigin) => {
    const checkStatus = (credential) => (clock.issuerDown ? 'unavailable' :
      checkIssuerStatus(credential, { serviceToken, issuerOrigin }));
    const app = createApp({ db: appDb, identifierKey, trustedIssuerKey, checkStatus, now });
    await withServer(app, async (appOrigin) => {
      const issuerAdmin = browser(issuerOrigin);
      await issuerAdmin.login('issuer1', PASSWORD);
      const issued = await issuerAdmin.request('POST', '/api/credentials', { version: '1', birthDate: BIRTH_DATE, salt: SALT });
      assert.equal(issued.status, 201);
      const credential = parsePrivateCredentialJson(JSON.stringify(issued.json));

      const operator = browser(appOrigin);
      await operator.login('operator1', PASSWORD);
      assert.ok(operator.csrfToken);

      // Browser-like fetch using the operator's session cookie
      const browserFetch = async (urlPath, init = {}) => {
        const target = urlPath.startsWith('http') ? urlPath : `${appOrigin}${urlPath}`;
        const headers = new Headers(init.headers ?? {});
        if (operator.cookie) headers.set('cookie', operator.cookie);
        return fetch(target, { ...init, headers });
      };

      const artifacts = await loadVerifiedArtifacts({ fetchImpl: browserFetch });
      const prover = {
        fullProve: (input, wasm, zkey) => groth16.fullProve(input, wasm, zkey, undefined, undefined, { singleThread: true }),
      };

      // 1. Valid workflow
      const validRun = await runBrowserProofWorkflow({
        credential,
        csrfToken: operator.csrfToken,
        encodeBirthDateNumber: birthDateNumberForProof,
        fetchImpl: browserFetch,
        groth16: prover,
        artifacts,
      });
      assert.equal(validRun.responseStatus, 200);
      assert.equal(validRun.outcome.ok, true);
      assert.equal(validRun.outcome.reasonCode, 'PROOF_VALID');
      assert.equal(JSON.stringify(validRun.submission).includes('birthDate'), false);
      assert.equal(JSON.stringify(validRun.submission).includes('salt'), false);

      // 2. Replay of the same submission
      const replayRes = await browserFetch('/api/verifications', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': operator.csrfToken },
        body: JSON.stringify(validRun.submission),
      });
      const replayOutcome = formatVerificationOutcome(replayRes.status, await replayRes.json());
      assert.equal(replayOutcome.category, 'replayed');
      assert.equal(replayOutcome.reasonCode, 'CHALLENGE_REPLAYED');

      // 3. Missing CSRF token on write
      const noCsrf = await runBrowserProofWorkflow({
        credential,
        csrfToken: '',
        encodeBirthDateNumber: birthDateNumberForProof,
        fetchImpl: browserFetch,
        groth16: prover,
        artifacts,
      });
      assert.equal(noCsrf.responseStatus, 403);
      assert.equal(noCsrf.outcome.code, 'CSRF_INVALID');

      // 4. Issuer unavailable outcome
      clock.issuerDown = true;
      const downRun = await runBrowserProofWorkflow({
        credential,
        csrfToken: operator.csrfToken,
        encodeBirthDateNumber: birthDateNumberForProof,
        fetchImpl: browserFetch,
        groth16: prover,
        artifacts,
      });
      assert.equal(downRun.responseStatus, 503);
      assert.equal(downRun.outcome.category, 'unavailable');
      assert.equal(downRun.outcome.reasonCode, 'ISSUER_UNAVAILABLE');
      clock.issuerDown = false;

      // 5. Expired challenge outcome
      const chRes = await operator.request('POST', '/api/challenges', { credentialId: credential.credentialId });
      const { proof, publicSignals } = await prover.fullProve(
        buildProofWitness(credential, chRes.json, birthDateNumberForProof),
        artifacts.wasmBytes,
        artifacts.zkeyBytes,
      );
      clock.now += 5 * 60_000;
      const expRes = await browserFetch('/api/verifications', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': operator.csrfToken },
        body: JSON.stringify(buildVerificationSubmission({
          challengeId: chRes.json.challengeId,
          credential,
          proof,
          publicSignals,
        })),
      });
      const expOutcome = formatVerificationOutcome(expRes.status, await expRes.json());
      assert.equal(expOutcome.category, 'expired');
      assert.equal(expOutcome.reasonCode, 'CHALLENGE_EXPIRED');

      // 6. Malformed / invalid outcomes map cleanly without leaking private data
      const malformedOutcome = formatVerificationOutcome(400, { code: 'MALFORMED_INPUT' });
      assert.equal(malformedOutcome.category, 'malformed');
      const invalidOutcome = formatVerificationOutcome(200, { reasonCode: 'PROOF_INVALID' });
      assert.equal(invalidOutcome.category, 'invalid');
    });
  });
});
