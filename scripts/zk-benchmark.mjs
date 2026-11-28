// Repeatable synthetic benchmark for Groth16 proof generation time, verification time, and proof JSON size.
import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import { groth16 } from 'snarkjs';
import { closeProofEngine, ENGINE_VERSION, verifyAgeProof } from '../src/app/proof-engine.mjs';
import { challengeHashFromNonce } from '../src/zk/challenge-hash.mjs';
import { credentialCommitment } from '../src/zk/poseidon.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const wasmPath = path.join(root, 'zk', 'artifacts', 'age18.wasm');
const zkeyPath = path.join(root, 'zk', 'artifacts', 'age18_final.zkey');
const defaultOutPath = path.join(root, 'docs', 'benchmarks', 'zk-benchmark-results.json');

function parseNumberFlag(name, fallback) {
  const prefix = `--${name}=`;
  const arg = process.argv.find((entry) => entry.startsWith(prefix));
  if (!arg) return fallback;
  const parsed = Number(arg.slice(prefix.length));
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new RangeError(`Invalid --${name} value`);
  }
  return parsed;
}

function summarize(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const sum = sorted.reduce((acc, value) => acc + value, 0);
  const mid = Math.floor(sorted.length / 2);
  const median = sorted.length % 2 === 0
    ? (sorted[mid - 1] + sorted[mid]) / 2
    : sorted[mid];
  return {
    min: Number(sorted[0].toFixed(2)),
    median: Number(median.toFixed(2)),
    mean: Number((sum / sorted.length).toFixed(2)),
    max: Number(sorted[sorted.length - 1].toFixed(2)),
  };
}

async function runSingle(index) {
  const nonce = Buffer.alloc(32, (index % 250) + 1);
  const challengeHash = challengeHashFromNonce(nonce);
  const birthDate = '20081109';
  const salt = String(100000000 + index);
  const commitment = credentialCommitment(birthDate, salt);
  const input = {
    birthDate,
    salt,
    commitment,
    cutoff: '20081109',
    challengeHash,
  };

  const proveStart = performance.now();
  const { proof, publicSignals } = await groth16.fullProve(input, wasmPath, zkeyPath, undefined, undefined, { singleThread: true });
  const proofGenerationMs = Number((performance.now() - proveStart).toFixed(2));

  const verifyStart = performance.now();
  const verified = await verifyAgeProof(publicSignals, proof);
  const verificationMs = Number((performance.now() - verifyStart).toFixed(2));
  assert.equal(verified, true, 'Benchmark proof must verify');

  const proofSizeBytes = Buffer.byteLength(JSON.stringify(proof), 'utf8');
  const publicSignalsSizeBytes = Buffer.byteLength(JSON.stringify(publicSignals), 'utf8');
  return { proofGenerationMs, verificationMs, proofSizeBytes, publicSignalsSizeBytes };
}

async function main() {
  const warmupCount = parseNumberFlag('warmup', 2);
  const sampleCount = parseNumberFlag('samples', 10);
  if (sampleCount < 1) throw new RangeError('samples must be at least 1');

  const packageJson = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  const cpus = os.cpus();

  for (let i = 0; i < warmupCount; i++) {
    await runSingle(i);
  }

  const samples = [];
  for (let i = 0; i < sampleCount; i++) {
    const measurement = await runSingle(warmupCount + i);
    samples.push({ sample: i + 1, ...measurement });
  }

  const report = {
    generatedAtUtc: new Date().toISOString(),
    engineVersion: ENGINE_VERSION,
    snarkjsVersion: packageJson.dependencies?.snarkjs ?? 'unknown',
    environment: {
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch,
      cpuModel: cpus[0]?.model ?? 'unknown',
      cpuCount: cpus.length,
      totalMemoryMB: Math.round(os.totalmem() / (1024 * 1024)),
    },
    methodology: {
      fixtureType: 'synthetic',
      warmupRuns: warmupCount,
      sampleCount,
      singleThreadProver: true,
    },
    summary: {
      proofGenerationMs: summarize(samples.map((s) => s.proofGenerationMs)),
      verificationMs: summarize(samples.map((s) => s.verificationMs)),
      proofSizeBytes: summarize(samples.map((s) => s.proofSizeBytes)),
      publicSignalsSizeBytes: summarize(samples.map((s) => s.publicSignalsSizeBytes)),
    },
    samples,
  };

  if (process.argv.includes('--write')) {
    await mkdir(path.dirname(defaultOutPath), { recursive: true });
    await writeFile(defaultOutPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  }

  console.log(JSON.stringify(report, null, 2));
}

try {
  await main();
  await closeProofEngine();
  process.exit(0);
} catch (error) {
  console.error(error);
  await closeProofEngine();
  process.exit(1);
}
