// Runtime and testable integrity verification for committed Groth16 artifacts.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
export const ARTIFACTS_DIR = path.join(ROOT, 'zk', 'artifacts');
export const CIRCUIT_PATH = path.join(ROOT, 'circuits', 'age18.circom');
export const MANIFEST_PATH = path.join(ARTIFACTS_DIR, 'manifest.json');

export function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function loadArtifactManifest(manifestPath = MANIFEST_PATH) {
  return JSON.parse(readFileSync(manifestPath, 'utf8'));
}

/** Verify the committed circuit and Groth16 artifacts match zk/artifacts/manifest.json. */
export function verifyCommittedArtifacts({
  manifestPath = MANIFEST_PATH,
  artifactsDir = ARTIFACTS_DIR,
  circuitPath = CIRCUIT_PATH,
} = {}) {
  const manifest = loadArtifactManifest(manifestPath);
  const circuitHash = sha256Hex(readFileSync(circuitPath));
  if (circuitHash !== manifest.circuitSha256) {
    throw new Error('Circuit hash does not match manifest.json');
  }
  const checked = {};
  for (const [name, expectedHash] of Object.entries(manifest.artifacts ?? {})) {
    const filePath = path.join(artifactsDir, name);
    const actualHash = sha256Hex(readFileSync(filePath));
    if (actualHash !== expectedHash) {
      throw new Error(`Artifact ${name} hash does not match manifest.json`);
    }
    checked[name] = actualHash;
  }
  return { manifest, checked };
}
