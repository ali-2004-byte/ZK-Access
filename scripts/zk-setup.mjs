import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { access, chmod, copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const circuit = path.join(root, 'circuits', 'age18.circom');
const build = path.join(root, 'zk', 'build');
const artifacts = path.join(root, 'zk', 'artifacts');
const tools = path.join(root, 'tools');
const snarkjs = path.join(root, 'node_modules', 'snarkjs', 'build', 'cli.cjs');
const compilerVersion = '2.2.3';
const snarkjsVersion = '0.7.6';
const circomlibVersion = '2.0.5';
const artifactNames = ['age18_final.zkey', 'age18.wasm', 'verification_key.json'];
const compilerAssets = {
  'win32-x64': ['circom-windows-amd64.exe', 'e43f132ee6f0aa79b705beceb59c2a7e6a54d7bdeab917ca34e9fc1951d185e1'],
  'linux-x64': ['circom-linux-amd64', '85342c7ff332d948df7c0c50ecf201e6129349aef550ce873f3c811b79fe53a3'],
  'darwin-x64': ['circom-macos-amd64', 'e006332b3fe225f11c3b87bd2debbf5d7f568d6efbde25e5a6a12cd6988c8ecb'],
};

async function sha256(file) {
  return createHash('sha256').update(await readFile(file)).digest('hex');
}

async function exists(file) {
  try {
    await access(file);
    return true;
  } catch {
    return false;
  }
}

async function compilerPath() {
  const asset = compilerAssets[`${process.platform}-${process.arch}`];
  if (!asset) throw new Error(`No pinned Circom binary for ${process.platform}-${process.arch}; install official Circom ${compilerVersion} manually`);
  const [name, expectedHash] = asset;
  const file = path.join(tools, name);
  await mkdir(tools, { recursive: true });
  if (!(await exists(file))) {
    const url = `https://github.com/iden3/circom/releases/download/v${compilerVersion}/${name}`;
    console.log(`Downloading official Circom ${compilerVersion} from ${url}`);
    const response = await fetch(url);
    if (!response.ok) throw new Error(`Circom download failed: HTTP ${response.status}`);
    const bytes = Buffer.from(await response.arrayBuffer());
    const actualHash = createHash('sha256').update(bytes).digest('hex');
    if (actualHash !== expectedHash) throw new Error('Circom download checksum mismatch');
    await writeFile(file, bytes);
  }
  if ((await sha256(file)) !== expectedHash) throw new Error('Circom compiler checksum mismatch');
  if (process.platform !== 'win32') await chmod(file, 0o755);
  return file;
}

function run(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: root, stdio: 'inherit', windowsHide: true });
    child.once('error', reject);
    child.once('exit', (code) => code === 0 ? resolve() : reject(new Error(`${path.basename(command)} exited with ${code}`)));
  });
}

function snark(args) {
  return run(process.execPath, [snarkjs, ...args]);
}

const circuitHash = await sha256(circuit);
const packageJson = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
if (packageJson.dependencies?.snarkjs !== snarkjsVersion || packageJson.dependencies?.circomlib !== circomlibVersion) {
  throw new Error('Groth16 package versions differ from pinned setup versions');
}
const manifestPath = path.join(artifacts, 'manifest.json');
if (await exists(manifestPath) && !process.argv.includes('--force')) {
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  if (manifest.circuitSha256 !== circuitHash) throw new Error('Circuit changed; review it, then run npm run zk:setup -- --force');
  if (manifest.compiler !== `circom ${compilerVersion}` || manifest.snarkjs !== snarkjsVersion || manifest.circomlib !== circomlibVersion) {
    throw new Error('Artifact tool versions differ from pinned setup versions');
  }
  for (const name of artifactNames) {
    if ((await sha256(path.join(artifacts, name))) !== manifest.artifacts?.[name]) throw new Error(`Artifact mismatch: ${name}`);
  }
  console.log('Existing Groth16 artifacts match this circuit; setup skipped.');
  process.exit(0);
}

await mkdir(build, { recursive: true });
await mkdir(artifacts, { recursive: true });
const circom = await compilerPath();
await run(circom, [circuit, '--r1cs', '--wasm', '--sym', '-l', path.join(root, 'node_modules'), '-o', build]);

const pot0 = path.join(build, 'pot12_0000.ptau');
const pot1 = path.join(build, 'pot12_0001.ptau');
const potFinal = path.join(build, 'pot12_final.ptau');
const zkey0 = path.join(build, 'age18_0000.zkey');
const zkeyFinal = path.join(artifacts, 'age18_final.zkey');
const verificationKey = path.join(artifacts, 'verification_key.json');
const wasm = path.join(artifacts, 'age18.wasm');

await snark(['powersoftau', 'new', 'bn128', '12', pot0]);
await snark(['powersoftau', 'contribute', pot0, pot1, '--name=Local demo phase 1', `-e=${randomBytes(32).toString('hex')}`]);
await snark(['powersoftau', 'prepare', 'phase2', pot1, potFinal]);
await snark(['groth16', 'setup', path.join(build, 'age18.r1cs'), potFinal, zkey0]);
await snark(['zkey', 'contribute', zkey0, zkeyFinal, '--name=Local demo phase 2', `-e=${randomBytes(32).toString('hex')}`]);
await snark(['zkey', 'verify', path.join(build, 'age18.r1cs'), potFinal, zkeyFinal]);
await snark(['zkey', 'export', 'verificationkey', zkeyFinal, verificationKey]);
await copyFile(path.join(build, 'age18_js', 'age18.wasm'), wasm);

const artifactHashes = Object.fromEntries(await Promise.all(artifactNames.map(async (name) => [name, await sha256(path.join(artifacts, name))])));
await writeFile(manifestPath, JSON.stringify({
  circuitSha256: circuitHash,
  compiler: `circom ${compilerVersion}`,
  snarkjs: snarkjsVersion,
  circomlib: circomlibVersion,
  ceremony: 'local single-party demo',
  artifacts: artifactHashes,
}, null, 2) + '\n');
console.log('Groth16 artifacts generated and verified in zk/artifacts.');
