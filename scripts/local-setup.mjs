import { generateKeyPairSync, randomBytes, createPrivateKey, createPublicKey } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const issuerDir = path.join(root, '.local', 'issuer');
const appDir = path.join(root, '.local', 'app');
const privatePath = path.join(issuerDir, 'signing-private.pem');
const publicPath = path.join(appDir, 'trusted-issuer-public.pem');
const issuerTokenPath = path.join(issuerDir, 'service-token');
const appTokenPath = path.join(appDir, 'issuer-service-token');

async function readOptional(file) {
  try {
    return await readFile(file, 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

async function writeNew(file, value) {
  await writeFile(file, value, { flag: 'wx', mode: 0o600 });
}

await mkdir(issuerDir, { recursive: true, mode: 0o700 });
await mkdir(appDir, { recursive: true, mode: 0o700 });

let privatePem = await readOptional(privatePath);
const publicPem = await readOptional(publicPath);
if (privatePem === null) {
  if (publicPem !== null) throw new Error('App trusts an issuer key but the issuer private key is missing; refusing key rotation');
  const pair = generateKeyPairSync('ed25519');
  privatePem = pair.privateKey.export({ format: 'pem', type: 'pkcs8' });
  await writeNew(privatePath, privatePem);
}
const privateKey = createPrivateKey(privatePem);
if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('Issuer signing key is not Ed25519');
const expectedPublic = createPublicKey(privateKey).export({ format: 'pem', type: 'spki' });
if (publicPem === null) await writeNew(publicPath, expectedPublic);
else if (publicPem !== expectedPublic) throw new Error('App trusted issuer public key does not match issuer private key');

let issuerToken = await readOptional(issuerTokenPath);
const appToken = await readOptional(appTokenPath);
if (issuerToken === null) {
  if (appToken !== null) throw new Error('App service token exists but issuer token is missing; refusing token replacement');
  issuerToken = randomBytes(32).toString('base64url');
  await writeNew(issuerTokenPath, issuerToken);
}
if (!/^[A-Za-z0-9_-]{43}$/.test(issuerToken)) throw new Error('Issuer service token is malformed');
if (appToken === null) await writeNew(appTokenPath, issuerToken);
else if (appToken !== issuerToken) throw new Error('App and issuer service tokens differ');

console.log('Local issuer key and app/issuer service credentials are ready. Existing secrets were preserved.');
