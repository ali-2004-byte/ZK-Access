import process from 'node:process';
import { createInterface, emitKeypressEvents } from 'node:readline';
import { bootstrapAdmins, existingAdmin } from '../src/auth/bootstrap.mjs';
import { normalizeUsername } from '../src/auth/username.mjs';
import { openAccountDatabase } from '../src/db/account-store.mjs';

function hiddenQuestion(label) {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error('Admin setup requires an interactive terminal');
  }
  emitKeypressEvents(process.stdin);
  process.stdout.write(label);
  return new Promise((resolve, reject) => {
    let value = '';
    const previousRaw = process.stdin.isRaw === true;
    const finish = (error) => {
      process.stdin.off('keypress', onKeypress);
      process.stdin.setRawMode(previousRaw);
      process.stdin.pause();
      process.stdout.write('\n');
      if (error) reject(error);
      else resolve(value);
    };
    const onKeypress = (character, key) => {
      if (key.ctrl && key.name === 'c') return finish(new Error('Admin setup interrupted'));
      if (key.name === 'return' || key.name === 'enter') return finish();
      if (key.name === 'backspace') {
        if (value.length > 0) {
          value = [...value].slice(0, -1).join('');
          process.stdout.write('\b \b');
        }
        return;
      }
      if (!character || key.ctrl || key.meta || key.name === 'escape') return;
      const printable = [...character].filter((part) => part.codePointAt(0) >= 32 && part.codePointAt(0) !== 127);
      value += printable.join('');
      process.stdout.write('*'.repeat(printable.length));
    };
    process.stdin.on('keypress', onKeypress);
    process.stdin.setRawMode(true);
    process.stdin.resume();
  });
}

async function newPassword(serviceName) {
  while (true) {
    const password = await hiddenQuestion(`${serviceName} admin password: `);
    if ([...password].length < 12) {
      process.stdout.write('Use at least 12 characters.\n');
      continue;
    }
    const confirmation = await hiddenQuestion(`Confirm ${serviceName} password: `);
    if (confirmation === password) return password;
    process.stdout.write('Passwords did not match; try again.\n');
  }
}

async function main() {
  const appDb = openAccountDatabase('app');
  const issuerDb = openAccountDatabase('issuer');
  try {
    const appExisting = existingAdmin(appDb, 'admin');
    const issuerExisting = existingAdmin(issuerDb, 'issuer_admin');
    if (appExisting && issuerExisting) {
      process.stdout.write('Both admin accounts already exist; no account was changed.\n');
      return;
    }
    if (!process.stdin.isTTY || !process.stdout.isTTY) {
      throw new Error('Admin setup requires an interactive terminal');
    }
    const terminal = createInterface({ input: process.stdin, output: process.stdout });
    let appUsername;
    let issuerUsername;
    try {
      appUsername = appExisting?.username_normalized ?? await terminal.question('App admin username: ');
      issuerUsername = issuerExisting?.username_normalized ?? await terminal.question('Issuer admin username: ');
    } finally {
      terminal.close();
    }
    const appNormalized = normalizeUsername(appUsername);
    const issuerNormalized = normalizeUsername(issuerUsername);
    if (appNormalized === issuerNormalized) throw new Error('The two admin usernames must differ after normalization');

    const appAdmin = appExisting ? null : { username: appUsername, password: await newPassword('App') };
    const issuerAdmin = issuerExisting ? null : { username: issuerUsername, password: await newPassword('Issuer') };
    const result = await bootstrapAdmins({ appDb, issuerDb, appAdmin, issuerAdmin });
    process.stdout.write(`Admin setup complete: ${Number(result.appCreated) + Number(result.issuerCreated)} account(s) created.\n`);
  } finally {
    appDb.close();
    issuerDb.close();
  }
}

try {
  await main();
} catch (error) {
  process.stderr.write(`Admin setup failed: ${error.message}\n`);
  process.exitCode = 1;
}
