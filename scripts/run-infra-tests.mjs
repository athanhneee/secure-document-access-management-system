import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const repositoryRoot = fileURLToPath(new URL('../', import.meta.url));
const environmentPath = path.join(repositoryRoot, '.local', 'dev.env');

function parseEnvironment(source) {
  return Object.fromEntries(
    source
      .split(/\r?\n/u)
      .filter((line) => line && !line.startsWith('#'))
      .map((line) => {
        const separator = line.indexOf('=');
        if (separator < 1) throw new Error('Invalid line in local environment file.');
        return [line.slice(0, separator), line.slice(separator + 1)];
      }),
  );
}

let localEnvironment = {};
try {
  localEnvironment = parseEnvironment(await readFile(environmentPath, 'utf8'));
} catch (error) {
  if (process.env['CI'] !== 'true') {
    throw new Error('Missing .local/dev.env. Run pnpm infra:up before infrastructure tests.', {
      cause: error,
    });
  }
}

const build = spawnSync(
  process.execPath,
  [
    path.join(repositoryRoot, 'node_modules', 'turbo', 'bin', 'turbo'),
    'run',
    'build',
    '--filter=@sda/api',
  ],
  {
    cwd: repositoryRoot,
    env: process.env,
    stdio: 'inherit',
    shell: false,
  },
);
if (build.error) throw build.error;
if (build.status !== 0) process.exit(build.status ?? 1);

const result = spawnSync(
  process.execPath,
  [
    '--test',
    '--test-concurrency=1',
    'test/infrastructure/object-storage.test.mjs',
    'test/infrastructure/clamav.test.mjs',
    'test/infrastructure/readiness.test.mjs',
  ],
  {
    cwd: repositoryRoot,
    env: { ...process.env, ...localEnvironment, RUN_INFRA_TESTS: '1' },
    stdio: 'inherit',
    shell: false,
  },
);

if (result.error) throw result.error;
process.exitCode = result.status ?? 1;
