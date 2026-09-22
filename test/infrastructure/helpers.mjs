import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));
export const composeBase = [
  'compose',
  '--env-file',
  path.join(repositoryRoot, '.local', 'dev.env'),
  '--file',
  path.join(repositoryRoot, 'infra', 'compose.yaml'),
  '--project-name',
  'secure-document-access-system-local',
];

export function dockerCompose(args, options = {}) {
  const result = spawnSync('docker', [...composeBase, ...args], {
    cwd: repositoryRoot,
    encoding: 'utf8',
    stdio: options.capture === false ? 'inherit' : 'pipe',
    env: process.env,
    shell: false,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    const details = [result.stderr, result.stdout]
      .filter((stream) => typeof stream === 'string' && stream.trim().length > 0)
      .map((stream) => stream.trim())
      .join('\n');
    throw new Error(
      `Docker Compose failed (${args.join(' ')}): ${details || `exit code ${result.status}`}`,
    );
  }
  return result.stdout;
}

export async function waitFor(predicate, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const result = await predicate();
      if (result) return result;
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`Condition was not met within ${timeoutMs}ms.`, { cause: lastError });
}
