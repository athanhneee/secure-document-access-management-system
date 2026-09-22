import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { after, before, test } from 'node:test';
import { dockerCompose, repositoryRoot, waitFor } from './helpers.mjs';

const port = 3199;
const readinessUrl = `http://127.0.0.1:${port}/api/v1/health/ready`;
let api;

async function readiness() {
  const response = await fetch(readinessUrl, { signal: AbortSignal.timeout(5_000) });
  const body = await response.json();
  return { response, body };
}

before(async () => {
  api = spawn(process.execPath, ['apps/api/dist/main.js'], {
    cwd: repositoryRoot,
    env: { ...process.env, HOST: '127.0.0.1', PORT: String(port), NODE_ENV: 'development' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  await waitFor(async () => {
    const result = await readiness();
    return result.response.status === 200 && result.body.status === 'ready';
  }, 30_000);
});

after(() => {
  dockerCompose(['start', 'redis'], { capture: false });
  api?.kill();
});

test('API readiness becomes degraded when a required dependency stops and recovers afterward', async () => {
  dockerCompose(['stop', '--timeout', '10', 'redis'], { capture: false });
  const degraded = await waitFor(async () => {
    const result = await readiness();
    return result.response.status === 503 ? result : undefined;
  });
  assert.equal(degraded.body.status, 'degraded');
  assert.equal(degraded.body.checks.redis.status, 'down');
  assert.doesNotMatch(JSON.stringify(degraded.body), /password|secret|credential|redis:\/\//i);

  dockerCompose(['start', 'redis'], { capture: false });
  const recovered = await waitFor(async () => {
    const result = await readiness();
    return result.response.status === 200 ? result : undefined;
  });
  assert.equal(recovered.body.status, 'ready');
});
