import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { buildDevelopmentEnvironment } from '../../scripts/generate-dev-secrets.mjs';

test('development secrets are complete, URL-safe, and unique per generation', () => {
  const first = buildDevelopmentEnvironment();
  const second = buildDevelopmentEnvironment();

  assert.notEqual(first, second);
  for (const name of [
    'POSTGRES_PASSWORD',
    'REDIS_PASSWORD',
    'MINIO_ROOT_PASSWORD',
    'GRAFANA_ADMIN_PASSWORD',
    'APP_ENCRYPTION_MASTER_KEY',
  ]) {
    assert.match(first, new RegExp(`^${name}=[A-Za-z0-9_-]{32,}$`, 'm'));
  }
  const generatedValues = first
    .split(/\r?\n/u)
    .filter((line) =>
      /^(?:POSTGRES_PASSWORD|REDIS_PASSWORD|MINIO_ROOT_PASSWORD|GRAFANA_ADMIN_PASSWORD)=/u.test(
        line,
      ),
    )
    .map((line) => line.slice(line.indexOf('=') + 1));
  for (const value of generatedValues) assert.doesNotMatch(value, /[+/]/u);
});

test('secret generator uses the Node cryptographic RNG and never Math.random', async () => {
  const source = await readFile(
    new URL('../../scripts/generate-dev-secrets.mjs', import.meta.url),
    'utf8',
  );
  assert.match(source, /randomBytes/u);
  assert.doesNotMatch(source, /Math\.random/u);
});
