import { defineConfig, devices } from '@playwright/test';
import { fileURLToPath } from 'node:url';

const repositoryRoot = fileURLToPath(new URL('./', import.meta.url));
const webPort = parsePort(process.env['E2E_WEB_PORT'], 3100);
const apiPort = parsePort(process.env['E2E_API_PORT'], 3101);
const webUrl = `http://127.0.0.1:${webPort}`;
const apiUrl = `http://127.0.0.1:${apiPort}`;

function parsePort(value: string | undefined, fallback: number): number {
  const port = value === undefined ? fallback : Number(value);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) {
    throw new Error('E2E port must be an integer between 1024 and 65535');
  }
  return port;
}

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: Boolean(process.env['CI']),
  retries: 0,
  workers: 1,
  reporter: 'list',
  use: { baseURL: webUrl, trace: 'retain-on-failure' },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: [
    {
      command: `pnpm --filter @sda/web exec next start -H 127.0.0.1 -p ${webPort}`,
      cwd: repositoryRoot,
      url: webUrl,
      timeout: 60_000,
      reuseExistingServer: false,
      env: { NODE_ENV: 'production', NEXT_TELEMETRY_DISABLED: '1' },
    },
    {
      command: 'node --env-file-if-exists=.local/dev.env apps/api/dist/main.js',
      cwd: repositoryRoot,
      url: `${apiUrl}/api/v1/health/live`,
      timeout: 60_000,
      reuseExistingServer: false,
      env: { NODE_ENV: 'test', PORT: String(apiPort), HOST: '127.0.0.1' },
    },
  ],
});
