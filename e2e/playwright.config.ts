import { defineConfig, devices } from '@playwright/test';
import { fileURLToPath } from 'node:url';

const repositoryRoot = fileURLToPath(new URL('../', import.meta.url));
const webDistDir = process.env['NEXT_DIST_DIR']?.trim() || '.next';
const webPort = parsePort(process.env['E2E_WEB_PORT'], 3100);
const apiPort = parsePort(process.env['E2E_API_PORT'], 3101);
const webUrl = `http://127.0.0.1:${webPort}`;
const apiUrl = `http://127.0.0.1:${apiPort}`;
const API_BASE = apiUrl;

function parsePort(value: string | undefined, fallback: number): number {
  const port = value === undefined ? fallback : Number(value);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) {
    throw new Error('E2E port must be an integer between 1024 and 65535');
  }
  return port;
}

export default defineConfig({
  testDir: './',
  fullyParallel: true,
  forbidOnly: Boolean(process.env['CI']),
  retries: 0,
  workers: 1,
  reporter: 'list',
  use: { baseURL: webUrl, trace: 'retain-on-failure' },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    {
      name: 'mobile-375',
      use: {
        ...devices['Desktop Chrome'],
        viewport: { width: 375, height: 667 },
        isMobile: true,
        hasTouch: true,
      },
    },
  ],
  webServer: [
    {
      command: `node apps/web/${webDistDir}/standalone/apps/web/server.js`,
      cwd: repositoryRoot,
      url: webUrl,
      timeout: 60_000,
      reuseExistingServer: false,
      env: {
        NODE_ENV: 'production',
        HOSTNAME: '127.0.0.1',
        PORT: String(webPort),
        NEXT_TELEMETRY_DISABLED: '1',
        INTERNAL_API_ORIGIN: API_BASE,
        NEXT_PUBLIC_API_BASE_URL: '/api/v1',
        CSP_CONNECT_ORIGINS: API_BASE,
      },
    },
    {
      command:
        'node --env-file-if-exists=.env --env-file-if-exists=.local/dev.env apps/api/dist/main.js',
      cwd: repositoryRoot,
      url: `${apiUrl}/api/v1/health/live`,
      timeout: 60_000,
      reuseExistingServer: false,
      env: {
        NODE_ENV: 'test',
        PORT: String(apiPort),
        API_PORT: String(apiPort),
        HOST: '127.0.0.1',
        API_HOST: '127.0.0.1',
        CORS_ALLOWED_ORIGINS: `${webUrl},http://localhost:${webPort}`,
        WEBAUTHN_ORIGINS: `${webUrl},http://localhost:${webPort}`,
        PASSWORD_RESET_BASE_URL: `${webUrl}/reset-password`,
      },
    },
  ],
});
