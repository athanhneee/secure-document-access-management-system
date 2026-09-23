import fs from 'node:fs';
import path from 'node:path';
import { createApplication } from './application.js';

if (!process.env['DATABASE_URL']) {
  const candidatePaths = [
    path.resolve(process.cwd(), '.local/dev.env'),
    path.resolve(process.cwd(), '../../.local/dev.env'),
    path.resolve(import.meta.dirname, '../../../../.local/dev.env'),
  ];
  for (const candidate of candidatePaths) {
    if (fs.existsSync(candidate)) {
      try {
        process.loadEnvFile(candidate);
        break;
      } catch {
        // Continue checking next candidate
      }
    }
  }
}

async function main(): Promise<void> {
  const rawPort = process.env['PORT'] ?? '3001';
  const port = Number(rawPort);
  if (!/^\d+$/.test(rawPort) || !Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error('PORT must be an integer between 1 and 65535.');
  }
  const host = process.env['HOST'] ?? '127.0.0.1';
  const application = await createApplication();
  await application.listen(port, host);
  console.info(
    'API health, authentication, user, department and scoped RBAC endpoints are available.',
  );
}

await main().catch((error) => {
  console.error('API failed to start. Check local configuration and port availability:', error);
  process.exitCode = 1;
});
