import { createApplication } from './application.js';

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

await main().catch(() => {
  console.error('API failed to start. Check local configuration and port availability.');
  process.exitCode = 1;
});
