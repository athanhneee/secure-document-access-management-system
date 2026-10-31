import { config as loadEnvironment } from 'dotenv';
import path from 'node:path';
import { defineConfig } from 'prisma/config';

loadEnvironment({
  path: [
    path.resolve(import.meta.dirname, '../../.env'),
    path.resolve(import.meta.dirname, '../../.local/dev.env'),
  ],
  quiet: true,
});

export default defineConfig({
  schema: 'prisma/schema.prisma',
  migrations: {
    path: 'prisma/migrations',
    seed: 'tsx prisma/seed.ts',
  },
  datasource: {
    // Prefer DIRECT_URL (e.g. Supabase Session Pooler :5432 or Direct :5432) for CLI migrations,
    // falling back to DATABASE_URL or a non-secret placeholder for offline validate/generate.
    url:
      process.env['DIRECT_URL'] ??
      process.env['DATABASE_URL'] ??
      'postgresql://127.0.0.1:5432/prisma_validation',
  },
});
