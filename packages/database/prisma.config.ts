import { config as loadEnvironment } from 'dotenv';
import path from 'node:path';
import { defineConfig } from 'prisma/config';

loadEnvironment({
  path: path.resolve(import.meta.dirname, '../../.local/dev.env'),
  quiet: true,
});

export default defineConfig({
  schema: 'prisma/schema.prisma',
  migrations: {
    path: 'prisma/migrations',
    seed: 'tsx prisma/seed.ts',
  },
  datasource: {
    // A non-secret placeholder keeps validate/generate usable before local infrastructure exists.
    url: process.env['DATABASE_URL'] ?? 'postgresql://127.0.0.1:5432/prisma_validation',
  },
});
