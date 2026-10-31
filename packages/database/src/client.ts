import { PrismaPg } from '@prisma/adapter-pg';
import type pg from 'pg';
import { PrismaClient } from './generated/prisma/client.js';

type PrismaGlobal = typeof globalThis & {
  __secureDocumentPrismaClient?: PrismaClient;
};

const prismaGlobal = globalThis as PrismaGlobal;
let processClient: PrismaClient | undefined;

interface ResolvedPgConfig {
  poolConfig: pg.PoolConfig;
  schema?: string;
}

function buildPgPoolConfig(connectionString?: string): ResolvedPgConfig {
  const rawValue = connectionString ?? process.env['DATABASE_URL'];
  if (!rawValue) throw new Error('DATABASE_URL is required to initialize the database client.');

  const url = new URL(rawValue);
  if (url.protocol !== 'postgresql:' && url.protocol !== 'postgres:') {
    throw new Error('DATABASE_URL must use the PostgreSQL protocol.');
  }

  const schema = url.searchParams.get('schema') ?? undefined;
  const sslMode = url.searchParams.get('sslmode')?.toLowerCase();
  const isSupabaseHost =
    url.hostname.endsWith('.supabase.co') || url.hostname.endsWith('.supabase.com');

  // Strip Prisma-specific query parameters before passing URL to node-postgres.
  url.searchParams.delete('schema');
  url.searchParams.delete('pgbouncer');
  url.searchParams.delete('connection_limit');

  const configuredMax = Number(process.env['DATABASE_POOL_MAX'] ?? '10');
  const max = Number.isFinite(configuredMax) && configuredMax > 0 ? Math.floor(configuredMax) : 10;

  const poolConfig: pg.PoolConfig = {
    max,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
  };

  const forceSsl =
    isSupabaseHost ||
    process.env['DATABASE_SSL'] === 'true' ||
    sslMode === 'require' ||
    sslMode === 'no-verify';

  if (forceSsl) {
    // Remove sslmode from URL so pg-connection-string does not override explicit PoolConfig.ssl.
    url.searchParams.delete('sslmode');
    const rejectUnauthorized =
      sslMode === 'no-verify' || process.env['DATABASE_SSL_REJECT_UNAUTHORIZED'] === 'false'
        ? false
        : !isSupabaseHost || process.env['DATABASE_SSL_REJECT_UNAUTHORIZED'] === 'true';
    poolConfig.ssl = { rejectUnauthorized };
  }

  poolConfig.connectionString = url.toString();

  return schema ? { poolConfig, schema } : { poolConfig };
}

export function createDatabaseClient(connectionString?: string): PrismaClient {
  const { poolConfig, schema } = buildPgPoolConfig(connectionString);
  const adapter = new PrismaPg(poolConfig, schema ? { schema } : undefined);
  return new PrismaClient({
    adapter,
    transactionOptions: {
      maxWait: 5_000,
      timeout: 15_000,
    },
  });
}

/** Reuses one pool during development hot reload and one instance per production process. */
export function getDatabaseClient(): PrismaClient {
  if (process.env['NODE_ENV'] === 'production') {
    processClient ??= createDatabaseClient();
    return processClient;
  }

  prismaGlobal.__secureDocumentPrismaClient ??= createDatabaseClient();
  return prismaGlobal.__secureDocumentPrismaClient;
}

export async function disconnectDatabase(): Promise<void> {
  const client = processClient ?? prismaGlobal.__secureDocumentPrismaClient;
  processClient = undefined;
  delete prismaGlobal.__secureDocumentPrismaClient;
  if (!client) return;
  await client.$disconnect();
}
