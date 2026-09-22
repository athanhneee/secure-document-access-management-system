import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from './generated/prisma/client.js';

type PrismaGlobal = typeof globalThis & {
  __secureDocumentPrismaClient?: PrismaClient;
};

const prismaGlobal = globalThis as PrismaGlobal;
let processClient: PrismaClient | undefined;

function requireDatabaseUrl(connectionString?: string): string {
  const value = connectionString ?? process.env['DATABASE_URL'];
  if (!value) throw new Error('DATABASE_URL is required to initialize the database client.');

  const url = new URL(value);
  if (url.protocol !== 'postgresql:' && url.protocol !== 'postgres:') {
    throw new Error('DATABASE_URL must use the PostgreSQL protocol.');
  }
  return value;
}

export function createDatabaseClient(connectionString?: string): PrismaClient {
  const adapter = new PrismaPg({ connectionString: requireDatabaseUrl(connectionString) });
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
