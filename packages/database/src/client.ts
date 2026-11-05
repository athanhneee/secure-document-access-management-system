import fs from 'node:fs';
import type tls from 'node:tls';
import { PrismaPg } from '@prisma/adapter-pg';
import type pg from 'pg';
import { PrismaClient } from './generated/prisma/client.js';

type PrismaGlobal = typeof globalThis & {
  __secureDocumentPrismaClient?: PrismaClient;
};

const prismaGlobal = globalThis as PrismaGlobal;
let processClient: PrismaClient | undefined;

export interface ResolvedPgConfig {
  poolConfig: pg.PoolConfig;
  schema?: string;
}

/**
 * Giải thuật nạp chứng chỉ gốc (Root CA) phục vụ xác thực chuỗi tin cậy X.509 cho kết nối TLS PostgreSQL:
 * - Nếu chuỗi cấu hình bắt đầu bằng header PEM (`-----BEGIN CERTIFICATE-----`), nạp trực tiếp từ biến môi trường (hỗ trợ ký tự xuống dòng `\n` được escape).
 * - Ngược lại, coi giá trị là đường dẫn tệp chứng chỉ trên đĩa và đọc đồng bộ lúc khởi tạo pool.
 */
function resolveCustomCaCertificate(rawCaCert: string | undefined): string | undefined {
  const trimmed = rawCaCert?.trim();
  if (!trimmed) return undefined;
  if (trimmed.includes('-----BEGIN CERTIFICATE-----')) {
    return trimmed.replace(/\\n/gu, '\n');
  }
  return fs.readFileSync(trimmed, 'utf8');
}

/**
 * Giải thuật chuẩn hóa cấu hình kết nối PostgreSQL & cưỡng chế TLS xác thực chứng chỉ nghiêm ngặt (chống CWE-295 MitM & CWE-319 Cleartext):
 * 1. Tách các tham số riêng của Prisma (`schema`, `pgbouncer`, `connection_limit`) khỏi chuỗi kết nối trước khi truyền xuống `node-postgres`.
 * 2. Tự động bật TLS có xác thực chứng chỉ (`rejectUnauthorized: true`, `minVersion: 'TLSv1.2'`) mặc định cho toàn bộ kết nối TCP trên `NODE_ENV=production` (kể cả khi không khai báo `DATABASE_SSL=true`), cho mọi máy chủ đám mây `.supabase.co`/`.supabase.com` (tuyệt đối không hạ `rejectUnauthorized: false`), hoặc khi có `DATABASE_SSL=true` / `DATABASE_CA_CERT` / `sslmode` yêu cầu mã hóa.
 * 3. Cơ chế Fail-Closed trên `NODE_ENV=production`: Từ chối khởi chạy ngay lập tức nếu phát hiện tắt xác thực chứng chỉ (CWE-295) hoặc ép chạy không mã hóa `DATABASE_SSL=false` / `sslmode=disable` (CWE-319).
 */
export function buildPgPoolConfig(connectionString?: string): ResolvedPgConfig {
  const rawValue = connectionString ?? process.env['DATABASE_URL'];
  if (!rawValue) throw new Error('DATABASE_URL is required to initialize the database client.');

  const url = new URL(rawValue);
  if (url.protocol !== 'postgresql:' && url.protocol !== 'postgres:') {
    throw new Error('DATABASE_URL must use the PostgreSQL protocol.');
  }

  const hostname = url.hostname.toLowerCase();
  const hostParam = url.searchParams.get('host') ?? '';
  const isUnixSocket = !hostname || hostname.startsWith('/') || hostParam.startsWith('/');
  const isSupabaseHost =
    hostname === 'supabase.co' ||
    hostname === 'supabase.com' ||
    hostname.endsWith('.supabase.co') ||
    hostname.endsWith('.supabase.com');

  const schema = url.searchParams.get('schema') ?? undefined;
  const sslMode = url.searchParams.get('sslmode')?.toLowerCase();
  const envSsl = process.env['DATABASE_SSL']?.trim().toLowerCase();
  const isProduction = process.env['NODE_ENV'] === 'production';
  const rejectUnauthorizedEnv = process.env['DATABASE_SSL_REJECT_UNAUTHORIZED']
    ?.trim()
    .toLowerCase();
  const explicitDisableVerify = sslMode === 'no-verify' || rejectUnauthorizedEnv === 'false';
  const explicitDisableSsl = sslMode === 'disable' || envSsl === 'false';

  // CONFLICT-RESOLVED: Chặn vô hiệu hóa xác thực chứng chỉ X.509 (CWE-295) và chặn kết nối không mã hóa (CWE-319) cả trên Production lẫn mọi máy chủ đám mây Supabase (HIGH-12).
  if ((isProduction || isSupabaseHost) && explicitDisableVerify) {
    throw new Error(
      'SECURITY VIOLATION (CWE-295): Disabling TLS certificate verification is strictly forbidden in production and on Supabase cloud hosts. Configure a valid CA bundle via DATABASE_CA_CERT or NODE_EXTRA_CA_CERTS.',
    );
  }

  if (((isProduction && !isUnixSocket) || isSupabaseHost) && explicitDisableSsl) {
    throw new Error(
      'SECURITY VIOLATION (CWE-319): Unencrypted PostgreSQL TCP connections (DATABASE_SSL=false or sslmode=disable) are strictly forbidden in production and on Supabase cloud hosts.',
    );
  }

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

  const ca = resolveCustomCaCertificate(process.env['DATABASE_CA_CERT']);
  // CONFLICT-RESOLVED: Enforce verified TLS by default in production TCP deployments and for all
  // `.supabase.co`/`.supabase.com` hosts without ever defaulting `rejectUnauthorized` to `false`.
  const forceSsl =
    (isProduction && !isUnixSocket) ||
    (isSupabaseHost && !explicitDisableSsl) ||
    envSsl === 'true' ||
    Boolean(ca) ||
    sslMode === 'require' ||
    sslMode === 'verify-ca' ||
    sslMode === 'verify-full' ||
    sslMode === 'no-verify';

  if (forceSsl) {
    // Remove sslmode from URL so pg-connection-string does not override explicit PoolConfig.ssl.
    url.searchParams.delete('sslmode');
    const sslOptions: tls.ConnectionOptions = {
      minVersion: 'TLSv1.2',
      rejectUnauthorized: !explicitDisableVerify,
      ...(ca ? { ca } : {}),
    };
    poolConfig.ssl = sslOptions;
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
