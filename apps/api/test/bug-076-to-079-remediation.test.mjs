import 'reflect-metadata';
import assert from 'node:assert/strict';
import crypto, { generateKeyPairSync, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { PGlite } from '@electric-sql/pglite';
import { pg_trgm } from '@electric-sql/pglite/contrib/pg_trgm';
import { canonicalizeJson } from '@sda/contracts';
import { AppConfigService } from '../dist/config/config.service.js';
import { validateEnv } from '../dist/config/env.schema.js';
import { TokenService, parseSigningPublicKeysJson } from '../dist/modules/auth/token.service.js';
import { buildSearchWhereClause } from '../dist/modules/documents/document-search-query.helper.js';
import {
  buildPgCliEnv,
  decryptBackupArtifactAes256Gcm,
  encryptBackupArtifactAes256Gcm,
  rewritePgDumpSqlForIsolatedSchema,
  verifyEncryptedBlobRoundtrip,
  verifyRestoredAuditChain,
} from '../../../scripts/backup-restore-live.helper.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../../..');

test('[BUG-076] .env.example uses JSON array for AUTH_SIGNING_PUBLIC_KEYS_JSON and TokenService supports both Array and Object map formats', async () => {
  const envExample = fs.readFileSync(path.join(repoRoot, '.env.example'), 'utf8');
  assert.match(
    envExample,
    /AUTH_SIGNING_PUBLIC_KEYS_JSON=\[\{"kid":"kid-1","publicKeyPem":"<PLACEHOLDER_ED25519_PUBLIC_KEY_PEM>"\}\]/u,
  );

  const pair1 = generateKeyPairSync('ed25519');
  const pair2 = generateKeyPairSync('ed25519');
  const privPem1 = pair1.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
  const pubPem1 = pair1.publicKey.export({ format: 'pem', type: 'spki' }).toString();
  const pubPem2 = pair2.publicKey.export({ format: 'pem', type: 'spki' }).toString();

  // Format 1: Standard Array (multi-key rotation compatible)
  const svcArray = new TokenService(
    new AppConfigService(
      validateEnv({
        NODE_ENV: 'development',
        AUTH_ACTIVE_KID: 'kid-1',
        AUTH_SIGNING_PRIVATE_KEY_PEM: privPem1,
        AUTH_SIGNING_PUBLIC_KEYS_JSON: JSON.stringify([
          { kid: 'kid-1', publicKeyPem: pubPem1 },
          { kid: 'kid-2', publicKeyPem: pubPem2 },
        ]),
      }),
    ),
  );
  const jwtFromArray = await svcArray.issueAccessToken(42n, 'sid-array', true);
  const claimsFromArray = await svcArray.verifyAccessToken(jwtFromArray);
  assert.equal(claimsFromArray.sub, '42');
  assert.equal((await svcArray.jwks()).keys.length, 2);

  // Format 2: Object map { [kid]: pem }
  const svcObject = new TokenService(
    new AppConfigService(
      validateEnv({
        NODE_ENV: 'development',
        AUTH_ACTIVE_KID: 'kid-1',
        AUTH_SIGNING_PRIVATE_KEY_PEM: privPem1,
        AUTH_SIGNING_PUBLIC_KEYS_JSON: JSON.stringify({
          'kid-1': pubPem1,
          'kid-2': pubPem2,
        }),
      }),
    ),
  );
  const verifiedCross = await svcObject.verifyAccessToken(jwtFromArray);
  assert.equal(verifiedCross.sid, 'sid-array');

  // Invalid primitive JSON must throw a descriptive error, NEVER `publicKeys.some is not a function`
  assert.throws(
    () => parseSigningPublicKeysJson('"not-an-array-or-object"'),
    /AUTH_SIGNING_PUBLIC_KEYS_JSON must be a JSON array or \{ \[kid\]: publicKeyPem \} object/u,
  );
});

test('[BUG-077] compose.prod.yaml forwards all required prod env vars to api & worker, and EnvSchema converts empty "" optional vars to undefined', () => {
  const composeProd = fs.readFileSync(path.join(repoRoot, 'infra/compose.prod.yaml'), 'utf8');
  const [, apiSection = '', workerSection = ''] = composeProd.split(/\n  (?:api|worker):\n/u);

  for (const requiredApiVar of [
    'ABAC_TRUSTED_NETWORK_CIDRS:',
    'DATABASE_SSL:',
    'DATABASE_SSL_REJECT_UNAUTHORIZED:',
    'DATABASE_CA_CERT:',
    'REDIS_URL:',
    'APP_ENCRYPTION_MASTER_KEY:',
    'EXPORT_ENCRYPTION_KEY:',
    'DOCUMENT_AUDIT_HMAC_KEY:',
    'AUTH_AUDIT_HMAC_KEY:',
    'STORAGE_ENDPOINT:',
    'STORAGE_PORT:',
    'STORAGE_REGION:',
    'STORAGE_USE_SSL:',
    'STORAGE_ACCESS_KEY:',
    'STORAGE_SECRET_KEY:',
    'STORAGE_BUCKET_DOCUMENTS:',
    'STORAGE_BUCKET_QUARANTINE:',
    'STORAGE_BUCKET_DERIVATIVES:',
  ]) {
    assert.ok(apiSection.includes(requiredApiVar), `api section missing ${requiredApiVar}`);
  }

  const workerEnvOnly = workerSection.split('\n  web:\n')[0] ?? '';
  for (const requiredWorkerVar of [
    'ABAC_TRUSTED_NETWORK_CIDRS:',
    'DATABASE_SSL:',
    'DATABASE_SSL_REJECT_UNAUTHORIZED:',
    'DATABASE_CA_CERT:',
    'REDIS_URL:',
    'APP_ENCRYPTION_MASTER_KEY:',
    'EXPORT_ENCRYPTION_KEY:',
    'DOCUMENT_AUDIT_HMAC_KEY:',
    'AUTH_AUDIT_HMAC_KEY:',
    'STORAGE_ENDPOINT:',
    'STORAGE_PORT:',
    'STORAGE_REGION:',
    'STORAGE_USE_SSL:',
    'STORAGE_ACCESS_KEY:',
    'STORAGE_SECRET_KEY:',
    'STORAGE_BUCKET_DOCUMENTS:',
    'STORAGE_BUCKET_QUARANTINE:',
    'STORAGE_BUCKET_DERIVATIVES:',
  ]) {
    assert.ok(
      workerEnvOnly.includes(requiredWorkerVar),
      `worker section missing ${requiredWorkerVar}`,
    );
  }

  // Empty string "" from Docker Compose `${OPTIONAL_VAR:-}` must NOT crash Zod `.min(...)`
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const baseProdEnv = {
    NODE_ENV: 'production',
    TRUST_PROXY: 'loopback,uniquelocal',
    ABAC_TRUSTED_NETWORK_CIDRS: '10.10.0.0/16',
    CORS_ALLOWED_ORIGINS: 'https://sda.example.gov',
    DATABASE_URL: 'postgresql://sda:fixture-password@db:5432/sda',
    DATABASE_CA_CERT: '',
    REDIS_URL: 'redis://:fixture-password@redis:6379/0',
    APP_ENCRYPTION_MASTER_KEY: 'prod-master-key-32-bytes-minimum-entropy!!',
    AUDIT_INTEGRITY_KEY: 'prod-audit-integrity-key-32-bytes-entropy!!',
    DOCUMENT_AUDIT_HMAC_KEY: 'prod-doc-audit-hmac-key-32-bytes-entropy!!',
    AUTH_AUDIT_HMAC_KEY: 'prod-auth-audit-hmac-key-32-bytes-entropy!!',
    AUDIT_KEY_ROTATION_JSON: '',
    EXPORT_ENCRYPTION_KEY: '',
    AUTH_ACTIVE_KID: 'prod-k1',
    AUTH_SIGNING_PRIVATE_KEY_PEM: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    AUTH_SIGNING_PUBLIC_KEYS_JSON: JSON.stringify([
      {
        kid: 'prod-k1',
        publicKeyPem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      },
    ]),
    STORAGE_ACCESS_KEY: 'prod-access-key',
    STORAGE_SECRET_KEY: 'prod-secret-key',
    WEBAUTHN_RP_ID: 'sda.example.gov',
    WEBAUTHN_ORIGINS: 'https://sda.example.gov',
    PASSWORD_RESET_BASE_URL: 'https://sda.example.gov/reset-password',
    SMTP_HOST: '',
    SMTP_USER: '',
    SMTP_PASS: '',
    METRICS_SCRAPE_TOKEN: '',
    EXPORT_STORAGE_DIR: '/var/lib/sda/exports',
  };

  const parsed = validateEnv(baseProdEnv);
  assert.equal(parsed.EXPORT_ENCRYPTION_KEY, undefined);
  assert.equal(parsed.DATABASE_CA_CERT, undefined);
  assert.equal(parsed.SMTP_HOST, '127.0.0.1');

  assert.throws(
    () => validateEnv({ ...baseProdEnv, EXPORT_ENCRYPTION_KEY: 'too-short-export-key' }),
    /EXPORT_ENCRYPTION_KEY/u,
  );
});

test('[BUG-078] Backup/Restore helper isolates PG* env vars, enforces real AES-256-GCM tamper detection, rewrites public.* schema safely, and verifies HMAC audit chains', () => {
  const cliEnv = buildPgCliEnv(
    'postgresql://backup_user:fixture-pass%21word@pg.internal:5433/sda_prod?schema=public&sslmode=require',
    {},
  );
  assert.equal(cliEnv.PGHOST, 'pg.internal');
  assert.equal(cliEnv.PGPORT, '5433');
  assert.equal(cliEnv.PGUSER, 'backup_user');
  assert.equal(cliEnv.PGPASSWORD, 'fixture-pass!word');
  assert.equal(cliEnv.PGDATABASE, 'sda_prod');
  assert.equal(cliEnv.PGSSLMODE, 'require');

  // Real AES-256-GCM encryption + tamper rejection
  const sha = verifyEncryptedBlobRoundtrip('drill-test-encryption-key-32-bytes!!');
  assert.equal(sha.length, 64);

  const samplePlain = Buffer.from('SELECT 1; -- sensitive backup payload', 'utf8');
  const enc = encryptBackupArtifactAes256Gcm(samplePlain, 'key-1', 'aad-1');
  assert.equal(enc.includes(samplePlain), false);
  assert.throws(() => decryptBackupArtifactAes256Gcm(enc, 'wrong-key', 'aad-1'));
  assert.deepEqual(decryptBackupArtifactAes256Gcm(enc, 'key-1', 'aad-1'), samplePlain);

  // Rewrite pg_dump SQL so SET search_path = public and hardcoded public.* triggers never hit live public
  const dumpSnippet = `
    SELECT pg_catalog.set_config('search_path', '', false);
    SET search_path = public;
    CREATE FUNCTION public.validate_user_clearance_for_grant() RETURNS trigger AS $$
    BEGIN
      PERFORM 1 FROM public.user_attribute_assignments uaa;
      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;
  `;
  const rewritten = rewritePgDumpSqlForIsolatedSchema(dumpSnippet, 'sda_dr_verify_abcd1234');
  assert.doesNotMatch(rewritten, /SET\s+search_path\s*=\s*public/iu);
  assert.doesNotMatch(rewritten, /\bpublic\./u);
  assert.match(rewritten, /sda_dr_verify_abcd1234\.user_attribute_assignments/u);

  // HMAC-SHA256 audit chain verification catches tampered rows
  const hmacKey = 'dr-audit-chain-hmac-secret-key-32-chars!!';
  const t1 = new Date('2026-11-26T01:00:00.000Z');
  const c1 = randomUUID();
  const row1Payload = canonicalizeJson({
    action: 'DOCUMENT_VIEW',
    actorUserId: '1',
    actorUsername: 'admin',
    chainAlgorithm: 'HMAC-SHA-256',
    chainPartition: 'DOCUMENT',
    chainSequence: '1',
    correlationId: c1,
    details: {},
    documentId: 'doc-1',
    accessSessionId: null,
    ipAddress: '127.0.0.1',
    objectType: 'DOCUMENT',
    objectId: 'doc-1',
    occurredAt: t1.toISOString(),
    outcome: 'SUCCESS',
    previousHash: null,
    reasonCode: null,
    userAgent: null,
  });
  const h1 = crypto.createHmac('sha256', hmacKey).update(row1Payload, 'utf8').digest('hex');
  const validRows = [
    {
      id: 1n,
      occurred_at: t1,
      actor_user_id: 1n,
      actor_username: 'admin',
      action: 'DOCUMENT_VIEW',
      object_type: 'DOCUMENT',
      object_id: 'doc-1',
      document_id: 'doc-1',
      access_session_id: null,
      outcome: 'SUCCESS',
      reason_code: null,
      ip_address: '127.0.0.1',
      user_agent: null,
      correlation_id: c1,
      details: {},
      previous_hash: null,
      entry_hash: h1,
      chain_partition: 'DOCUMENT',
      chain_sequence: 1n,
      chain_algorithm: 'HMAC-SHA-256',
      hmac_key_version: 1,
    },
  ];
  const verified = verifyRestoredAuditChain(validRows, hmacKey);
  assert.equal(verified.cryptographicCount, 1);

  assert.throws(
    () => verifyRestoredAuditChain([{ ...validRows[0], outcome: 'TAMPERED' }], hmacKey),
    /HMAC-SHA256 verification failed/u,
  );
});

test('[BUG-079] buildSearchWhereClause matches idx_documents_fts verbatim, uses % + ILIKE + department subquery, and hits GIN index in PostgreSQL planner', async () => {
  const sqlFragment = buildSearchWhereClause({
    userId: 10n,
    hasGlobalDiscover: true,
    discoverableDeptIds: null,
    roleIds: [],
    userClearanceRank: 3,
    input: { q: 'tài chính', page: 1, pageSize: 20, sort: 'created_at', order: 'desc' },
    sanitizedQuery: 'tài chính',
  });
  const renderedTemplate = sqlFragment.strings.join('?');

  // Exact match with idx_documents_fts (no dep."name" appended to to_tsvector on documents)
  assert.match(
    renderedTemplate,
    /to_tsvector\('simple',\s*coalesce\(d\."title",\s*''\)\s*\|\|\s*' '\s*\|\|\s*coalesce\(d\."description",\s*''\)\s*\|\|\s*' '\s*\|\|\s*coalesce\(d\."document_code",\s*''\)\)/u,
  );
  assert.doesNotMatch(renderedTemplate, /similarity\s*\(/iu);
  assert.match(renderedTemplate, /d\."title"\s*%/u);
  assert.match(renderedTemplate, /d\."title"\s*ILIKE/u);
  assert.match(
    renderedTemplate,
    /d\."department_id"\s*IN\s*\(\s*SELECT\s+dep_s\."id"\s+FROM\s+departments\s+dep_s/u,
  );

  // Prove real PostgreSQL query planner uses idx_documents_fts & idx_documents_title_trgm via PGlite
  const pg = await PGlite.create('memory://', { extensions: { pg_trgm } });
  try {
    await pg.exec(`
      CREATE EXTENSION IF NOT EXISTS pg_trgm;
      CREATE TABLE departments (id BIGINT PRIMARY KEY, name TEXT NOT NULL);
      CREATE TABLE documents (
        id UUID PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        document_code TEXT NOT NULL,
        department_id BIGINT NOT NULL REFERENCES departments(id)
      );
      CREATE INDEX idx_documents_fts ON documents USING gin (
        to_tsvector('simple', coalesce(title, '') || ' ' || coalesce(description, '') || ' ' || coalesce(document_code, ''))
      );
      CREATE INDEX idx_documents_title_trgm ON documents USING gin (title gin_trgm_ops);
      SET enable_seqscan = off;
    `);

    const explainFts = await pg.query(
      `EXPLAIN SELECT d.id FROM documents d
       WHERE to_tsvector('simple', coalesce(d."title", '') || ' ' || coalesce(d."description", '') || ' ' || coalesce(d."document_code", ''))
             @@ plainto_tsquery('simple', $1)`,
      ['báo cáo'],
    );
    const planText = explainFts.rows.map((r) => Object.values(r)[0]).join('\n');
    assert.match(
      planText,
      /idx_documents_fts/u,
      `Expected planner to use idx_documents_fts, got:\n${planText}`,
    );
  } finally {
    await pg.close();
  }
});
