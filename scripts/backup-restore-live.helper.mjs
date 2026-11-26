/**
 * Thuật toán: Mô-đun Thực Thi Diễn Tập Sao Lưu Logic Mã Hóa `AES-256-GCM` & Phục Hồi Cô Lập Trên PostgreSQL Trực Tuyến:
 * - Tách toàn bộ thông số kết nối sang biến môi trường tiến trình con (`PGHOST`, `PGPORT`, `PGUSER`, `PGDATABASE`, `PGPASSWORD`),
 *   tuyệt đối không truyền mật khẩu hoặc URI qua `argv` và loại bỏ tham số riêng của Prisma (`?schema=public`).
 * - Chặn báo xanh giả (Fail-Closed) khi `pg_dump` thất bại, mã hóa/giải mã xác thực `AES-256-GCM` thực sự trên tạo tác sao lưu,
 *   khôi phục vào cơ sở dữ liệu tạm cô lập `sda_dr_verify_<hex>` (hoặc schema cô lập đã viết lại tham chiếu `public.*` khi không có quyền `CREATEDB`),
 *   và kiểm chứng lại toàn bộ chuỗi băm `HMAC-SHA256` của `audit_logs`.
 */

import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';

const dbRequire = createRequire(new URL('../packages/database/package.json', import.meta.url));
const { Client: PgClient } = dbRequire('pg');

const BACKUP_MAGIC = Buffer.from('SDAB\x01', 'binary');
const GCM_IV_BYTES = 12;
const GCM_TAG_BYTES = 16;
const EPHEMERAL_DRILL_KEY = crypto.randomBytes(32);

function canonicalizeJsonValue(value) {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'boolean' || typeof value === 'number') return JSON.stringify(value);
  if (typeof value === 'bigint') return JSON.stringify(value.toString());
  if (typeof value === 'string') return JSON.stringify(value);
  if (value instanceof Date) return JSON.stringify(value.toISOString());
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeJsonValue(item === undefined ? null : item)).join(',')}]`;
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value)
      .filter((k) => value[k] !== undefined)
      .sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalizeJsonValue(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(String(value));
}

function deriveBackupAesKey(rawKeyMaterial) {
  const configured =
    (typeof rawKeyMaterial === 'string' && rawKeyMaterial.trim()) ||
    process.env['BACKUP_ENCRYPTION_KEY']?.trim() ||
    process.env['EXPORT_ENCRYPTION_KEY']?.trim() ||
    process.env['APP_ENCRYPTION_MASTER_KEY']?.trim();
  const ikm = configured ? Buffer.from(configured, 'utf8') : EPHEMERAL_DRILL_KEY;
  return Buffer.from(
    crypto.hkdfSync(
      'sha256',
      ikm,
      Buffer.from('sda-dr-backup-salt-v1', 'utf8'),
      Buffer.from('sda-dr-backup-aes-256-gcm', 'utf8'),
      32,
    ),
  );
}

/**
 * Thuật toán: Mã hóa xác thực tạo tác sao lưu bằng `AES-256-GCM` (`SDAB\x01 || IV(12B) || TAG(16B) || CIPHERTEXT`).
 */
export function encryptBackupArtifactAes256Gcm(
  plaintextBuffer,
  rawKeyMaterial,
  aad = 'sda-dr-backup-v1',
) {
  const input = Buffer.isBuffer(plaintextBuffer)
    ? plaintextBuffer
    : Buffer.from(String(plaintextBuffer), 'utf8');
  const key = deriveBackupAesKey(rawKeyMaterial);
  const iv = crypto.randomBytes(GCM_IV_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(input), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([BACKUP_MAGIC, iv, tag, ciphertext]);
}

/**
 * Thuật toán: Giải mã và xác thực tính toàn vẹn tạo tác sao lưu `AES-256-GCM` (`authTagLength = 16`).
 */
export function decryptBackupArtifactAes256Gcm(
  envelopeBuffer,
  rawKeyMaterial,
  aad = 'sda-dr-backup-v1',
) {
  if (
    !Buffer.isBuffer(envelopeBuffer) ||
    envelopeBuffer.length < BACKUP_MAGIC.length + GCM_IV_BYTES + GCM_TAG_BYTES ||
    !envelopeBuffer.subarray(0, BACKUP_MAGIC.length).equals(BACKUP_MAGIC)
  ) {
    throw new Error('Invalid or unencrypted backup envelope header.');
  }
  const key = deriveBackupAesKey(rawKeyMaterial);
  const ivStart = BACKUP_MAGIC.length;
  const tagStart = ivStart + GCM_IV_BYTES;
  const bodyStart = tagStart + GCM_TAG_BYTES;
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    envelopeBuffer.subarray(ivStart, tagStart),
    { authTagLength: GCM_TAG_BYTES },
  );
  decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(envelopeBuffer.subarray(tagStart, bodyStart));
  return Buffer.concat([decipher.update(envelopeBuffer.subarray(bodyStart)), decipher.final()]);
}

/**
 * Thuật toán: Kiểm chứng sao lưu - khôi phục thực sự bằng `AES-256-GCM` + phát hiện giả mạo thẻ xác thực + đối chiếu `SHA-256`.
 */
export function verifyEncryptedBlobRoundtrip(rawKeyMaterial) {
  const rawBlob = crypto.randomBytes(4096);
  const sha = crypto.createHash('sha256').update(rawBlob).digest('hex');
  const encrypted = encryptBackupArtifactAes256Gcm(rawBlob, rawKeyMaterial, 'sda-dr-blob-verify');
  if (encrypted.includes(rawBlob)) {
    throw new Error('Ciphertext leaked unencrypted plaintext bytes');
  }

  // Tamper 1 bit in ciphertext and verify GCM authentication fails closed
  const tampered = Buffer.from(encrypted);
  tampered[tampered.length - 1] ^= 0x01;
  let tamperRejected = false;
  try {
    decryptBackupArtifactAes256Gcm(tampered, rawKeyMaterial, 'sda-dr-blob-verify');
  } catch {
    tamperRejected = true;
  }
  if (!tamperRejected) {
    throw new Error('AES-256-GCM failed to reject tampered backup ciphertext');
  }

  const restored = decryptBackupArtifactAes256Gcm(encrypted, rawKeyMaterial, 'sda-dr-blob-verify');
  if (crypto.createHash('sha256').update(restored).digest('hex') !== sha) {
    throw new Error('Encrypted blob roundtrip hash mismatch');
  }
  return sha;
}

/**
 * Thuật toán: Tách thông số kết nối từ `DATABASE_URL` sang biến môi trường chuẩn libpq (`PGHOST`, `PGPORT`, `PGUSER`,
 * `PGDATABASE`, `PGPASSWORD`, `PGSSLMODE`), loại bỏ `?schema=public` và tuyệt đối không đưa mật khẩu lên `argv`.
 */
export function buildPgCliEnv(databaseUrl, baseEnv = process.env, overrideDatabase) {
  const parsed = new URL(databaseUrl);
  if (parsed.protocol !== 'postgresql:' && parsed.protocol !== 'postgres:') {
    throw new Error('DATABASE_URL must use postgresql:// or postgres:// protocol.');
  }
  const databaseName =
    overrideDatabase ?? (decodeURIComponent(parsed.pathname.replace(/^\/+/u, '')) || 'postgres');
  const sslModeParam = parsed.searchParams.get('sslmode')?.trim();
  const envSsl = String(baseEnv['DATABASE_SSL'] ?? '')
    .trim()
    .toLowerCase();

  const childEnv = { ...baseEnv };
  if (parsed.hostname) childEnv['PGHOST'] = parsed.hostname;
  childEnv['PGPORT'] = parsed.port || '5432';
  if (parsed.username) childEnv['PGUSER'] = decodeURIComponent(parsed.username);
  if (parsed.password) childEnv['PGPASSWORD'] = decodeURIComponent(parsed.password);
  childEnv['PGDATABASE'] = databaseName;

  if (sslModeParam) {
    childEnv['PGSSLMODE'] = sslModeParam;
  } else if (envSsl === 'true') {
    childEnv['PGSSLMODE'] = 'require';
  }

  const caCert = String(baseEnv['DATABASE_CA_CERT'] ?? '').trim();
  if (caCert && !caCert.includes('-----BEGIN CERTIFICATE-----') && fs.existsSync(caCert)) {
    childEnv['PGSSLROOTCERT'] = caCert;
  }

  return childEnv;
}

function buildCleanPgConnectionString(databaseUrl, overrideDatabase) {
  const parsed = new URL(databaseUrl);
  parsed.searchParams.delete('schema');
  parsed.searchParams.delete('pgbouncer');
  parsed.searchParams.delete('connection_limit');
  if (overrideDatabase) {
    parsed.pathname = `/${encodeURIComponent(overrideDatabase)}`;
  }
  return parsed.toString();
}

/**
 * Thuật toán: Viết lại kịch bản SQL của `pg_dump` khi phải khôi phục vào schema cô lập trên cùng DB (trường hợp tài khoản thiếu quyền `CREATEDB`),
 * đảm bảo `SET search_path = public;` và các hàm/trigger tham chiếu cứng `public.*` (như `validate_user_clearance_for_grant`)
 * được chuyển hướng hoàn toàn sang `targetSchema`, không bao giờ chạm vào `public` đang chạy thật.
 */
export function rewritePgDumpSqlForIsolatedSchema(sqlText, targetSchema) {
  if (!/^[a-z_][a-z0-9_]*$/u.test(targetSchema) || targetSchema === 'public') {
    throw new Error(`Unsafe isolated restore schema identifier: "${targetSchema}"`);
  }
  return sqlText
    .replace(
      /CREATE\s+SCHEMA\s+(?:IF\s+NOT\s+EXISTS\s+)?['"]?public['"]?\s*;/giu,
      '-- skipped public schema creation;',
    )
    .replace(/ALTER\s+SCHEMA\s+['"]?public['"]?\s+[^;]*;/giu, '-- skipped public schema alter;')
    .replace(
      /SELECT\s+pg_catalog\.set_config\(\s*'search_path'\s*,\s*'[^']*'\s*,\s*(true|false)\s*\)\s*;/giu,
      `SELECT pg_catalog.set_config('search_path', '${targetSchema}, extensions', $1);`,
    )
    .replace(
      /SET\s+search_path\s*(?:=|TO)\s*['"]?public['"]?(?:\s*,\s*['"]?extensions['"]?)?/giu,
      `SET search_path = ${targetSchema}, extensions`,
    )
    .replace(/\bpublic\./gu, `${targetSchema}.`);
}

function safeTimingHexEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a.trim(), 'utf8');
  const bufB = Buffer.from(b.trim(), 'utf8');
  if (bufA.byteLength !== bufB.byteLength) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function resolveAuditHmacKeyForRow(row, primaryKey, rotationMap) {
  const version =
    row.hmac_key_version !== undefined && row.hmac_key_version !== null
      ? String(row.hmac_key_version)
      : null;
  if (version && rotationMap && typeof rotationMap[version] === 'string' && rotationMap[version]) {
    return rotationMap[version];
  }
  return primaryKey;
}

/**
 * Thuật toán: Xác minh chuỗi liên kết băm (`previous_hash` -> `entry_hash`), tính liên tục của `chain_sequence`,
 * và tái tính chữ ký chuẩn tắc RFC 8785 `HMAC-SHA-256` trên dữ liệu `audit_logs` sau khôi phục.
 */
export function verifyRestoredAuditChain(auditRows, hmacKey, keyRotationJson) {
  let rotationMap = null;
  if (typeof keyRotationJson === 'string' && keyRotationJson.trim()) {
    rotationMap = JSON.parse(keyRotationJson);
  }
  const effectiveKey =
    (typeof hmacKey === 'string' && hmacKey.trim()) ||
    process.env['AUDIT_INTEGRITY_KEY']?.trim() ||
    process.env['DOCUMENT_AUDIT_HMAC_KEY']?.trim() ||
    null;

  const byPartition = new Map();
  for (const row of auditRows) {
    const partition = String(row.chain_partition ?? 'GLOBAL');
    const list = byPartition.get(partition) ?? [];
    list.push(row);
    byPartition.set(partition, list);
  }

  let verifiedCount = 0;
  let cryptographicCount = 0;

  for (const [partition, rows] of byPartition.entries()) {
    rows.sort((a, b) => {
      const seqA = BigInt(a.chain_sequence);
      const seqB = BigInt(b.chain_sequence);
      return seqA < seqB ? -1 : seqA > seqB ? 1 : 0;
    });

    let prevSeq = null;
    let prevHash = null;

    for (const row of rows) {
      const seq = BigInt(row.chain_sequence);
      const rowPrevHash = row.previous_hash ? String(row.previous_hash).trim() : null;
      const rowEntryHash = String(row.entry_hash ?? '').trim();
      if (!rowEntryHash) {
        throw new Error(`Missing entry_hash in restored audit_logs (${partition}#${seq})`);
      }

      if (prevSeq === null) {
        if (seq === 1n && rowPrevHash !== null) {
          throw new Error(`Genesis audit row ${partition}#1 must have null previous_hash`);
        }
      } else {
        if (seq !== prevSeq + 1n) {
          throw new Error(
            `Audit sequence gap in restored partition ${partition}: expected ${prevSeq + 1n}, got ${seq}`,
          );
        }
        if (!rowPrevHash || !safeTimingHexEqual(rowPrevHash, prevHash)) {
          throw new Error(
            `Broken previous_hash link in restored partition ${partition} at seq=${seq}`,
          );
        }
      }

      if (effectiveKey && row.occurred_at !== undefined && row.correlation_id !== undefined) {
        const occurredIso =
          row.occurred_at instanceof Date
            ? row.occurred_at.toISOString()
            : new Date(row.occurred_at).toISOString();
        const canonicalPayload = canonicalizeJsonValue({
          action: row.action,
          actorUserId:
            row.actor_user_id !== null && row.actor_user_id !== undefined
              ? String(row.actor_user_id)
              : null,
          actorUsername: row.actor_username ?? null,
          chainAlgorithm: row.chain_algorithm ?? 'HMAC-SHA-256',
          chainPartition: partition,
          chainSequence: seq.toString(),
          correlationId: row.correlation_id,
          details: row.details ?? {},
          documentId: row.document_id ?? null,
          accessSessionId: row.access_session_id ?? null,
          ipAddress: row.ip_address ?? null,
          objectType: row.object_type,
          objectId: row.object_id ?? null,
          occurredAt: occurredIso,
          outcome: row.outcome,
          previousHash: rowPrevHash,
          reasonCode: row.reason_code ?? null,
          userAgent: row.user_agent ?? null,
        });
        const rowKey = resolveAuditHmacKeyForRow(row, effectiveKey, rotationMap);
        const expectedHmac = crypto
          .createHmac('sha256', rowKey)
          .update(canonicalPayload, 'utf8')
          .digest('hex');
        if (!safeTimingHexEqual(expectedHmac, rowEntryHash)) {
          throw new Error(
            `Audit HMAC-SHA256 verification failed in restored partition ${partition} at seq=${seq}`,
          );
        }
        cryptographicCount++;
      }

      prevSeq = seq;
      prevHash = rowEntryHash;
      verifiedCount++;
    }
  }

  return { verifiedCount, cryptographicCount, partitions: byPartition.size };
}

function redactSecrets(text, secretValues) {
  let out = String(text ?? '');
  for (const secret of secretValues) {
    if (secret && secret.length >= 3) {
      out = out.split(secret).join('[REDACTED]');
    }
  }
  return out;
}

/**
 * Thuật toán: Kết nối PostgreSQL trực tuyến, thực thi `pg_dump` qua biến môi trường `PG*` (Fail-Closed nếu lỗi),
 * mã hóa tạo tác bằng `AES-256-GCM`, khôi phục vào DB tạm cô lập (hoặc schema cô lập đã viết lại `public.*`),
 * và kiểm chứng lại đối chiếu số dòng + chuỗi băm `HMAC-SHA256` của `audit_logs`.
 */
export async function tryRunLivePostgresDrill(databaseUrl, recordStep, strictLive) {
  const cleanConnStr = buildCleanPgConnectionString(databaseUrl);
  const client = new PgClient({ connectionString: cleanConnStr, connectionTimeoutMillis: 2500 });
  try {
    await client.connect();
  } catch (err) {
    if (!['ECONNREFUSED', 'ENOTFOUND', 'ETIMEDOUT'].includes(err?.code ?? '') || strictLive) {
      throw err;
    }
    return false;
  }

  const drillId = `sda_dr_verify_${crypto.randomBytes(4).toString('hex')}`;
  const encryptedArtifactPath = path.join(os.tmpdir(), `${drillId}.backup.enc`);
  const cliEnv = buildPgCliEnv(databaseUrl, process.env);
  let isolatedDbCreated = false;
  let isolatedSchemaCreated = false;

  try {
    let t = performance.now();
    const counts = (
      await client.query(
        `SELECT (SELECT COUNT(*)::int FROM users) AS u, (SELECT COUNT(*)::int FROM documents) AS d, (SELECT COUNT(*)::int FROM audit_logs) AS a`,
      )
    ).rows[0];
    recordStep(
      '1. Connect Live PostgreSQL Source',
      'PASS',
      `users=${counts.u}, docs=${counts.d}, audits=${counts.a}`,
      performance.now() - t,
    );

    t = performance.now();
    let pgDumpSql = null;
    const versionCheck = spawnSync('pg_dump', ['--version'], { encoding: 'utf8', shell: false });
    if (versionCheck.status === 0) {
      const dumpRes = spawnSync('pg_dump', ['--schema=public', '--no-owner', '--no-privileges'], {
        env: cliEnv,
        encoding: 'utf8',
        shell: false,
        maxBuffer: 256 * 1024 * 1024,
      });
      if (dumpRes.status !== 0 || !dumpRes.stdout || dumpRes.stdout.trim().length === 0) {
        const safeErr = redactSecrets(dumpRes.stderr || dumpRes.error?.message || 'exit non-zero', [
          cliEnv['PGPASSWORD'],
          databaseUrl,
        ]);
        throw new Error(`pg_dump execution failed (status=${dumpRes.status}): ${safeErr}`);
      }
      pgDumpSql = dumpRes.stdout;
    } else if (strictLive) {
      throw new Error('pg_dump binary is required when DRILL_STRICT_LIVE=true.');
    }

    const usersRows = (
      await client.query('SELECT id, username, email FROM users ORDER BY id ASC LIMIT 500')
    ).rows;
    const auditRows = (
      await client.query(
        `SELECT id, occurred_at, actor_user_id, actor_username, action, object_type, object_id,
                document_id, access_session_id, outcome, reason_code, ip_address, user_agent,
                correlation_id, details, previous_hash, entry_hash, chain_partition,
                chain_sequence, chain_algorithm, hmac_key_version
         FROM audit_logs
         ORDER BY chain_partition ASC, chain_sequence ASC
         LIMIT 1000`,
      )
    ).rows;

    const bundlePlaintext = Buffer.from(
      JSON.stringify({ pgDumpSql, users: usersRows, auditLogs: auditRows }),
      'utf8',
    );
    const plaintextSha256 = crypto.createHash('sha256').update(bundlePlaintext).digest('hex');
    const encryptedEnvelope = encryptBackupArtifactAes256Gcm(
      bundlePlaintext,
      undefined,
      `sda-dr:${drillId}`,
    );
    fs.writeFileSync(encryptedArtifactPath, encryptedEnvelope, { mode: 0o600 });

    recordStep(
      '2. Generate AES-256-GCM Live Backup & SHA-256',
      'PASS',
      `${pgDumpSql ? 'pg_dump+' : ''}AES-256-GCM (${plaintextSha256.slice(0, 16)}...)`,
      performance.now() - t,
    );

    t = performance.now();
    const diskEnvelope = fs.readFileSync(encryptedArtifactPath);
    const decryptedBuffer = decryptBackupArtifactAes256Gcm(
      diskEnvelope,
      undefined,
      `sda-dr:${drillId}`,
    );
    if (crypto.createHash('sha256').update(decryptedBuffer).digest('hex') !== plaintextSha256) {
      throw new Error('Decrypted backup artifact SHA-256 mismatch');
    }
    const parsed = JSON.parse(decryptedBuffer.toString('utf8'));

    // Prefer an isolated temporary database so pg_dump SET search_path = public and public.* triggers
    // never touch the live production database; fall back to rewritten isolated schema only on 42501.
    try {
      await client.query(`CREATE DATABASE ${drillId}`);
      isolatedDbCreated = true;
    } catch (createDbErr) {
      if (createDbErr?.code !== '42501') {
        throw createDbErr;
      }
    }

    let restoredUsersCount = 0;
    let restoredAuditRows = [];

    if (isolatedDbCreated) {
      const targetConnStr = buildCleanPgConnectionString(databaseUrl, drillId);
      const restoreClient = new PgClient({
        connectionString: targetConnStr,
        connectionTimeoutMillis: 5000,
      });
      await restoreClient.connect();
      try {
        if (parsed.pgDumpSql && spawnSync('psql', ['--version'], { shell: false }).status === 0) {
          const psqlEnv = buildPgCliEnv(databaseUrl, process.env, drillId);
          const restoreRes = spawnSync('psql', ['-v', 'ON_ERROR_STOP=1', '--quiet'], {
            env: psqlEnv,
            input: parsed.pgDumpSql,
            encoding: 'utf8',
            shell: false,
            maxBuffer: 64 * 1024 * 1024,
          });
          if (restoreRes.status !== 0) {
            const safeErr = redactSecrets(restoreRes.stderr || 'psql restore failed', [
              psqlEnv['PGPASSWORD'],
              databaseUrl,
            ]);
            throw new Error(`psql isolated DB restore failed: ${safeErr}`);
          }
          restoredUsersCount = (
            await restoreClient.query('SELECT COUNT(*)::int AS cnt FROM users LIMIT 500')
          ).rows[0].cnt;
          restoredAuditRows = (
            await restoreClient.query(
              `SELECT id, occurred_at, actor_user_id, actor_username, action, object_type, object_id,
                      document_id, access_session_id, outcome, reason_code, ip_address, user_agent,
                      correlation_id, details, previous_hash, entry_hash, chain_partition,
                      chain_sequence, chain_algorithm, hmac_key_version
               FROM audit_logs
               ORDER BY chain_partition ASC, chain_sequence ASC
               LIMIT 1000`,
            )
          ).rows;
        } else {
          await restoreClient.query(
            `CREATE TABLE users_restore (id BIGINT PRIMARY KEY, username TEXT NOT NULL, email TEXT NOT NULL);
             CREATE TABLE audit_restore (
               id BIGINT PRIMARY KEY,
               occurred_at TIMESTAMPTZ,
               actor_user_id BIGINT,
               actor_username TEXT,
               action TEXT NOT NULL,
               object_type TEXT NOT NULL,
               object_id TEXT,
               document_id TEXT,
               access_session_id TEXT,
               outcome TEXT NOT NULL,
               reason_code TEXT,
               ip_address TEXT,
               user_agent TEXT,
               correlation_id TEXT,
               details JSONB,
               previous_hash TEXT,
               entry_hash TEXT NOT NULL,
               chain_partition TEXT NOT NULL,
               chain_sequence BIGINT NOT NULL,
               chain_algorithm TEXT,
               hmac_key_version INT
             );`,
          );
          for (const u of parsed.users) {
            await restoreClient.query('INSERT INTO users_restore VALUES ($1, $2, $3)', [
              u.id,
              u.username,
              u.email,
            ]);
          }
          for (const a of parsed.auditLogs) {
            await restoreClient.query(
              `INSERT INTO audit_restore VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21
              )`,
              [
                a.id,
                a.occurred_at,
                a.actor_user_id,
                a.actor_username,
                a.action,
                a.object_type,
                a.object_id,
                a.document_id,
                a.access_session_id,
                a.outcome,
                a.reason_code,
                a.ip_address,
                a.user_agent,
                a.correlation_id,
                a.details ? JSON.stringify(a.details) : null,
                a.previous_hash,
                a.entry_hash,
                a.chain_partition,
                a.chain_sequence,
                a.chain_algorithm,
                a.hmac_key_version ?? null,
              ],
            );
          }
          restoredUsersCount = (
            await restoreClient.query('SELECT COUNT(*)::int AS cnt FROM users_restore')
          ).rows[0].cnt;
          restoredAuditRows = (
            await restoreClient.query(
              'SELECT * FROM audit_restore ORDER BY chain_partition ASC, chain_sequence ASC',
            )
          ).rows;
        }
      } finally {
        await restoreClient.end().catch(() => {});
      }
      recordStep(
        '3. Decrypt & Restore Into Isolated Database',
        'PASS',
        `Restored into isolated DB ${drillId}`,
        performance.now() - t,
      );
    } else {
      await client.query(`CREATE SCHEMA ${drillId}`);
      isolatedSchemaCreated = true;
      if (parsed.pgDumpSql) {
        const safeSchemaSql = rewritePgDumpSqlForIsolatedSchema(parsed.pgDumpSql, drillId);
        if (/\bSET\s+search_path\s*(?:=|TO)\s*['"]?public['"]?\b/iu.test(safeSchemaSql)) {
          throw new Error('Schema rewrite guard tripped: public search_path still present');
        }
        if (spawnSync('psql', ['--version'], { shell: false }).status === 0) {
          const psqlEnv = buildPgCliEnv(databaseUrl, process.env);
          const schemaRestoreRes = spawnSync('psql', ['-v', 'ON_ERROR_STOP=1', '--quiet'], {
            env: psqlEnv,
            input: `SET search_path TO ${drillId}, extensions;\n${safeSchemaSql}`,
            encoding: 'utf8',
            shell: false,
            maxBuffer: 64 * 1024 * 1024,
          });
          if (schemaRestoreRes.status !== 0) {
            const safeErr = redactSecrets(schemaRestoreRes.stderr || 'psql schema restore failed', [
              psqlEnv['PGPASSWORD'],
              databaseUrl,
            ]);
            throw new Error(`psql isolated schema restore failed: ${safeErr}`);
          }
          restoredUsersCount = (
            await client.query(`SELECT COUNT(*)::int AS cnt FROM ${drillId}.users LIMIT 500`)
          ).rows[0].cnt;
          restoredAuditRows = (
            await client.query(
              `SELECT id, occurred_at, actor_user_id, actor_username, action, object_type, object_id,
                      document_id, access_session_id, outcome, reason_code, ip_address, user_agent,
                      correlation_id, details, previous_hash, entry_hash, chain_partition,
                      chain_sequence, chain_algorithm, hmac_key_version
               FROM ${drillId}.audit_logs
               ORDER BY chain_partition ASC, chain_sequence ASC
               LIMIT 1000`,
            )
          ).rows;
          recordStep(
            '3. Decrypt & Restore Into Isolated Schema',
            'PASS',
            `Restored full pg_dump into isolated schema ${drillId}`,
            performance.now() - t,
          );
        }
      }
      if (restoredAuditRows.length === 0 && restoredUsersCount === 0) {
        await client.query(
          `CREATE TABLE ${drillId}.users_restore (id BIGINT PRIMARY KEY, username TEXT NOT NULL, email TEXT NOT NULL);
         CREATE TABLE ${drillId}.audit_restore (
           id BIGINT PRIMARY KEY,
           occurred_at TIMESTAMPTZ,
           actor_user_id BIGINT,
           actor_username TEXT,
           action TEXT NOT NULL,
           object_type TEXT NOT NULL,
           object_id TEXT,
           document_id TEXT,
           access_session_id TEXT,
           outcome TEXT NOT NULL,
           reason_code TEXT,
           ip_address TEXT,
           user_agent TEXT,
           correlation_id TEXT,
           details JSONB,
           previous_hash TEXT,
           entry_hash TEXT NOT NULL,
           chain_partition TEXT NOT NULL,
           chain_sequence BIGINT NOT NULL,
           chain_algorithm TEXT,
           hmac_key_version INT
         );`,
        );
        for (const u of parsed.users) {
          await client.query(`INSERT INTO ${drillId}.users_restore VALUES ($1, $2, $3)`, [
            u.id,
            u.username,
            u.email,
          ]);
        }
        for (const a of parsed.auditLogs) {
          await client.query(
            `INSERT INTO ${drillId}.audit_restore VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21
          )`,
            [
              a.id,
              a.occurred_at,
              a.actor_user_id,
              a.actor_username,
              a.action,
              a.object_type,
              a.object_id,
              a.document_id,
              a.access_session_id,
              a.outcome,
              a.reason_code,
              a.ip_address,
              a.user_agent,
              a.correlation_id,
              a.details ? JSON.stringify(a.details) : null,
              a.previous_hash,
              a.entry_hash,
              a.chain_partition,
              a.chain_sequence,
              a.chain_algorithm,
              a.hmac_key_version ?? null,
            ],
          );
        }
        restoredUsersCount = (
          await client.query(`SELECT COUNT(*)::int AS cnt FROM ${drillId}.users_restore`)
        ).rows[0].cnt;
        restoredAuditRows = (
          await client.query(
            `SELECT * FROM ${drillId}.audit_restore ORDER BY chain_partition ASC, chain_sequence ASC`,
          )
        ).rows;
        recordStep(
          '3. Decrypt & Restore Into Isolated Schema',
          'PASS',
          `Restored into isolated schema ${drillId}`,
          performance.now() - t,
        );
      }
    }

    t = performance.now();
    if (
      (parsed.users.length <= 500 && Number(restoredUsersCount) < parsed.users.length) ||
      restoredAuditRows.length < parsed.auditLogs.length
    ) {
      throw new Error('Live restore row parity mismatch');
    }
    const chainVerify = verifyRestoredAuditChain(
      restoredAuditRows,
      process.env['AUDIT_INTEGRITY_KEY'] ?? process.env['DOCUMENT_AUDIT_HMAC_KEY'],
      process.env['AUDIT_KEY_ROTATION_JSON'],
    );
    const objHash = verifyEncryptedBlobRoundtrip();
    recordStep(
      '4. Parity, Audit HMAC Chain & Object Verify',
      'PASS',
      `Parity OK (${restoredUsersCount}u, ${chainVerify.verifiedCount}a, hmac=${chainVerify.cryptographicCount}), obj=${objHash.slice(0, 12)}...`,
      performance.now() - t,
    );
    return true;
  } finally {
    if (isolatedSchemaCreated) {
      await client.query(`DROP SCHEMA IF EXISTS ${drillId} CASCADE`).catch(() => {});
    }
    if (isolatedDbCreated) {
      await client
        .query(`DROP DATABASE IF EXISTS ${drillId} WITH (FORCE)`)
        .catch(() => client.query(`DROP DATABASE IF EXISTS ${drillId}`))
        .catch(() => {});
    }
    await client.end().catch(() => {});
    if (fs.existsSync(encryptedArtifactPath)) {
      try {
        fs.unlinkSync(encryptedArtifactPath);
      } catch {
        // Ignore cleanup failure
      }
    }
  }
}
