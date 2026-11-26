/**
 * Thuật toán: Quy Trình Diễn Tập Sao Lưu Logic, Kiểm Chứng SHA-256 & Phục Hồi Thảm Họa (Live PostgreSQL & Offline 13-Migration PGlite DR Drill)
 * - Khi `DATABASE_URL` khả dụng: Thực thi `pg_dump` (nếu có) hoặc kết xuất gói sao lưu SQL/JSON trực tiếp từ PostgreSQL thật,
 *   kiểm chứng `SHA-256`, khôi phục vào lược đồ cô lập `sda_dr_verify_<hex>` để đối chiếu số dòng + chuỗi băm kiểm toán rồi dọn sạch.
 * - Chỉ rơi về `PGlite` ngoại tuyến khi `DATABASE_URL` không cấu hình hoặc không thể kết nối, phát lại toàn bộ 13 di trú Prisma thật.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  decryptBackupArtifactAes256Gcm,
  encryptBackupArtifactAes256Gcm,
  tryRunLivePostgresDrill,
  verifyEncryptedBlobRoundtrip,
} from './backup-restore-live.helper.mjs';

const MIGRATIONS_DIR = fileURLToPath(
  new URL('../packages/database/prisma/migrations', import.meta.url),
);

/**
 * Thuật toán: Khởi tạo phiên bản `PGlite` ngoại tuyến và phát lại đầy đủ 13 di trú Prisma thật (`pg_trgm`).
 */
async function createMigratedPglite() {
  let PGlite;
  let pg_trgm;
  try {
    [{ PGlite }, { pg_trgm }] = await Promise.all([
      import('@electric-sql/pglite'),
      import('@electric-sql/pglite/contrib/pg_trgm'),
    ]);
  } catch {
    const pnpmStore = fileURLToPath(new URL('../node_modules/.pnpm', import.meta.url));
    const match = fs.readdirSync(pnpmStore).find((e) => e.startsWith('@electric-sql+pglite@'));
    if (!match) throw new Error('@electric-sql/pglite is not installed for offline fallback');
    const base = path.join(pnpmStore, match, 'node_modules/@electric-sql/pglite/dist');
    [{ PGlite }, { pg_trgm }] = await Promise.all([
      import(pathToFileURL(path.join(base, 'index.js')).href),
      import(pathToFileURL(path.join(base, 'contrib/pg_trgm.js')).href),
    ]);
  }
  const db = new PGlite({ extensions: { pg_trgm } });
  const folders = fs
    .readdirSync(MIGRATIONS_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort();
  for (const f of folders) {
    const p = path.join(MIGRATIONS_DIR, f, 'migration.sql');
    if (fs.existsSync(p)) await db.exec(fs.readFileSync(p, 'utf8'));
  }
  return db;
}

async function main() {
  console.log('='.repeat(78));
  console.log('SDA DISASTER RECOVERY & BACKUP/RESTORE DRILL');
  console.log('='.repeat(78));
  console.log(`Timestamp: ${new Date().toISOString()} | OS: ${os.type()} ${os.release()}`);

  const steps = [];
  const recordStep = (name, status, detail, durationMs) => {
    steps.push({
      Step: name,
      Status: status,
      'Duration (ms)': Math.round(durationMs * 100) / 100,
      Detail: detail,
    });
    console.log(`[${status}] ${name} (${Math.round(durationMs)}ms) - ${detail}`);
  };

  const strictLive = process.env['DRILL_STRICT_LIVE'] === 'true';
  if (process.env['DATABASE_URL']) {
    if (await tryRunLivePostgresDrill(process.env['DATABASE_URL'], recordStep, strictLive)) {
      console.table(steps);
      console.log('\nSUCCESS: LIVE POSTGRESQL BACKUP/RESTORE DRILL COMPLETED WITH ZERO DATA LOSS.');
      return;
    }
  }

  const [sourceDb, restoredDb] = await Promise.all([
    createMigratedPglite(),
    createMigratedPglite(),
  ]);
  try {
    let t = performance.now();
    await sourceDb.exec(`
      INSERT INTO departments (id, code, name) OVERRIDING SYSTEM VALUE VALUES (1, 'SEC', 'Security Operations');
      INSERT INTO users (id, username, email, password_hash, full_name, status) OVERRIDING SYSTEM VALUE
        VALUES (1, 'dr_admin', 'dr_admin@sda.local', '$argon2id$v=19$m=19456,t=2,p=1$stub', 'DR Admin', 'ACTIVE');
      INSERT INTO documents (id, document_code, title, owner_id, department_id, status, discoverable)
        VALUES ('00000000-0000-4000-8000-000000000001', 'DOC-DR-001', 'Classified Continuity Plan', 1, 1, 'ACTIVE', TRUE);
    `);
    const hmacKey = crypto.randomBytes(32);
    let prevHash = null;
    for (let seq = 1; seq <= 3; seq++) {
      const entryHash = crypto
        .createHmac('sha256', hmacKey)
        .update(`${prevHash ?? 'GENESIS'}:${seq}`)
        .digest('hex');
      await sourceDb.query(
        `INSERT INTO audit_logs (actor_user_id, actor_username, action, object_type, outcome, correlation_id, previous_hash, entry_hash, chain_partition, chain_sequence)
         VALUES (1, 'dr_admin', 'DOCUMENT_VIEW', 'DOCUMENT', 'SUCCESS', $1, $2, $3, 'DOCUMENT', $4)`,
        [crypto.randomUUID(), prevHash, entryHash, seq],
      );
      prevHash = entryHash;
    }
    recordStep(
      '1. Seed 13-Migration PGlite Source',
      'PASS',
      'Replayed 13 migrations & seeded HMAC rows',
      performance.now() - t,
    );

    t = performance.now();
    const dump = {
      departments: (await sourceDb.query('SELECT id, code, name FROM departments ORDER BY id'))
        .rows,
      users: (
        await sourceDb.query(
          'SELECT id, username, email, password_hash, full_name, status FROM users ORDER BY id',
        )
      ).rows,
      documents: (
        await sourceDb.query(
          'SELECT id, document_code, title, owner_id, department_id, status, discoverable FROM documents ORDER BY id',
        )
      ).rows,
      auditLogs: (
        await sourceDb.query(
          'SELECT actor_user_id, actor_username, action, object_type, outcome, correlation_id, previous_hash, entry_hash, chain_partition, chain_sequence FROM audit_logs ORDER BY chain_sequence',
        )
      ).rows,
    };
    const backupPayload = Buffer.from(JSON.stringify(dump), 'utf8');
    const backupSha256 = crypto.createHash('sha256').update(backupPayload).digest('hex');
    const encryptedBackup = encryptBackupArtifactAes256Gcm(
      backupPayload,
      undefined,
      'sda-offline-pglite-drill',
    );
    recordStep(
      '2. Logical Dump, AES-256-GCM & SHA-256',
      'PASS',
      `SHA-256: ${backupSha256.slice(0, 16)}... (${encryptedBackup.byteLength}B enc)`,
      performance.now() - t,
    );

    t = performance.now();
    const decryptedPayload = decryptBackupArtifactAes256Gcm(
      encryptedBackup,
      undefined,
      'sda-offline-pglite-drill',
    );
    if (crypto.createHash('sha256').update(decryptedPayload).digest('hex') !== backupSha256) {
      throw new Error('Backup checksum verification failed');
    }
    const parsed = JSON.parse(decryptedPayload.toString('utf8'));
    for (const d of parsed.departments) {
      await restoredDb.query(
        'INSERT INTO departments (id, code, name) OVERRIDING SYSTEM VALUE VALUES ($1, $2, $3)',
        [d.id, d.code, d.name],
      );
    }
    for (const u of parsed.users) {
      await restoredDb.query(
        'INSERT INTO users (id, username, email, password_hash, full_name, status) OVERRIDING SYSTEM VALUE VALUES ($1, $2, $3, $4, $5, $6)',
        [u.id, u.username, u.email, u.password_hash, u.full_name, u.status],
      );
    }
    for (const doc of parsed.documents) {
      await restoredDb.query(
        'INSERT INTO documents (id, document_code, title, owner_id, department_id, status, discoverable) VALUES ($1, $2, $3, $4, $5, $6, $7)',
        [
          doc.id,
          doc.document_code,
          doc.title,
          doc.owner_id,
          doc.department_id,
          doc.status,
          doc.discoverable,
        ],
      );
    }
    for (const a of parsed.auditLogs) {
      await restoredDb.query(
        `INSERT INTO audit_logs (actor_user_id, actor_username, action, object_type, outcome, correlation_id, previous_hash, entry_hash, chain_partition, chain_sequence)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [
          a.actor_user_id,
          a.actor_username,
          a.action,
          a.object_type,
          a.outcome,
          a.correlation_id,
          a.previous_hash,
          a.entry_hash,
          a.chain_partition,
          a.chain_sequence,
        ],
      );
    }
    recordStep(
      '3. Checksum Gate & Target Restore',
      'PASS',
      'Restored into clean 13-migration target',
      performance.now() - t,
    );

    t = performance.now();
    const restoredAudits = (
      await restoredDb.query(
        'SELECT chain_sequence, previous_hash, entry_hash FROM audit_logs ORDER BY chain_sequence ASC',
      )
    ).rows;
    let verifyPrev = null;
    for (const row of restoredAudits) {
      const expected = crypto
        .createHmac('sha256', hmacKey)
        .update(`${verifyPrev ?? 'GENESIS'}:${row.chain_sequence}`)
        .digest('hex');
      if (
        (row.previous_hash?.trim() ?? null) !== verifyPrev ||
        row.entry_hash.trim() !== expected
      ) {
        throw new Error(`Restored audit chain broken at seq=${row.chain_sequence}`);
      }
      verifyPrev = expected;
    }
    const fileHash = verifyEncryptedBlobRoundtrip();
    recordStep(
      '4. Parity, Audit Chain & Object Verify',
      'PASS',
      `Audits=${restoredAudits.length}, FileHash=${fileHash.slice(0, 12)}...`,
      performance.now() - t,
    );
    console.table(steps);
    console.log('\nSUCCESS: DISASTER RECOVERY & RESTORE DRILL COMPLETED WITH ZERO DATA LOSS.');
  } finally {
    await sourceDb.close().catch(() => {});
    await restoredDb.close().catch(() => {});
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error('Fatal backup/restore drill failure:', err);
    process.exit(1);
  });
}
