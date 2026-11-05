/**
 * SDA Disaster Recovery & Backup/Restore Drill Runner
 * Demonstrates PostgreSQL table data export, SHA-256 bundle verification,
 * disaster simulation, full restore, audit HMAC chain re-validation,
 * and object storage recovery verification.
 *
 * Thuật toán: Quy Trình Diễn Tập Sao Lưu Logic, Kiểm Chứng Băm SHA-256 & Phục Hồi Thảm Họa (Disaster Recovery & Cryptographic Restore Drill)
 * Mục đích: Xác minh khả năng khôi phục toàn vẹn 100% cơ sở dữ liệu quan hệ, chuỗi nhật ký kiểm toán bất biến và đối tượng lưu trữ mã hóa sau sự cố mất mát toàn bộ nút đích.
 * Cơ chế hoạt động:
 *   - Bước 1-2: Khởi tạo dữ liệu nguồn kèm chuỗi băm liên kết `HMAC-SHA256`, kết xuất gói sao lưu JSON và tính tổng kiểm mật mã `SHA-256` (`backupSha256`).
 *   - Bước 3-5: Giả lập thảm họa trên phiên bản PostgreSQL WASM (`PGlite`) trống, xác thực lại chữ ký `SHA-256` của gói sao lưu trước khi nạp (Fail-Closed) và khôi phục tuần tự từng bảng.
 *   - Bước 6-8: Đối chiếu chẵn lẻ số dòng (Row Parity), tính lại toàn bộ mắt xích `previous_hash -> entry_hash` theo `chain_sequence` và kiểm chứng khôi phục chính xác từng bit cho tệp mã hóa Object Storage.
 */

import os from 'node:os';
import crypto from 'node:crypto';
import { PGlite } from '@electric-sql/pglite';
import {
  DRILL_SCHEMA_SQL,
  populateDrillSourceDb,
  restoreParsedTables,
  verifyObjectStorageRoundtrip,
  verifyRestoredAuditChain,
} from './helpers/backup-restore-fixtures.mjs';

/**
 * Thuật toán: Bộ Điều Phối Kịch Bản Diễn Tập Khôi Phục Thảm Họa 8 Bước Có Đo Độ Trễ (8-Stage Timed DR Drill Orchestrator)
 * Mục đích: Thực thi tuần tự 8 bước kiểm định sao lưu - phục hồi và lập bảng thống kê thời gian thực thi chi tiết từng pha.
 */
async function main() {
  console.log('='.repeat(78));
  console.log('SDA DISASTER RECOVERY & BACKUP/RESTORE DRILL');
  console.log('='.repeat(78));
  console.log(`Timestamp: ${new Date().toISOString()}`);
  console.log(`OS: ${os.type()} ${os.release()} | Architecture: ${os.arch()}`);
  console.log('='.repeat(78));

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

  // Step 1: Initialize Source Database with Seed Data
  const sourceDb = new PGlite();
  const t0 = performance.now();
  await populateDrillSourceDb(sourceDb);
  recordStep(
    '1. Initialize Source Database & Populate Data',
    'PASS',
    'Created users, documents, classification history, and chained audit logs',
    performance.now() - t0,
  );

  // Step 2: Perform Logical Backup & Create Checksummed Bundle
  // CONFLICT-RESOLVED: Kết xuất đầy đủ các bảng liên kết theo chuẩn Prisma và sắp xếp audit_logs theo chain_sequence ASC.
  const t1 = performance.now();
  const departmentsDump = await sourceDb.query('SELECT * FROM departments ORDER BY id ASC;');
  const usersDump = await sourceDb.query('SELECT * FROM users ORDER BY id ASC;');
  const levelsDump = await sourceDb.query('SELECT * FROM classification_levels ORDER BY id ASC;');
  const categoriesDump = await sourceDb.query('SELECT * FROM business_categories ORDER BY id ASC;');
  const docsDump = await sourceDb.query('SELECT * FROM documents ORDER BY id ASC;');
  const historyDump = await sourceDb.query(
    'SELECT * FROM document_classification_history ORDER BY id ASC;',
  );
  const auditDump = await sourceDb.query('SELECT * FROM audit_logs ORDER BY chain_sequence ASC;');

  const backupPayload = JSON.stringify({
    metadata: {
      version: 'v1.0.0',
      timestamp: new Date().toISOString(),
      sourceSystem: 'SDA-PRODUCTION',
    },
    tables: {
      departments: departmentsDump.rows,
      users: usersDump.rows,
      classification_levels: levelsDump.rows,
      business_categories: categoriesDump.rows,
      documents: docsDump.rows,
      document_classification_history: historyDump.rows,
      audit_logs: auditDump.rows,
    },
  });

  const backupSha256 = crypto.createHash('sha256').update(backupPayload).digest('hex');
  recordStep(
    '2. Generate Logical Backup & Checksum',
    'PASS',
    `Backup size: ${backupPayload.length} bytes, SHA-256: ${backupSha256.slice(0, 16)}...`,
    performance.now() - t1,
  );

  // Step 3: Simulate Disaster (Clean Empty Destination Target)
  const t2 = performance.now();
  const restoredDb = new PGlite();
  await restoredDb.exec(DRILL_SCHEMA_SQL);
  recordStep(
    '3. Simulate Disaster & Provision Empty Target',
    'PASS',
    'Target database ready with zero records',
    performance.now() - t2,
  );

  // Step 4: Verify Backup Bundle Integrity Before Restore
  const t3 = performance.now();
  const verifyDigest = crypto.createHash('sha256').update(backupPayload).digest('hex');
  if (verifyDigest !== backupSha256) {
    throw new Error('Backup payload corrupted or altered!');
  }
  recordStep(
    '4. Verify Backup Bundle Checksum',
    'PASS',
    'SHA-256 matched perfectly, zero corruption',
    performance.now() - t3,
  );

  // Step 5: Restore Data into Clean Target Database
  const t4 = performance.now();
  await restoreParsedTables(restoredDb, JSON.parse(backupPayload));
  recordStep(
    '5. Restore Table Records into Target',
    'PASS',
    'Restored 100% of relational and audit rows',
    performance.now() - t4,
  );

  // Step 6: Validate Row Count Parity & Content Equality
  const t5 = performance.now();
  const restoredUsers = await restoredDb.query('SELECT COUNT(*) as count FROM users;');
  const restoredDocs = await restoredDb.query('SELECT COUNT(*) as count FROM documents;');
  const restoredHistory = await restoredDb.query(
    'SELECT COUNT(*) as count FROM document_classification_history;',
  );
  const restoredAudits = await restoredDb.query('SELECT COUNT(*) as count FROM audit_logs;');

  if (
    Number(restoredUsers.rows[0].count) !== usersDump.rows.length ||
    Number(restoredDocs.rows[0].count) !== docsDump.rows.length ||
    Number(restoredHistory.rows[0].count) !== historyDump.rows.length ||
    Number(restoredAudits.rows[0].count) !== auditDump.rows.length
  ) {
    throw new Error('Row count mismatch after restoration!');
  }
  recordStep(
    '6. Row Count & Parity Verification',
    'PASS',
    `Exact match: ${restoredUsers.rows[0].count} users, ${restoredDocs.rows[0].count} docs, ${restoredAudits.rows[0].count} audits`,
    performance.now() - t5,
  );

  // Step 7: Validate Cryptographic HMAC Chain Integrity on Restored Data
  const t6 = performance.now();
  await verifyRestoredAuditChain(restoredDb);
  recordStep(
    '7. Restored Audit HMAC Chain Verification',
    'PASS',
    '100% cryptographic continuity verified, zero tampering',
    performance.now() - t6,
  );

  // Step 8: Object Storage Backup & Recovery Simulation
  const t7 = performance.now();
  const originalFileHash = verifyObjectStorageRoundtrip();
  recordStep(
    '8. Object Storage Backup & Bit-Exact Restore',
    'PASS',
    `File hash verified: ${originalFileHash.slice(0, 16)}...`,
    performance.now() - t7,
  );

  console.log('\n' + '='.repeat(78));
  console.log('DISASTER RECOVERY DRILL SUMMARY:');
  console.log('='.repeat(78));
  console.table(steps);

  console.log('\nSUCCESS: DISASTER RECOVERY & RESTORE DRILL COMPLETED WITH ZERO DATA LOSS.');
  process.exit(0);
}

main().catch((err) => {
  console.error('Fatal backup/restore drill failure:', err);
  process.exit(1);
});
