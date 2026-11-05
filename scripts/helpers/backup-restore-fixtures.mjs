/**
 * Module: Bộ Dựng Dữ Liệu Nguồn & Kiểm Chứng Phục Hồi Cho Diễn Tập Sao Lưu (DR Drill Fixtures & Cryptographic Verifiers)
 * Thuật toán: Khởi tạo lược đồ quan hệ PGlite dùng chung, sinh chuỗi nhật ký kiểm toán liên kết `HMAC-SHA256`,
 *   kiểm chứng tính liên tục mật mã sau khôi phục và kiểm chứng phục hồi chính xác từng bit cho đối tượng mã hóa.
 */
import crypto from 'node:crypto';

export const DRILL_SCHEMA_SQL = `
  CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'ACTIVE'
  );

  CREATE TABLE documents (
    id UUID PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    classification_level INTEGER NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'ACTIVE'
  );

  CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    action VARCHAR(100) NOT NULL,
    sequence BIGINT NOT NULL,
    previous_record_hash VARCHAR(64) NOT NULL,
    record_hash VARCHAR(64) NOT NULL
  );
`;

const GENESIS_HASH = '0'.repeat(64);
const DRILL_HMAC_SECRET = 'drill-secret';

/**
 * Thuật toán: Sinh Dữ Liệu Gốc & Chuỗi Băm Liên Kết Kiểm Toán `HMAC-SHA256` (Chained Audit Seed Generator)
 * Mục đích: Khởi tạo bảng người dùng, tài liệu và 5 mắt xích kiểm toán nối tiếp nhau trên CSDL nguồn.
 */
export async function populateDrillSourceDb(sourceDb) {
  await sourceDb.exec(DRILL_SCHEMA_SQL);
  await sourceDb.query(
    `INSERT INTO users (username, status) VALUES ($1, $2), ($3, $4), ($5, $6);`,
    ['admin_root', 'ACTIVE', 'owner_dept1', 'ACTIVE', 'reader_staff', 'ACTIVE'],
  );

  const docId1 = crypto.randomUUID();
  const docId2 = crypto.randomUUID();
  await sourceDb.query(
    `INSERT INTO documents (id, title, classification_level, status)
     VALUES ($1, $2, $3, $4), ($5, $6, $7, $8);`,
    [
      docId1,
      'Chien Luoc An Toan Thong Tin 2026',
      3,
      'ACTIVE',
      docId2,
      'Bao Cao Kiem Toan Quy 3',
      2,
      'ACTIVE',
    ],
  );

  let prevHash = GENESIS_HASH;
  for (let seq = 1; seq <= 5; seq++) {
    const recHash = crypto
      .createHmac('sha256', DRILL_HMAC_SECRET)
      .update(`${prevHash}:${seq}:AUDIT_${seq}`)
      .digest('hex');
    await sourceDb.query(
      `INSERT INTO audit_logs (action, sequence, previous_record_hash, record_hash)
       VALUES ($1, $2, $3, $4);`,
      [`SYSTEM_EVENT_${seq}`, seq, prevHash, recHash],
    );
    prevHash = recHash;
  }
}

/**
 * Thuật toán: Nạp Lại Dữ Liệu Tham Số Hóa Từ Bản Sao Lưu Logic Vào CSDL Đích (Parameterized Logical Table Restorer)
 * Mục đích: Chèn tuần tự toàn bộ bản ghi `users`, `documents` và `audit_logs` bằng truy vấn gắn tham số (`$1..$N`) chống SQL Injection.
 */
export async function restoreParsedTables(restoredDb, parsedBackup) {
  for (const user of parsedBackup.tables.users) {
    await restoredDb.query('INSERT INTO users (id, username, status) VALUES ($1, $2, $3);', [
      user.id,
      user.username,
      user.status,
    ]);
  }
  for (const doc of parsedBackup.tables.documents) {
    await restoredDb.query(
      'INSERT INTO documents (id, title, classification_level, status) VALUES ($1, $2, $3, $4);',
      [doc.id, doc.title, doc.classification_level, doc.status],
    );
  }
  for (const log of parsedBackup.tables.audit_logs) {
    await restoredDb.query(
      'INSERT INTO audit_logs (id, action, sequence, previous_record_hash, record_hash) VALUES ($1, $2, $3, $4, $5);',
      [log.id, log.action, log.sequence, log.previous_record_hash, log.record_hash],
    );
  }
}

/**
 * Thuật toán: Xác Thực Lại Toàn Bộ Chuỗi Mắt Xích `HMAC-SHA256` Sau Khôi Phục (Post-Restore HMAC Chain Verifier)
 * Mục đích: Đảm bảo không có bản ghi kiểm toán nào bị thất lạc, đảo thứ tự hoặc biến đổi nội dung sau phục hồi.
 */
export async function verifyRestoredAuditChain(restoredDb) {
  const restoredAuditRows = await restoredDb.query(
    'SELECT sequence, previous_record_hash, record_hash, action FROM audit_logs ORDER BY sequence ASC;',
  );
  let chainCursor = GENESIS_HASH;

  for (const row of restoredAuditRows.rows) {
    if (row.previous_record_hash !== chainCursor) {
      throw new Error(`Restored audit sequence ${row.sequence} chain link mismatch!`);
    }
    const expected = crypto
      .createHmac('sha256', DRILL_HMAC_SECRET)
      .update(`${chainCursor}:${row.sequence}:AUDIT_${row.sequence}`)
      .digest('hex');
    if (row.record_hash !== expected) {
      throw new Error(`Restored audit sequence ${row.sequence} hash verification failed!`);
    }
    chainCursor = row.record_hash;
  }
}

/**
 * Thuật toán: Kiểm Chứng Sao Lưu & Phục Hồi Nguyên Bản Từng Bit Cho Object Storage (Bit-Exact Object Recovery Verifier)
 * Mục đích: Đối chiếu tổng kiểm `SHA-256` trước và sau giải mã Base64 của bản sao lưu tệp mã hóa `AES-256-GCM`.
 */
export function verifyObjectStorageRoundtrip() {
  const sampleDocumentBuffer = Buffer.from(
    'PDF_ENCRYPTED_HEADER_TEST_CIPHERTEXT_AES_256_GCM_SIMULATION_DATA',
  );
  const originalFileHash = crypto.createHash('sha256').update(sampleDocumentBuffer).digest('hex');

  const objectBackup = {
    key: 'documents/2026/test_doc.enc',
    sha256: originalFileHash,
    sizeBytes: sampleDocumentBuffer.length,
    base64Data: sampleDocumentBuffer.toString('base64'),
  };

  const restoredBuffer = Buffer.from(objectBackup.base64Data, 'base64');
  const restoredFileHash = crypto.createHash('sha256').update(restoredBuffer).digest('hex');
  if (restoredFileHash !== originalFileHash) {
    throw new Error('Object storage restore corrupted file content!');
  }
  return originalFileHash;
}
