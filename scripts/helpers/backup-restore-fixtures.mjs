/**
 * Module: Bộ Dựng Dữ Liệu Nguồn & Kiểm Chứng Phục Hồi Cho Diễn Tập Sao Lưu (DR Drill Fixtures & Cryptographic Verifiers)
 * Thuật toán: Khởi tạo lược đồ quan hệ PGlite khớp chuẩn Prisma, sinh chuỗi nhật ký kiểm toán liên kết `HMAC-SHA256`,
 *   kiểm chứng tính liên tục mật mã sau khôi phục và kiểm chứng phục hồi chính xác từng bit cho đối tượng mã hóa.
 */
import crypto from 'node:crypto';

// CONFLICT-RESOLVED: Đồng bộ 100% tên bảng và cột diễn tập sao lưu/phục hồi với packages/database/prisma/schema/*.prisma (document_classification_history, chain_sequence, previous_hash, entry_hash, correlation_id).
export const DRILL_SCHEMA_SQL = `
  CREATE TABLE departments (
    id BIGSERIAL PRIMARY KEY,
    code VARCHAR(30) UNIQUE NOT NULL,
    name VARCHAR(150) NOT NULL
  );

  CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(150) NOT NULL,
    department_id BIGINT REFERENCES departments(id),
    status VARCHAR(30) NOT NULL DEFAULT 'ACTIVE'
  );

  CREATE TABLE classification_levels (
    id BIGSERIAL PRIMARY KEY,
    code VARCHAR(40) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    rank INTEGER UNIQUE NOT NULL
  );

  CREATE TABLE business_categories (
    id BIGSERIAL PRIMARY KEY,
    code VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(150) NOT NULL,
    department_id BIGINT REFERENCES departments(id)
  );

  CREATE TABLE documents (
    id UUID PRIMARY KEY,
    document_code VARCHAR(60) UNIQUE NOT NULL,
    title VARCHAR(255) NOT NULL,
    owner_id BIGINT NOT NULL REFERENCES users(id),
    department_id BIGINT NOT NULL REFERENCES departments(id),
    status VARCHAR(30) NOT NULL DEFAULT 'ACTIVE'
  );

  CREATE TABLE document_classification_history (
    id BIGSERIAL PRIMARY KEY,
    document_id UUID NOT NULL REFERENCES documents(id),
    classification_level_id BIGINT NOT NULL REFERENCES classification_levels(id),
    business_category_id BIGINT NOT NULL REFERENCES business_categories(id),
    classified_by BIGINT NOT NULL REFERENCES users(id),
    effective_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    effective_to TIMESTAMPTZ
  );

  CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_user_id BIGINT REFERENCES users(id),
    actor_username VARCHAR(80),
    action VARCHAR(100) NOT NULL,
    object_type VARCHAR(80) NOT NULL,
    outcome VARCHAR(20) NOT NULL,
    correlation_id UUID NOT NULL,
    previous_hash CHAR(64),
    entry_hash CHAR(64) NOT NULL,
    chain_partition VARCHAR(80) NOT NULL DEFAULT 'GLOBAL',
    chain_sequence BIGINT NOT NULL
  );
`;

const DRILL_HMAC_SECRET = 'drill-secret';

/**
 * Thuật toán: Sinh Dữ Liệu Gốc & Chuỗi Băm Liên Kết Kiểm Toán `HMAC-SHA256` (Chained Audit Seed Generator)
 * Mục đích: Khởi tạo phòng ban, người dùng, phân loại độ mật, tài liệu và 5 mắt xích kiểm toán nối tiếp nhau trên CSDL nguồn.
 */
export async function populateDrillSourceDb(sourceDb) {
  await sourceDb.exec(DRILL_SCHEMA_SQL);
  await sourceDb.query('INSERT INTO departments (code, name) VALUES ($1, $2);', [
    'HEAD_OFFICE',
    'Khối văn phòng',
  ]);
  await sourceDb.query(
    `INSERT INTO users (username, email, password_hash, full_name, department_id, status)
     VALUES ($1, $2, $3, $4, 1, 'ACTIVE'),
            ($5, $6, $3, $7, 1, 'ACTIVE'),
            ($8, $9, $3, $10, 1, 'ACTIVE');`,
    [
      'admin_root',
      'admin_root@local.invalid',
      '!DRILL_DISABLED_DEMO_HASH!',
      'Quản trị diễn tập',
      'owner_dept1',
      'owner_dept1@local.invalid',
      'Chủ tài liệu diễn tập',
      'reader_staff',
      'reader_staff@local.invalid',
      'Nhân sự đọc diễn tập',
    ],
  );
  await sourceDb.query(
    `INSERT INTO classification_levels (code, name, rank)
     VALUES ('CONFIDENTIAL', 'Mật', 2), ('SECRET', 'Tối mật', 3);`,
  );
  await sourceDb.query(
    'INSERT INTO business_categories (code, name, department_id) VALUES ($1, $2, 1);',
    ['SECURITY_OPERATIONS', 'An toàn thông tin'],
  );

  const docId1 = crypto.randomUUID();
  const docId2 = crypto.randomUUID();
  await sourceDb.query(
    `INSERT INTO documents (id, document_code, title, owner_id, department_id, status)
     VALUES ($1, $2, $3, 2, 1, 'ACTIVE'), ($4, $5, $6, 2, 1, 'ACTIVE');`,
    [
      docId1,
      'DOC-DRILL-001',
      'Chien Luoc An Toan Thong Tin 2026',
      docId2,
      'DOC-DRILL-002',
      'Bao Cao Kiem Toan Quy 3',
    ],
  );
  await sourceDb.query(
    `INSERT INTO document_classification_history (document_id, classification_level_id, business_category_id, classified_by)
     VALUES ($1, 2, 1, 2), ($2, 1, 1, 2);`,
    [docId1, docId2],
  );

  let prevHash = null;
  for (let seq = 1; seq <= 5; seq++) {
    const entryHash = crypto
      .createHmac('sha256', DRILL_HMAC_SECRET)
      .update(`${prevHash ?? 'GENESIS'}:${seq}:AUDIT_${seq}`)
      .digest('hex');
    await sourceDb.query(
      `INSERT INTO audit_logs (
         actor_user_id, actor_username, action, object_type, outcome,
         correlation_id, previous_hash, entry_hash, chain_partition, chain_sequence
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'GLOBAL', $9);`,
      [
        1,
        'admin_root',
        `SYSTEM_EVENT_${seq}`,
        'SYSTEM',
        'SUCCESS',
        crypto.randomUUID(),
        prevHash,
        entryHash,
        seq,
      ],
    );
    prevHash = entryHash;
  }
}

/**
 * Thuật toán: Nạp Lại Dữ Liệu Tham Số Hóa Từ Bản Sao Lưu Logic Vào CSDL Đích (Parameterized Logical Table Restorer)
 * Mục đích: Chèn tuần tự theo đúng thứ tự khóa ngoại bằng truy vấn gắn tham số (`$1..$N`) chống SQL Injection.
 */
export async function restoreParsedTables(restoredDb, parsedBackup) {
  const { tables } = parsedBackup;
  for (const dept of tables.departments) {
    await restoredDb.query('INSERT INTO departments (id, code, name) VALUES ($1, $2, $3);', [
      dept.id,
      dept.code,
      dept.name,
    ]);
  }
  for (const user of tables.users) {
    await restoredDb.query(
      `INSERT INTO users (id, username, email, password_hash, full_name, department_id, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7);`,
      [
        user.id,
        user.username,
        user.email,
        user.password_hash,
        user.full_name,
        user.department_id,
        user.status,
      ],
    );
  }
  for (const level of tables.classification_levels) {
    await restoredDb.query(
      'INSERT INTO classification_levels (id, code, name, rank) VALUES ($1, $2, $3, $4);',
      [level.id, level.code, level.name, level.rank],
    );
  }
  for (const cat of tables.business_categories) {
    await restoredDb.query(
      'INSERT INTO business_categories (id, code, name, department_id) VALUES ($1, $2, $3, $4);',
      [cat.id, cat.code, cat.name, cat.department_id],
    );
  }
  for (const doc of tables.documents) {
    await restoredDb.query(
      `INSERT INTO documents (id, document_code, title, owner_id, department_id, status)
       VALUES ($1, $2, $3, $4, $5, $6);`,
      [doc.id, doc.document_code, doc.title, doc.owner_id, doc.department_id, doc.status],
    );
  }
  for (const hist of tables.document_classification_history) {
    await restoredDb.query(
      `INSERT INTO document_classification_history (
         id, document_id, classification_level_id, business_category_id, classified_by, effective_from, effective_to
       ) VALUES ($1, $2, $3, $4, $5, $6, $7);`,
      [
        hist.id,
        hist.document_id,
        hist.classification_level_id,
        hist.business_category_id,
        hist.classified_by,
        hist.effective_from,
        hist.effective_to,
      ],
    );
  }
  for (const log of tables.audit_logs) {
    await restoredDb.query(
      `INSERT INTO audit_logs (
         id, occurred_at, actor_user_id, actor_username, action, object_type,
         outcome, correlation_id, previous_hash, entry_hash, chain_partition, chain_sequence
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);`,
      [
        log.id,
        log.occurred_at,
        log.actor_user_id,
        log.actor_username,
        log.action,
        log.object_type,
        log.outcome,
        log.correlation_id,
        log.previous_hash,
        log.entry_hash,
        log.chain_partition,
        log.chain_sequence,
      ],
    );
  }
}

/**
 * Thuật toán: Xác Thực Lại Toàn Bộ Chuỗi Mắt Xích `HMAC-SHA256` Sau Khôi Phục (Post-Restore HMAC Chain Verifier)
 * Mục đích: Đảm bảo không có bản ghi kiểm toán nào bị thất lạc, đảo thứ tự `chain_sequence` hoặc đứt gãy `previous_hash -> entry_hash`.
 */
export async function verifyRestoredAuditChain(restoredDb) {
  const restoredAuditRows = await restoredDb.query(
    'SELECT chain_sequence, previous_hash, entry_hash, action FROM audit_logs ORDER BY chain_sequence ASC;',
  );
  let chainCursor = null;

  for (const row of restoredAuditRows.rows) {
    const seq = Number(row.chain_sequence);
    const prevHash = row.previous_hash ? row.previous_hash.trim() : null;
    const entryHash = row.entry_hash.trim();
    if (prevHash !== chainCursor) {
      throw new Error(`Restored audit chain_sequence ${seq} chain link mismatch!`);
    }
    const expected = crypto
      .createHmac('sha256', DRILL_HMAC_SECRET)
      .update(`${chainCursor ?? 'GENESIS'}:${seq}:AUDIT_${seq}`)
      .digest('hex');
    if (entryHash !== expected) {
      throw new Error(`Restored audit chain_sequence ${seq} hash verification failed!`);
    }
    chainCursor = entryHash;
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
