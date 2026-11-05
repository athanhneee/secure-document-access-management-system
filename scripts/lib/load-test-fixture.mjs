/**
 * SDA Enterprise Load Testing Synthetic Database & PDF Fixture Seeder
 * Separated from scenario definitions for Single Responsibility (Rule §3).
 */

import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { PGlite } from '@electric-sql/pglite';

// CONFLICT-RESOLVED: Phân giải pdf-lib qua createRequire neo vào apps/api/package.json thay vì đường dẫn cứng trong node_modules để tương thích kho lưu trữ ảo pnpm.
const require = createRequire(new URL('../../apps/api/package.json', import.meta.url));
const { PDFDocument } = require('pdf-lib');

/**
 * Thuật toán: Chèn Lô Đa Dòng Tham Số Hóa Chống SQL Injection (Parameterized Multi-Row Batch Insert Executor)
 * Mục đích: Khởi tạo danh sách giữ chỗ vị trí `$1..$N` theo lô mà không nội suy giá trị thời gian chạy vào chuỗi SQL.
 */
async function batchInsertParameterized(db, tableName, columns, rows, batchSize = 500) {
  for (let offset = 0; offset < rows.length; offset += batchSize) {
    const chunk = rows.slice(offset, offset + batchSize);
    const params = [];
    const valueTuples = chunk.map((row) => {
      const placeholders = row.map((val) => {
        params.push(val);
        return `$${params.length}`;
      });
      return `(${placeholders.join(', ')})`;
    });
    await db.query(
      `INSERT INTO ${tableName} (${columns.join(', ')}) VALUES ${valueTuples.join(', ')};`,
      params,
    );
  }
}

/**
 * Thuật toán: Khởi Tạo Lược Đồ Chuẩn Prisma & Gieo Lô Dữ Liệu Tải Kết Hợp Chuỗi Băm `HMAC-SHA256`
 * Mục đích: Cấp phát CSDL PGlite trong bộ nhớ khớp 100% tên bảng/cột của Prisma schema (`documents`,
 *   `document_classification_history`, `access_grants`, `audit_logs`), nạp 5.000 tài liệu, quyền truy cập đang hiệu lực,
 *   5.000 bản ghi kiểm toán nối chuỗi băm và tạo mẫu PDF gốc phục vụ đo kiểm hiệu năng.
 */
export async function createAndSeedLoadTestFixture() {
  const db = new PGlite();

  // CONFLICT-RESOLVED: Đồng bộ 100% tên bảng và cột với lược đồ Prisma chuẩn (tách document_classification_history, chuẩn hóa principal_user_id/chain_sequence/previous_hash/entry_hash).
  await db.exec(`
    CREATE TABLE IF NOT EXISTS classification_levels (
      id BIGSERIAL PRIMARY KEY,
      code VARCHAR(40) UNIQUE NOT NULL,
      name VARCHAR(100) NOT NULL,
      rank INTEGER UNIQUE NOT NULL
    );
    CREATE TABLE IF NOT EXISTS business_categories (
      id BIGSERIAL PRIMARY KEY,
      code VARCHAR(50) UNIQUE NOT NULL,
      name VARCHAR(150) NOT NULL
    );
    CREATE TABLE IF NOT EXISTS documents (
      id UUID PRIMARY KEY,
      document_code VARCHAR(60) UNIQUE NOT NULL,
      title VARCHAR(255) NOT NULL,
      description TEXT,
      owner_id BIGINT NOT NULL,
      department_id BIGINT NOT NULL,
      current_version_id BIGINT,
      status VARCHAR(30) NOT NULL DEFAULT 'ACTIVE',
      discoverable BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      version INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS document_classification_history (
      id BIGSERIAL PRIMARY KEY,
      document_id UUID NOT NULL REFERENCES documents(id),
      classification_level_id BIGINT NOT NULL REFERENCES classification_levels(id),
      business_category_id BIGINT NOT NULL REFERENCES business_categories(id),
      reason TEXT,
      classified_by BIGINT NOT NULL,
      effective_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      effective_to TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS access_grants (
      id UUID PRIMARY KEY,
      document_id UUID NOT NULL REFERENCES documents(id),
      principal_type VARCHAR(20) NOT NULL,
      principal_user_id BIGINT,
      principal_role_id BIGINT,
      source VARCHAR(30) NOT NULL,
      valid_from TIMESTAMPTZ NOT NULL,
      valid_until TIMESTAMPTZ NOT NULL,
      status VARCHAR(30) NOT NULL DEFAULT 'ACTIVE',
      granted_by BIGINT NOT NULL,
      granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      version INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGSERIAL PRIMARY KEY,
      occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      actor_user_id BIGINT,
      actor_username VARCHAR(80),
      action VARCHAR(100) NOT NULL,
      object_type VARCHAR(80) NOT NULL,
      object_id VARCHAR(100),
      document_id UUID,
      outcome VARCHAR(20) NOT NULL,
      correlation_id UUID NOT NULL,
      previous_hash CHAR(64),
      entry_hash CHAR(64) NOT NULL,
      chain_partition VARCHAR(80) NOT NULL DEFAULT 'GLOBAL',
      chain_sequence BIGINT NOT NULL
    );
    CREATE INDEX idx_documents_department_status ON documents (department_id, status, created_at DESC);
    CREATE UNIQUE INDEX uq_document_current_classification ON document_classification_history (document_id) WHERE effective_to IS NULL;
    CREATE INDEX idx_dch_level_active ON document_classification_history (classification_level_id, document_id) WHERE effective_to IS NULL;
    CREATE INDEX idx_access_grants_user_active ON access_grants (principal_user_id, document_id, status, valid_until);
    CREATE UNIQUE INDEX uq_audit_chain_position ON audit_logs (chain_partition, chain_sequence);
    CREATE INDEX idx_audit_partition_time ON audit_logs (chain_partition, occurred_at DESC);
  `);

  await batchInsertParameterized(
    db,
    'classification_levels',
    ['code', 'name', 'rank'],
    [
      ['INTERNAL', 'Nội bộ', 1],
      ['CONFIDENTIAL', 'Mật', 2],
      ['SECRET', 'Tối mật', 3],
      ['TOP_SECRET', 'Tuyệt mật', 4],
    ],
    10,
  );
  await batchInsertParameterized(
    db,
    'business_categories',
    ['code', 'name'],
    [['GENERAL_OPERATIONS', 'Nghiệp vụ chung']],
    10,
  );

  const docRows = [];
  const classificationRows = [];
  const grantRows = [];
  const docIds = [];
  const validFrom = new Date(Date.now() - 3600000).toISOString();
  const validUntil = new Date(Date.now() + 86400000).toISOString();

  for (let i = 1; i <= 5000; i++) {
    const docId = crypto.randomUUID();
    const ownerId = (i % 100) + 1;
    docIds.push(docId);
    docRows.push([
      docId,
      `DOC-${100000 + i}`,
      `Tài liệu nghiệp vụ dự án số ${i}`,
      `Mô tả an toàn ${i}`,
      ownerId,
      (i % 20) + 1,
      'ACTIVE',
      true,
    ]);
    classificationRows.push([docId, (i % 4) + 1, 1, ownerId]);

    if (i % 10 === 0) {
      grantRows.push([
        crypto.randomUUID(),
        docId,
        'USER',
        (i % 50) + 1,
        null,
        'DIRECT',
        validFrom,
        validUntil,
        'ACTIVE',
        ownerId,
      ]);
    }
  }

  await batchInsertParameterized(
    db,
    'documents',
    [
      'id',
      'document_code',
      'title',
      'description',
      'owner_id',
      'department_id',
      'status',
      'discoverable',
    ],
    docRows,
    500,
  );
  await batchInsertParameterized(
    db,
    'document_classification_history',
    ['document_id', 'classification_level_id', 'business_category_id', 'classified_by'],
    classificationRows,
    500,
  );
  await batchInsertParameterized(
    db,
    'access_grants',
    [
      'id',
      'document_id',
      'principal_type',
      'principal_user_id',
      'principal_role_id',
      'source',
      'valid_from',
      'valid_until',
      'status',
      'granted_by',
    ],
    grantRows,
    500,
  );

  let prevHash = null;
  const auditHmacKey = crypto.randomBytes(32);
  const auditRows = [];
  for (let seq = 1; seq <= 5000; seq++) {
    const docId = docIds[seq % docIds.length];
    const entryHash = crypto
      .createHmac('sha256', auditHmacKey)
      .update(`${prevHash ?? 'GENESIS'}:${seq}:DOCUMENT_ACCESSED:SUCCESS`)
      .digest('hex');
    auditRows.push([
      (seq % 50) + 1,
      'DOCUMENT_ACCESSED',
      'DOCUMENT',
      docId,
      docId,
      'SUCCESS',
      crypto.randomUUID(),
      prevHash,
      entryHash,
      'DOCUMENT',
      seq,
    ]);
    prevHash = entryHash;
  }
  await batchInsertParameterized(
    db,
    'audit_logs',
    [
      'actor_user_id',
      'action',
      'object_type',
      'object_id',
      'document_id',
      'outcome',
      'correlation_id',
      'previous_hash',
      'entry_hash',
      'chain_partition',
      'chain_sequence',
    ],
    auditRows,
    500,
  );

  const samplePdf = await PDFDocument.create();
  const page = samplePdf.addPage([595, 842]);
  page.drawText('CONFIDENTIAL DOCUMENT HEADER - INTERNAL USE ONLY', { x: 50, y: 800, size: 12 });
  const samplePdfBytes = Buffer.from(await samplePdf.save());

  return { db, docIds, samplePdfBytes };
}
