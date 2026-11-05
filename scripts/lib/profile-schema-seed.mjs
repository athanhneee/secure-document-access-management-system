/**
 * SDA Query Profiler High-Volume Synthetic Dataset Seeder
 * Extracted from scripts/profile-queries.mjs for modularity (Rule §3).
 */

import crypto from 'node:crypto';
import { PGlite } from '@electric-sql/pglite';
import { PROFILE_SCHEMA_SQL } from './profile-schema-ddl.mjs';

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
 * Thuật toán: Cấp Phát Lược Đồ Phức Hợp B-Tree Chuẩn Prisma & Gieo Lô Mật Độ Cao (High-Cardinality Batch Seeder)
 * Mục đích: Khởi tạo lược đồ quan hệ chuẩn Prisma kèm chỉ mục B-Tree, nạp hơn 48.000 bản ghi liên kết
 *   và cập nhật thống kê `ANALYZE` cho bộ lập kế hoạch PostgreSQL.
 */
export async function createAndSeedProfileDatabase() {
  const db = new PGlite();
  await db.exec(PROFILE_SCHEMA_SQL);

  // CONFLICT-RESOLVED: Nạp dữ liệu mẫu theo đúng danh sách cột chuẩn của Prisma schema (users, documents, document_versions, document_classification_history, access_grants, access_sessions, audit_logs).
  const deptRows = Array.from({ length: 50 }, (_, idx) => [
    `DEPT_${idx + 1}`,
    `Phòng ban chức năng số ${idx + 1}`,
  ]);
  await batchInsertParameterized(db, 'departments', ['code', 'name'], deptRows, 50);

  const userRows = Array.from({ length: 1000 }, (_, idx) => [
    `user_${idx + 1}`,
    `user_${idx + 1}@org.vn`,
    '!PROFILER_SYNTHETIC_DISABLED_HASH!',
    `Nhân sự thử tải ${idx + 1}`,
    ((idx + 1) % 50) + 1,
    'ACTIVE',
  ]);
  await batchInsertParameterized(
    db,
    'users',
    ['username', 'email', 'password_hash', 'full_name', 'department_id', 'status'],
    userRows,
    250,
  );

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
    ['code', 'name', 'department_id'],
    [['GENERAL_OPERATIONS', 'Nghiệp vụ chung', 1]],
    10,
  );

  const docRows = [];
  const versionRows = [];
  const classificationRows = [];
  const docIds = [];
  for (let i = 1; i <= 5000; i++) {
    const id = crypto.randomUUID();
    const ownerId = (i % 500) + 1;
    docIds.push(id);
    docRows.push([
      id,
      `DOC-${100000 + i}`,
      `Kế hoạch an toàn thông tin tài liệu ${i}`,
      `Mô tả nghiệp vụ ${i}`,
      ownerId,
      (i % 50) + 1,
      'ACTIVE',
      true,
    ]);
    versionRows.push([
      id,
      1,
      `doc_${i}.pdf`,
      `documents/2026/${id}/v1.enc`,
      'application/pdf',
      4096,
      crypto.createHash('sha256').update(`ver_${i}`).digest('hex'),
      'kms-key-v1',
      'CLEAN',
      ownerId,
    ]);
    classificationRows.push([id, (i % 4) + 1, 1, ownerId]);
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
    'document_versions',
    [
      'document_id',
      'version_no',
      'original_filename',
      'storage_key',
      'mime_type',
      'file_size_bytes',
      'sha256_hash',
      'encryption_key_ref',
      'scan_status',
      'uploaded_by',
    ],
    versionRows,
    500,
  );
  await batchInsertParameterized(
    db,
    'document_classification_history',
    ['document_id', 'classification_level_id', 'business_category_id', 'classified_by'],
    classificationRows,
    500,
  );

  const grantRows = [];
  const grantIds = [];
  const now = Date.now();
  const past = new Date(now - 86400000).toISOString();
  const future = new Date(now + 86400000).toISOString();
  for (let i = 1; i <= 10000; i++) {
    const id = crypto.randomUUID();
    grantIds.push(id);
    grantRows.push([
      id,
      docIds[i % docIds.length],
      'USER',
      (i % 1000) + 1,
      null,
      'DIRECT',
      past,
      future,
      'ACTIVE',
      (i % 500) + 1,
    ]);
  }
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

  const sessionRows = Array.from({ length: 2000 }, (_, idx) => {
    const i = idx + 1;
    return [
      crypto.randomUUID(),
      grantIds[i % grantIds.length],
      (i % 5000) + 1,
      (i % 1000) + 1,
      `10.20.${(i % 200) + 1}.${(i % 250) + 1}`,
      'ACTIVE',
      past,
      new Date(now - (i % 300) * 1000).toISOString(),
    ];
  });
  await batchInsertParameterized(
    db,
    'access_sessions',
    [
      'id',
      'access_grant_id',
      'document_version_id',
      'user_id',
      'ip_address',
      'status',
      'started_at',
      'last_activity_at',
    ],
    sessionRows,
    500,
  );

  const seqByPart = { DOCUMENT: 0, AUTH: 0 };
  const prevByPart = { DOCUMENT: null, AUTH: null };
  const auditSeedHmacKey = crypto.randomBytes(32);
  const auditRows = [];
  for (let i = 1; i <= 20000; i++) {
    const part = i % 2 === 0 ? 'DOCUMENT' : 'AUTH';
    const seq = ++seqByPart[part];
    const prevHash = prevByPart[part];
    const entryHash = crypto
      .createHmac('sha256', auditSeedHmacKey)
      .update(`${prevHash ?? 'GENESIS'}:${seq}`)
      .digest('hex');
    const docId = docIds[i % docIds.length];
    auditRows.push([
      (i % 500) + 1,
      'DOCUMENT_ACCESSED',
      'DOCUMENT',
      docId,
      docId,
      'SUCCESS',
      crypto.randomUUID(),
      prevHash,
      entryHash,
      part,
      seq,
    ]);
    prevByPart[part] = entryHash;
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
    1000,
  );

  await db.exec('ANALYZE;');
  return { db, docIds };
}
