/**
 * SDA Query Profiler Schema & High-Volume Synthetic Dataset Seeder
 * Extracted from scripts/profile-queries.mjs for modularity (Rule §3 ≤ 180 lines).
 */

import crypto from 'node:crypto';
import { PGlite } from '@electric-sql/pglite';

/**
 * Algorithm / Thuật toán: Parameterized Multi-Row Batch Insert Executor (Chèn Lô Tham Số Hóa Chống SQL Injection)
 * Purpose / Mục đích: Construct positional `$1..$N` placeholders without interpolating runtime values into SQL text.
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
 * Algorithm / Thuật toán: Composite B-Tree Schema Provisioning & High-Cardinality Batch Seeding
 * Purpose / Mục đích: Provision 6 relational tables with production composite B-Tree indexes and seed 38,050+
 *   interlinked records (50 departments, 1,000 users, 5,000 documents, 10,000 grants, 2,000 sessions, 20,000 audit logs)
 *   so PostgreSQL's cost-based query planner exercises realistic selectivity statistics.
 */
export async function createAndSeedProfileDatabase() {
  const db = new PGlite();

  await db.exec(`
    CREATE TABLE IF NOT EXISTS departments (
      id BIGSERIAL PRIMARY KEY,
      code VARCHAR(50) UNIQUE NOT NULL,
      name VARCHAR(150) NOT NULL
    );
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      department_id BIGINT REFERENCES departments(id),
      clearance_level INTEGER NOT NULL DEFAULT 1,
      status VARCHAR(30) NOT NULL DEFAULT 'ACTIVE'
    );
    CREATE TABLE IF NOT EXISTS documents (
      id UUID PRIMARY KEY,
      document_code VARCHAR(50) UNIQUE NOT NULL,
      title VARCHAR(255) NOT NULL,
      description TEXT,
      classification_id INTEGER NOT NULL,
      owner_id BIGINT REFERENCES users(id),
      department_id BIGINT REFERENCES departments(id),
      status VARCHAR(30) NOT NULL DEFAULT 'ACTIVE',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS access_grants (
      id UUID PRIMARY KEY,
      document_id UUID REFERENCES documents(id),
      grantee_user_id BIGINT REFERENCES users(id),
      grantee_role_id BIGINT,
      grant_type VARCHAR(20) NOT NULL,
      status VARCHAR(30) NOT NULL DEFAULT 'ACTIVE',
      valid_from TIMESTAMPTZ NOT NULL,
      valid_until TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS access_sessions (
      id UUID PRIMARY KEY,
      grant_id UUID REFERENCES access_grants(id),
      user_id BIGINT REFERENCES users(id),
      document_id UUID REFERENCES documents(id),
      status VARCHAR(30) NOT NULL DEFAULT 'ACTIVE',
      session_token_hash VARCHAR(64) UNIQUE NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGSERIAL PRIMARY KEY,
      actor_user_id BIGINT,
      action VARCHAR(100) NOT NULL,
      object_type VARCHAR(100) NOT NULL,
      object_id VARCHAR(100),
      outcome VARCHAR(30) NOT NULL,
      chain_partition VARCHAR(50) NOT NULL,
      sequence BIGINT NOT NULL,
      previous_record_hash VARCHAR(64),
      record_hash VARCHAR(64) NOT NULL,
      occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX idx_users_lookup ON users(department_id, status);
    CREATE INDEX idx_docs_search_composite ON documents (classification_id, department_id, status, created_at DESC);
    CREATE INDEX idx_docs_owner ON documents (owner_id, status);
    CREATE INDEX idx_grants_zero_trust ON access_grants (document_id, grantee_user_id, status, valid_from, valid_until);
    CREATE INDEX idx_sessions_active ON access_sessions (session_token_hash, status, expires_at);
    CREATE INDEX idx_audit_partition_seq ON audit_logs (chain_partition, sequence ASC);
  `);

  const deptRows = Array.from({ length: 50 }, (_, idx) => [
    `DEPT_${idx + 1}`,
    `Phòng ban chức năng số ${idx + 1}`,
  ]);
  await batchInsertParameterized(db, 'departments', ['code', 'name'], deptRows, 50);

  const userRows = Array.from({ length: 1000 }, (_, idx) => [
    `user_${idx + 1}`,
    `user_${idx + 1}@org.vn`,
    ((idx + 1) % 50) + 1,
    ((idx + 1) % 4) + 1,
    'ACTIVE',
  ]);
  await batchInsertParameterized(
    db,
    'users',
    ['username', 'email', 'department_id', 'clearance_level', 'status'],
    userRows,
    250,
  );

  const docRows = [];
  const docIds = [];
  for (let i = 1; i <= 5000; i++) {
    const id = crypto.randomUUID();
    docIds.push(id);
    docRows.push([
      id,
      `DOC-${100000 + i}`,
      `Kế hoạch an toàn thông tin tài liệu ${i}`,
      `Mô tả nghiệp vụ ${i}`,
      (i % 4) + 1,
      (i % 500) + 1,
      (i % 50) + 1,
      'ACTIVE',
    ]);
  }
  await batchInsertParameterized(
    db,
    'documents',
    [
      'id',
      'document_code',
      'title',
      'description',
      'classification_id',
      'owner_id',
      'department_id',
      'status',
    ],
    docRows,
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
      (i % 1000) + 1,
      null,
      'USER',
      'ACTIVE',
      past,
      future,
    ]);
  }
  await batchInsertParameterized(
    db,
    'access_grants',
    [
      'id',
      'document_id',
      'grantee_user_id',
      'grantee_role_id',
      'grant_type',
      'status',
      'valid_from',
      'valid_until',
    ],
    grantRows,
    500,
  );

  const sessionRows = [];
  for (let i = 1; i <= 2000; i++) {
    const tokenHash = crypto.createHash('sha256').update(`token_${i}`).digest('hex');
    sessionRows.push([
      crypto.randomUUID(),
      grantIds[i % grantIds.length],
      (i % 1000) + 1,
      docIds[i % docIds.length],
      'ACTIVE',
      tokenHash,
      future,
    ]);
  }
  await batchInsertParameterized(
    db,
    'access_sessions',
    ['id', 'grant_id', 'user_id', 'document_id', 'status', 'session_token_hash', 'expires_at'],
    sessionRows,
    500,
  );

  let prevHash = '0000000000000000000000000000000000000000000000000000000000000000';
  const auditRows = [];
  for (let i = 1; i <= 20000; i++) {
    const recHash = crypto.createHmac('sha256', 'k').update(`${prevHash}:${i}`).digest('hex');
    const part = i % 2 === 0 ? 'DOCUMENT' : 'AUTH';
    auditRows.push([
      (i % 500) + 1,
      'READ',
      'DOCUMENT',
      docIds[i % docIds.length],
      'SUCCESS',
      part,
      i,
      prevHash,
      recHash,
    ]);
    prevHash = recHash;
  }
  await batchInsertParameterized(
    db,
    'audit_logs',
    [
      'actor_user_id',
      'action',
      'object_type',
      'object_id',
      'outcome',
      'chain_partition',
      'sequence',
      'previous_record_hash',
      'record_hash',
    ],
    auditRows,
    1000,
  );

  return { db, docIds };
}
