/**
 * SDA Enterprise Load Testing Synthetic Database & PDF Fixture Seeder
 * Separated from scenario definitions for Single Responsibility (Rule §3).
 */

import crypto from 'node:crypto';
import pkg from '../../apps/api/node_modules/pdf-lib/cjs/index.js';
const { PDFDocument } = pkg;
import { PGlite } from '@electric-sql/pglite';

/**
 * Algorithm / Thuật toán: Parameterized Multi-Row Batch Insert Executor (Chèn Lô Tham Số Hóa Chống SQL Injection)
 * Purpose: Construct positional `$1..$N` placeholders without interpolating runtime values into SQL text.
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
 * Algorithm / Thuật toán: Batch-Chunked Synthetic Relational & HMAC Hash-Chain Seeding
 * Purpose: Initialize an isolated in-memory PGlite database with composite B-Tree indexes, 5,000 synthetic
 *   documents, active grants, 5,000 HMAC-SHA256 chained audit records, and an in-memory PDF template buffer.
 */
export async function createAndSeedLoadTestFixture() {
  const db = new PGlite();

  await db.exec(`
    CREATE TABLE IF NOT EXISTS documents (
      id UUID PRIMARY KEY, document_code VARCHAR(50) NOT NULL, title VARCHAR(255) NOT NULL,
      description TEXT, classification_id INTEGER NOT NULL, owner_id BIGINT NOT NULL,
      department_id BIGINT NOT NULL, status VARCHAR(30) NOT NULL DEFAULT 'ACTIVE',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS access_grants (
      id UUID PRIMARY KEY, document_id UUID NOT NULL, grantee_user_id BIGINT, grantee_role_id BIGINT,
      grant_type VARCHAR(20) NOT NULL, status VARCHAR(30) NOT NULL DEFAULT 'ACTIVE',
      valid_from TIMESTAMPTZ NOT NULL, valid_until TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGSERIAL PRIMARY KEY, actor_user_id BIGINT, action VARCHAR(100) NOT NULL,
      object_type VARCHAR(100) NOT NULL, object_id VARCHAR(100), outcome VARCHAR(30) NOT NULL,
      chain_partition VARCHAR(50) NOT NULL, previous_record_hash VARCHAR(64),
      record_hash VARCHAR(64) NOT NULL, occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX idx_docs_search ON documents (classification_id, department_id, status);
    CREATE INDEX idx_grants_lookup ON access_grants (document_id, status, valid_from, valid_until);
    CREATE INDEX idx_audit_partition ON audit_logs (chain_partition, occurred_at);
  `);

  const docRows = [];
  const grantRows = [];
  const docIds = [];
  const validFrom = new Date(Date.now() - 3600000).toISOString();
  const validUntil = new Date(Date.now() + 86400000).toISOString();

  for (let i = 1; i <= 5000; i++) {
    const docId = crypto.randomUUID();
    docIds.push(docId);
    docRows.push([
      docId,
      `DOC-${100000 + i}`,
      `Tài liệu nghiệp vụ dự án số ${i}`,
      `Mô tả an toàn ${i}`,
      (i % 4) + 1,
      (i % 100) + 1,
      (i % 20) + 1,
      'ACTIVE',
    ]);
    if (i % 10 === 0) {
      grantRows.push([
        crypto.randomUUID(),
        docId,
        (i % 50) + 1,
        null,
        'USER',
        'ACTIVE',
        validFrom,
        validUntil,
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
      'classification_id',
      'owner_id',
      'department_id',
      'status',
    ],
    docRows,
    500,
  );
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

  let prevHash = '0'.repeat(64);
  const auditRows = [];
  for (let i = 1; i <= 5000; i++) {
    const recHash = crypto
      .createHmac('sha256', 'audit-secret-key')
      .update(`${prevHash}:${i}:VIEW:SUCCESS`)
      .digest('hex');
    auditRows.push([
      (i % 50) + 1,
      'DOCUMENT_ACCESSED',
      'DOCUMENT',
      docIds[i % docIds.length],
      'SUCCESS',
      'DOCUMENT',
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
      'previous_record_hash',
      'record_hash',
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
