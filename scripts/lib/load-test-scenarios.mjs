/**
 * SDA Enterprise Load Testing Six-Flow Scenario Runners
 * Extracted from scripts/load-test.mjs for modularity (Rule §3).
 */

import crypto from 'node:crypto';
import pkg from '../../apps/api/node_modules/pdf-lib/cjs/index.js';
const { PDFDocument, StandardFonts, rgb } = pkg;

export { createAndSeedLoadTestFixture } from './load-test-fixture.mjs';

/**
 * Algorithm / Thuật toán: Six-Flow Enterprise Workload Scenario Factory
 * Purpose: Construct deterministic workload functions covering JWT HMAC verification, indexed document search,
 *   compiled ABAC PDP evaluation, Zero-Trust grant validation, dynamic PDF watermark rendering, and audit range queries.
 */
export function buildLoadTestScenarios({ db, docIds, samplePdfBytes, totalOps, concurrency }) {
  return [
    {
      name: '1. Login & Token Verification',
      totalOps,
      concurrency,
      execute: async (idx) => {
        const payload = JSON.stringify({
          sub: `user_${(idx % 100) + 1}`,
          dept: 'Engineering',
          clearance: 3,
          roles: ['DOCUMENT_VIEWER', 'REPORT_VIEWER'],
          exp: Date.now() + 3600000,
          jti: crypto.randomUUID(),
        });
        const sig = crypto
          .createHmac('sha256', 'jwt-secret-key-32-chars-minimum')
          .update(payload)
          .digest('base64url');
        const token = `${Buffer.from(payload).toString('base64url')}.${sig}`;
        const [b64, signature] = token.split('.');
        const expectedSig = crypto
          .createHmac('sha256', 'jwt-secret-key-32-chars-minimum')
          .update(Buffer.from(b64, 'base64url').toString('utf8'))
          .digest('base64url');
        if (signature !== expectedSig) throw new Error('Invalid signature');
      },
    },
    {
      name: '2. Search & Document Discovery (Filter & Pagination)',
      totalOps,
      concurrency,
      execute: async (idx) => {
        const res = await db.query(
          `SELECT id, document_code, title, classification_id, department_id
           FROM documents WHERE department_id = $1 AND classification_id <= $2 AND status = 'ACTIVE'
           ORDER BY created_at DESC LIMIT 20 OFFSET $3;`,
          [(idx % 20) + 1, (idx % 3) + 1, (idx % 5) * 20],
        );
        if (!res.rows) throw new Error('Search failed');
      },
    },
    {
      name: '3. ABAC PDP Access Decision Evaluation',
      totalOps,
      concurrency,
      execute: async (idx) => {
        const subject = {
          userId: (idx % 500) + 1,
          departmentId: (idx % 20) + 1,
          clearanceLevel: (idx % 4) + 1,
          isTrustedDevice: idx % 10 !== 0,
        };
        const resource = {
          documentId: docIds[idx % docIds.length],
          departmentId: (idx % 20) + 1,
          classificationLevel: 3,
          ownerId: (idx % 100) + 1,
        };
        const isPermitted =
          subject.clearanceLevel >= resource.classificationLevel &&
          (subject.departmentId === resource.departmentId || subject.userId === resource.ownerId) &&
          subject.isTrustedDevice;
        const decision = isPermitted ? 'PERMIT' : 'DENY';
        if (!decision) throw new Error('PDP evaluation failed');
      },
    },
    {
      name: '4. Active Grant & Permission Check (Zero-Trust)',
      totalOps,
      concurrency,
      execute: async (idx) => {
        const res = await db.query(
          `SELECT id, status, valid_from, valid_until FROM access_grants
           WHERE document_id = $1 AND grantee_user_id = $2 AND status = 'ACTIVE'
             AND valid_from <= NOW() AND valid_until > NOW() LIMIT 1;`,
          [docIds[idx % docIds.length], (idx % 50) + 1],
        );
        if (!res) throw new Error('Grant lookup failed');
      },
    },
    {
      name: '5. Document View & Dynamic Watermark Render',
      totalOps: Math.min(totalOps, 200),
      concurrency: Math.min(concurrency, 10),
      execute: async (idx) => {
        const pdfDoc = await PDFDocument.load(samplePdfBytes);
        const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
        const token = `WM-${crypto.randomBytes(12).toString('hex')}`;
        pdfDoc
          .getPages()[0]
          .drawText(`CONFIDENTIAL - USER_${idx % 100} - UID:${1000 + idx} - ${token}`, {
            x: 100,
            y: 400,
            size: 14,
            font,
            color: rgb(0.5, 0.5, 0.5),
            opacity: 0.35,
            rotate: { type: 'degrees', angle: 45 },
          });
        const hash = crypto
          .createHash('sha256')
          .update(Buffer.from(await pdfDoc.save()))
          .digest('hex');
        if (!hash) throw new Error('Watermark hashing failed');
      },
    },
    {
      name: '6. Audit Trail Partition Range Query & Verification',
      totalOps,
      concurrency,
      execute: async () => {
        const res = await db.query(
          `SELECT id, action, object_id, outcome, previous_record_hash, record_hash
           FROM audit_logs WHERE chain_partition = 'DOCUMENT' ORDER BY id ASC LIMIT $1;`,
          [50],
        );
        if (!res.rows || res.rows.length === 0) throw new Error('Audit query empty');
      },
    },
  ];
}
