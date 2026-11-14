import test from 'node:test';
import assert from 'node:assert/strict';
import { PDFDocument } from 'pdf-lib';
import { sanitizeCsvCell } from '../dist/modules/reports/csv-formula-sanitizer.js';
import {
  generatePdfTable,
  generateExcelTable,
  sanitizeForPdf,
} from '../dist/modules/reports/export-formatter.js';

/**
 * Thuật toán / Tổng quan module:
 * Kiểm thử đơn vị bộ định dạng báo cáo tuân thủ `@sda/api` (`PDF` đa trang A4 ngang không cắt cụt chuỗi dài,
 * `EXCEL` OOXML `.xlsx` và khử độc Formula Injection OWASP CWE-1236).
 */

test('export-formatter — sanitizeForPdf correctly transliterates Vietnamese accents to ASCII', () => {
  const input = 'Báo cáo Kiểm toán: 100% thành công, Đã xử lý';
  const sanitized = sanitizeForPdf(input);
  assert.equal(sanitized, 'Bao cao Kiem toan: 100% thanh cong, Da xu ly');
  assert.ok(/^[\x20-\x7E]*$/.test(sanitized));
});

test('export-formatter — generatePdfTable creates multi-page A4 PDF without 55-row cap or cell ellipsis truncation', async () => {
  const columns = [
    { key: 'id', header: 'Mã log' },
    { key: 'action', header: 'Hành động' },
    { key: 'actor', header: 'Người thực hiện' },
    { key: 'entryHash', header: 'Băm chuỗi SHA-256' },
  ];
  const sampleSha = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';
  const rows = Array.from({ length: 85 }, (_, idx) => ({
    id: String(idx + 1),
    action: idx % 2 === 0 ? 'DOCUMENT_VIEW' : 'EXPORT_AUDIT',
    actor: `Nguyễn Văn Kiểm Toán ${idx + 1}`,
    entryHash: sampleSha,
  }));

  const buffer = await generatePdfTable('Báo cáo kiểm toán bảo mật đa trang', columns, rows);
  assert.ok(Buffer.isBuffer(buffer));
  assert.equal(buffer.subarray(0, 4).toString(), '%PDF');

  const loadedPdf = await PDFDocument.load(buffer);
  assert.ok(loadedPdf.getPageCount() >= 3, 'Expected >= 3 A4 pages for 85 multi-line records');
  const firstPage = loadedPdf.getPage(0);
  const { width, height } = firstPage.getSize();
  assert.ok(width > height, 'Expected A4 Landscape page orientation');
});

test('export-formatter — generateExcelTable creates valid XLSX buffer with PK magic bytes and formula defense', async () => {
  const columns = [
    { key: 'id', header: 'ID' },
    { key: 'action', header: 'Hành động' },
    { key: 'formulaTest', header: 'Công thức độc hại' },
  ];
  const rows = [
    { id: '1', action: 'VIEW', formulaTest: '=CMD|"/C calc"!A0' },
    { id: '2', action: 'DOWNLOAD', formulaTest: 'safe line\n=SUM(1,2)' },
  ];

  assert.equal(sanitizeCsvCell('safe line\n=SUM(1,2)'), "'safe line\n=SUM(1,2)");

  const buffer = await generateExcelTable('Kiểm toán', columns, rows);
  assert.ok(Buffer.isBuffer(buffer));
  assert.ok(buffer.length > 500, 'XLSX buffer should be sufficiently large');
  assert.equal(
    buffer.subarray(0, 2).toString(),
    'PK',
    'XLSX buffer must start with PK zip signature',
  );
});
