import test from 'node:test';
import assert from 'node:assert/strict';
import {
  generatePdfTable,
  generateExcelTable,
  sanitizeForPdf,
} from '../dist/modules/reports/export-formatter.js';

test('export-formatter — sanitizeForPdf correctly transliterates Vietnamese accents to ASCII', () => {
  const input = 'Báo cáo Kiểm toán: 100% thành công, Đã xử lý';
  const sanitized = sanitizeForPdf(input);
  assert.equal(sanitized, 'Bao cao Kiem toan: 100% thanh cong, Da xu ly');
  // Ensure no non-ASCII characters remain
  assert.ok(/^[\x20-\x7E]*$/.test(sanitized));
});

test('export-formatter — generatePdfTable creates valid PDF buffer with %PDF header', async () => {
  const columns = [
    { key: 'id', header: 'Mã log' },
    { key: 'action', header: 'Hành động' },
    { key: 'actor', header: 'Người thực hiện' },
  ];
  const rows = [
    { id: '1', action: 'DOCUMENT_VIEW', actor: 'Nguyen Van A' },
    { id: '2', action: 'EXPORT_AUDIT', actor: 'Tran Thi B' },
  ];

  const buffer = await generatePdfTable('Báo cáo kiểm toán bảo mật', columns, rows);
  assert.ok(Buffer.isBuffer(buffer));
  assert.ok(buffer.length > 500, 'PDF buffer should be sufficiently large');
  assert.equal(
    buffer.subarray(0, 4).toString(),
    '%PDF',
    'PDF buffer must start with %PDF magic bytes',
  );
});

test('export-formatter — generateExcelTable creates valid XLSX buffer with PK magic bytes', async () => {
  const columns = [
    { key: 'id', header: 'ID' },
    { key: 'action', header: 'Hành động' },
    { key: 'formulaTest', header: 'Công thức độc hại' },
  ];
  const rows = [
    { id: '1', action: 'VIEW', formulaTest: '=CMD|"/C calc"!A0' },
    { id: '2', action: 'DOWNLOAD', formulaTest: '+12345' },
  ];

  const buffer = await generateExcelTable('Kiểm toán', columns, rows);
  assert.ok(Buffer.isBuffer(buffer));
  assert.ok(buffer.length > 500, 'XLSX buffer should be sufficiently large');
  // XLSX is a ZIP archive, starts with PK\x03\x04
  assert.equal(
    buffer.subarray(0, 2).toString(),
    'PK',
    'XLSX buffer must start with PK zip signature',
  );
});
