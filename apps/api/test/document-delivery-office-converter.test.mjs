import assert from 'node:assert/strict';
import { test } from 'node:test';
import { PDFDocument } from 'pdf-lib';
import { AppErrorCode } from '../../../packages/contracts/dist/error-codes.js';
import { OfficeConverterService } from '../dist/modules/documents/office-converter.service.js';
import { createZipBuffer } from './helpers/zip-builder.mjs';
import { withMockGotenbergServer } from './helpers/document-delivery-mocks.mjs';

test('OfficeConverter — blocks VBA macros with OFFICE_MACRO_BLOCKED', async () => {
  const converter = new OfficeConverterService();
  const macroDocx = createZipBuffer([
    { name: '[Content_Types].xml', content: '<Types></Types>' },
    {
      name: 'word/document.xml',
      content:
        '<w:document><w:body><w:p><w:r><w:t>Macro Document</w:t></w:r></w:p></w:body></w:document>',
    },
    { name: 'word/vbaProject.bin', content: Buffer.from('DANGEROUS MACRO BINARY PAYLOAD') },
  ]);

  await assert.rejects(
    async () => {
      await converter.convertOfficeToPdf(macroDocx, 'invoice.docx');
    },
    (err) => err.getResponse?.()?.errorCode === AppErrorCode.OFFICE_MACRO_BLOCKED,
  );
});

test('OfficeConverter — blocks Excel macro workbook vbaData.xml', async () => {
  const converter = new OfficeConverterService();
  const macroXlsx = createZipBuffer([
    { name: '[Content_Types].xml', content: '<Types></Types>' },
    { name: 'xl/workbook.xml', content: '<workbook></workbook>' },
    { name: 'xl/vbaData.xml', content: '<vbaData></vbaData>' },
  ]);

  await assert.rejects(
    async () => {
      await converter.convertOfficeToPdf(macroXlsx, 'budget.xlsx');
    },
    (err) => err.getResponse?.()?.errorCode === AppErrorCode.OFFICE_MACRO_BLOCKED,
  );
});

test('OfficeConverter — detects corrupt file with OFFICE_CONVERSION_FAILED', async () => {
  const converter = new OfficeConverterService();
  const corruptBuffer = Buffer.from('completely invalid non-zip content 123456');

  await assert.rejects(
    async () => {
      await converter.convertOfficeToPdf(corruptBuffer, 'corrupt.docx');
    },
    (err) => err.getResponse?.()?.errorCode === AppErrorCode.OFFICE_CONVERSION_FAILED,
  );
});

test('OfficeConverter — converts safe DOCX to clean printable PDF', async () => {
  const converter = new OfficeConverterService();
  const safeDocx = createZipBuffer([
    { name: '[Content_Types].xml', content: '<Types></Types>' },
    {
      name: 'word/document.xml',
      content:
        '<w:document><w:body><w:p><w:r><w:t>Quarterly Financial Results</w:t></w:r></w:p><w:p><w:r><w:t>Revenue exceeded target by 15%.</w:t></w:r></w:p></w:body></w:document>',
    },
  ]);

  const pdfBuffer = await converter.convertOfficeToPdf(safeDocx, 'quarterly.docx');
  assert.ok(pdfBuffer.length > 0);
  const loaded = await PDFDocument.load(pdfBuffer);
  assert.ok(loaded.getPageCount() >= 1, 'Converted PDF must have at least 1 page');
});

test('OfficeConverter — converts safe DOCX via Gotenberg container when service is available', async () => {
  const mockGotenbergPdf = await PDFDocument.create();
  mockGotenbergPdf.addPage([595.28, 841.89]);
  const mockPdfBytes = Buffer.from(await mockGotenbergPdf.save());

  let receivedRequest = false;
  let receivedPath = '';
  let receivedContentType = '';

  await withMockGotenbergServer(
    (req, res) => {
      receivedRequest = true;
      receivedPath = req.url || '';
      receivedContentType = req.headers['content-type'] || '';
      if (req.url === '/forms/libreoffice/convert' && req.method === 'POST') {
        res.writeHead(200, { 'Content-Type': 'application/pdf' });
        res.end(mockPdfBytes);
      } else {
        res.writeHead(404);
        res.end();
      }
    },
    async ({ converter }) => {
      const safeDocx = createZipBuffer([
        { name: '[Content_Types].xml', content: '<Types></Types>' },
        {
          name: 'word/document.xml',
          content:
            '<w:document><w:body><w:p><w:r><w:t>Financial Report 2026</w:t></w:r></w:p></w:body></w:document>',
        },
      ]);

      const resultPdf = await converter.convertOfficeToPdf(safeDocx, 'annual_report.docx');
      assert.ok(receivedRequest, 'Gotenberg server must receive conversion request');
      assert.equal(receivedPath, '/forms/libreoffice/convert');
      assert.ok(receivedContentType.includes('multipart/form-data'));
      assert.ok(resultPdf.length > 0);

      const loaded = await PDFDocument.load(resultPdf);
      assert.equal(loaded.getPageCount(), 1);
    },
  );
});

test('OfficeConverter — falls back gracefully to internal engine when Gotenberg returns 500', async () => {
  await withMockGotenbergServer(
    (_req, res) => {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end('Internal LibreOffice Failure');
    },
    async ({ converter }) => {
      const safeDocx = createZipBuffer([
        { name: '[Content_Types].xml', content: '<Types></Types>' },
        {
          name: 'word/document.xml',
          content:
            '<w:document><w:body><w:p><w:r><w:t>Quarterly Financial Results</w:t></w:r></w:p></w:body></w:document>',
        },
      ]);

      const resultPdf = await converter.convertOfficeToPdf(safeDocx, 'fallback_report.docx');
      assert.ok(resultPdf.length > 0);
      const loaded = await PDFDocument.load(resultPdf);
      assert.ok(loaded.getPageCount() >= 1);
    },
  );
});

test('OfficeConverter — falls back gracefully when Gotenberg service is offline (ECONNREFUSED)', async () => {
  const mockConfig = {
    get(key) {
      if (key === 'GOTENBERG_URL') return 'http://127.0.0.1:59998';
      if (key === 'GOTENBERG_ENABLED') return true;
      return undefined;
    },
  };

  const converter = new OfficeConverterService(mockConfig);
  const safeDocx = createZipBuffer([
    { name: '[Content_Types].xml', content: '<Types></Types>' },
    {
      name: 'word/document.xml',
      content:
        '<w:document><w:body><w:p><w:r><w:t>Offline Gotenberg Fallback</w:t></w:r></w:p></w:body></w:document>',
    },
  ]);

  const resultPdf = await converter.convertOfficeToPdf(safeDocx, 'offline_report.docx');
  assert.ok(resultPdf.length > 0);
  const loaded = await PDFDocument.load(resultPdf);
  assert.ok(loaded.getPageCount() >= 1);
});

test('OfficeConverter — blocks macro before attempting Gotenberg conversion (pre-flight security)', async () => {
  let requestMade = false;
  await withMockGotenbergServer(
    (_req, res) => {
      requestMade = true;
      res.writeHead(200);
      res.end();
    },
    async ({ converter }) => {
      const macroDocx = createZipBuffer([
        { name: '[Content_Types].xml', content: '<Types></Types>' },
        { name: 'word/document.xml', content: '<w:document></w:document>' },
        { name: 'word/vbaProject.bin', content: Buffer.from('MACRO_PAYLOAD') },
      ]);

      await assert.rejects(
        async () => {
          await converter.convertOfficeToPdf(macroDocx, 'exploit.docx');
        },
        (err) => err.getResponse?.()?.errorCode === AppErrorCode.OFFICE_MACRO_BLOCKED,
      );

      assert.equal(
        requestMade,
        false,
        'Security pre-check must reject macro before calling Gotenberg',
      );
    },
  );
});
