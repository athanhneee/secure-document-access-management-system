import 'reflect-metadata';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import net from 'node:net';
import { Readable } from 'node:stream';
import { test } from 'node:test';
import { PDFDocument } from 'pdf-lib';
import { AppErrorCode } from '@sda/contracts';
import { AppConfigService } from '../dist/config/config.service.js';
import { AntivirusScannerService } from '../dist/modules/documents/antivirus-scanner.service.js';
import { FileValidationService } from '../dist/modules/documents/file-validation.service.js';
import { WatermarkEngineService } from '../dist/modules/watermarks/watermark-engine.service.js';

test('Dangerous Files: EICAR — real AntivirusScannerService detects EICAR in Buffer and over ClamAV zINSTREAM TCP', async () => {
  const encodedParts = await Promise.all([
    readFile(
      new URL('../../../test/fixtures/eicar.com.base64.part-01.txt', import.meta.url),
      'utf8',
    ),
    readFile(
      new URL('../../../test/fixtures/eicar.com.base64.part-02.txt', import.meta.url),
      'utf8',
    ),
  ]);
  const fixture = Buffer.from(encodedParts.map((p) => p.trim()).join(''), 'base64');

  const eicarSha256 = createHash('sha256').update(fixture).digest('hex');
  assert.equal(fixture.length, 68);
  assert.equal(eicarSha256, '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f');

  const clamServer = net.createServer((socket) => {
    const chunks = [];
    socket.on('data', (chunk) => {
      chunks.push(chunk);
      const buf = Buffer.concat(chunks);
      if (buf.length >= 14 && buf.subarray(buf.length - 4).readUInt32BE(0) === 0) {
        const body = buf.toString('latin1');
        if (body.includes('EICAR-STANDARD-ANTIVIRUS-TEST-FILE!')) {
          socket.end('stream: Win.Test.EICAR_HDB-1 FOUND\0');
        } else {
          socket.end('stream: OK\0');
        }
      }
    });
  });

  await new Promise((resolve) => clamServer.listen(0, '127.0.0.1', resolve));
  try {
    const { port } = clamServer.address();
    const config = new AppConfigService({
      CLAMAV_HOST: '127.0.0.1',
      CLAMAV_PORT: port,
    });
    const scanner = new AntivirusScannerService(config);

    const bufferScan = await scanner.scan(fixture);
    assert.equal(bufferScan.status, 'INFECTED');
    assert.equal(bufferScan.virusName, 'Eicar-Test-Signature');

    const streamScan = await scanner.scan(Readable.from([fixture]));
    assert.equal(streamScan.status, 'INFECTED');
    assert.equal(streamScan.virusName, 'Win.Test.EICAR_HDB-1');

    const cleanScan = await scanner.scan(Readable.from([Buffer.from('%PDF-1.7\nclean content')]));
    assert.equal(cleanScan.status, 'CLEAN');
  } finally {
    await new Promise((resolve) => clamServer.close(resolve));
  }
});

test('Dangerous Files: MIME Spoofing — rejects executable disguised as PDF or Office document', () => {
  const validator = new FileValidationService();

  const fakePdf = Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00]);
  assert.throws(
    () => validator.validateMagicBytes(fakePdf, '.pdf'),
    /does not match PDF format magic bytes/u,
  );

  const fakeDocx = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01]);
  assert.throws(
    () => validator.validateMagicBytes(fakeDocx, '.docx'),
    /does not match Office OpenXML zip magic bytes/u,
  );

  const fakeXlsx = Buffer.from('#!/bin/sh\nrm -rf /');
  assert.throws(
    () => validator.validateMagicBytes(fakeXlsx, '.xlsx'),
    /does not match Office OpenXML zip magic bytes/u,
  );
});

test('Dangerous Files: Path Traversal & Double Extension Spoofing', () => {
  const validator = new FileValidationService();

  assert.throws(() => validator.sanitizeFilename('report\0.pdf'), /forbidden null byte/u);
  assert.throws(
    () => validator.sanitizeFilename('report.exe.pdf'),
    /forbidden executable double extension: .exe/u,
  );
  assert.throws(
    () => validator.sanitizeFilename('invoice.bat.docx'),
    /forbidden executable double extension: .bat/u,
  );
  assert.throws(
    () => validator.sanitizeFilename('report\u202Edpy.exe'),
    /forbidden bidirectional override/u,
  );
});

test('Dangerous Files: Multi-Page PDF — watermarks all pages without buffer corruption', async () => {
  const engine = new WatermarkEngineService();

  const pdfDoc = await PDFDocument.create();
  for (let i = 1; i <= 5; i++) {
    pdfDoc.addPage([595, 842]);
  }
  const multiPagePdfBytes = Buffer.from(await pdfDoc.save());

  const token = engine.generateWatermarkToken();
  const result = await engine.applyWatermarkToPdf(
    multiPagePdfBytes,
    {
      id: 77n,
      username: 'manager_kim',
      fullName: 'Kim Nguyen',
      employeeCode: 'EMP-77',
    },
    {
      id: randomUUID(),
      title: 'Bao Cao Thuong Nien 5 Trang',
      documentCode: 'DOC-ANNUAL-2026',
      classificationName: 'MAT',
      requireWatermark: true,
    },
    {
      id: 1n,
      template_text: '{fullName} - {documentCode} - {timestamp}',
      opacity_percent: 25,
      rotation_degrees: 45,
      font_size: 14,
      color_hex: '#808080',
      include_qr_code: false,
      is_visible: true,
    },
    token,
  );

  assert.equal(result.pageCount, 5, 'Must stamp exactly all 5 pages');
  assert.ok(result.watermarkedBuffer.length > multiPagePdfBytes.length);

  const reloaded = await PDFDocument.load(result.watermarkedBuffer);
  assert.equal(reloaded.getPageCount(), 5);
});

test('Dangerous Files: Watermark Failure [NFR-SEC04] — real WatermarkEngineService fails closed on corrupt PDF when watermark is required', async () => {
  const engine = new WatermarkEngineService();
  const corruptedPdfBuffer = Buffer.from('NOT_A_VALID_PDF_BINARY_PAYLOAD');

  await assert.rejects(
    async () =>
      engine.applyWatermarkToPdf(
        corruptedPdfBuffer,
        { id: 88n, username: 'reader_sec', fullName: 'Sec Reader', employeeCode: 'EMP-88' },
        {
          id: randomUUID(),
          title: 'Secret Payload',
          documentCode: 'DOC-SEC-99',
          classificationName: 'SECRET',
          requireWatermark: true,
        },
        {
          id: 1n,
          template_text: '{username} | {documentCode} | {timestamp} | {shortToken}',
          opacity_percent: 30,
          rotation_degrees: -30,
          font_size: 12,
          color_hex: '#991B1B',
          include_qr_code: true,
          is_visible: true,
        },
      ),
    (err) => {
      assert.equal(err.status, 403);
      assert.equal(err.response?.errorCode, AppErrorCode.WATERMARK_GENERATION_FAILED);
      return true;
    },
  );
});
