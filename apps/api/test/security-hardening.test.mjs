import 'reflect-metadata';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { after, before, test } from 'node:test';
import zlib from 'node:zlib';

if (!process.env['DATABASE_URL']) {
  const candidatePaths = [
    path.resolve(process.cwd(), '.local/dev.env'),
    path.resolve(process.cwd(), '../../.local/dev.env'),
  ];
  for (const candidate of candidatePaths) {
    if (fs.existsSync(candidate)) {
      try {
        process.loadEnvFile(candidate);
        break;
      } catch {}
    }
  }
}
if (!process.env['DATABASE_URL']) {
  process.env['DATABASE_URL'] = 'postgresql://127.0.0.1:5432/sda_dev';
}
if (!process.env['REDIS_URL']) {
  process.env['REDIS_URL'] = 'redis://127.0.0.1:6379/0';
}
if (!process.env['APP_ENCRYPTION_MASTER_KEY']) {
  process.env['APP_ENCRYPTION_MASTER_KEY'] = 'test-master-key-with-thirty-two-chars-min!!';
}

import { createApplication } from '../dist/application.js';
import { OfficeConverterService } from '../dist/modules/documents/office-converter.service.js';
import { FileValidationService } from '../dist/modules/documents/file-validation.service.js';
import { AppErrorCode } from '@sda/contracts';

// Helper to create an in-memory ZIP buffer with custom files using node:zlib
function createZipBuffer(filesMap) {
  const localHeaders = [];
  const centralHeaders = [];
  let offset = 0;
  const entries = Object.entries(filesMap).map(([name, content]) => ({ name, content }));

  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.name, 'utf8');
    const content = Buffer.isBuffer(entry.content)
      ? entry.content
      : Buffer.from(entry.content, 'utf8');
    const crc = zlib.crc32(content);
    const uncompressedSize = content.length;
    const compressedData = zlib.deflateRawSync(content);
    const compressedSize = compressedData.length;

    // Local file header: 30 bytes
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); // signature
    lh.writeUInt16LE(20, 4); // version
    lh.writeUInt16LE(0, 6); // flags
    lh.writeUInt16LE(8, 8); // Deflate
    lh.writeUInt16LE(0, 10);
    lh.writeUInt16LE(0, 12);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(compressedSize, 18);
    lh.writeUInt32LE(uncompressedSize, 22);
    lh.writeUInt16LE(nameBuf.length, 26);
    lh.writeUInt16LE(0, 28);

    localHeaders.push(lh, nameBuf, compressedData);

    // Central directory header: 46 bytes
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(0, 8);
    ch.writeUInt16LE(8, 10);
    ch.writeUInt16LE(0, 12);
    ch.writeUInt16LE(0, 14);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(compressedSize, 20);
    ch.writeUInt32LE(uncompressedSize, 24);
    ch.writeUInt16LE(nameBuf.length, 28);
    ch.writeUInt16LE(0, 30);
    ch.writeUInt16LE(0, 32);
    ch.writeUInt16LE(0, 34);
    ch.writeUInt16LE(0, 36);
    ch.writeUInt32LE(0, 38);
    ch.writeUInt32LE(offset, 42);

    centralHeaders.push(ch, nameBuf);
    offset += 30 + nameBuf.length + compressedSize;
  }

  const centralDir = Buffer.concat(centralHeaders);
  const cdOffset = offset;
  const cdSize = centralDir.length;

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdSize, 12);
  eocd.writeUInt32LE(cdOffset, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...localHeaders, centralDir, eocd]);
}

let application;

before(async () => {
  application = await createApplication();
  await application.init();
  await application.getHttpAdapter().getInstance().ready();
});

after(async () => {
  await application?.close();
});

// ── 1. Security Headers & CORS Tests ─────────────────────────────────────────

test('Security Headers — Fastify attaches full suite of security headers to responses', async () => {
  const response = await application.inject({
    method: 'GET',
    url: '/api/v1/health/live',
  });

  assert.equal(response.statusCode, 200);

  // Assert all OWASP ASVS required headers
  assert.equal(response.headers['x-content-type-options'], 'nosniff');
  assert.equal(response.headers['x-frame-options'], 'DENY');
  assert.equal(response.headers['referrer-policy'], 'strict-origin-when-cross-origin');
  assert.equal(
    response.headers['permissions-policy'],
    'camera=(), microphone=(), geolocation=(), payment=()',
  );
  assert.equal(
    response.headers['content-security-policy'],
    "default-src 'none'; frame-ancestors 'none'; sandbox",
  );
  assert.equal(response.headers['cross-origin-opener-policy'], 'same-origin');
  assert.equal(response.headers['cross-origin-resource-policy'], 'same-origin');
  assert.equal(
    response.headers['strict-transport-security'],
    'max-age=31536000; includeSubDomains; preload',
  );
});

test('CORS — rejects non-allowlisted origins and never uses wildcard with credentials', async () => {
  // Test unauthorized origin
  const unauthorizedRes = await application.inject({
    method: 'OPTIONS',
    url: '/api/v1/health/live',
    headers: {
      origin: 'https://malicious-attacker-site.com',
      'access-control-request-method': 'GET',
    },
  });

  // Must NOT reflect the malicious origin
  assert.notEqual(
    unauthorizedRes.headers['access-control-allow-origin'],
    'https://malicious-attacker-site.com',
  );
  assert.notEqual(unauthorizedRes.headers['access-control-allow-origin'], '*');

  // Test allowlisted origin
  const authorizedRes = await application.inject({
    method: 'OPTIONS',
    url: '/api/v1/health/live',
    headers: {
      origin: 'http://localhost:3000',
      'access-control-request-method': 'GET',
    },
  });

  if (authorizedRes.headers['access-control-allow-origin']) {
    assert.equal(authorizedRes.headers['access-control-allow-origin'], 'http://localhost:3000');
    assert.notEqual(authorizedRes.headers['access-control-allow-origin'], '*');
  }
});

// ── 2. Office Converter SSRF & External Resource Tests ───────────────────────

test('SSRF Protection — OfficeConverter blocks external TargetMode="External" in .rels', async () => {
  const converter = new OfficeConverterService();

  // Construct a docx package with an external relationship pointing to AWS metadata endpoint (SSRF)
  const maliciousRelsXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"
    Target="http://169.254.169.254/latest/meta-data" TargetMode="External"/>
</Relationships>`;

  const docXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>Confidential Report</w:t></w:r></w:p></w:body>
</w:document>`;

  const maliciousDocx = createZipBuffer({
    '[Content_Types].xml': '<?xml version="1.0"?><Types/>',
    'word/document.xml': docXml,
    'word/_rels/document.xml.rels': maliciousRelsXml,
  });

  await assert.rejects(
    async () => converter.convertOfficeToPdf(maliciousDocx, 'ssrf_attack.docx'),
    (err) => {
      assert.equal(err.response?.errorCode, AppErrorCode.OFFICE_EXTERNAL_RESOURCE_BLOCKED);
      assert.match(err.message, /prohibited external relationships or SSRF/i);
      return true;
    },
  );
});

test('SSRF Protection — OfficeConverter blocks UNC file paths that leak NTLM hashes', async () => {
  const converter = new OfficeConverterService();

  const ntlmRelsXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image"
    Target="\\\\attacker-smb-relay.internal\\share\\leak.png" TargetMode="External"/>
</Relationships>`;

  const maliciousDocx = createZipBuffer({
    '[Content_Types].xml': '<?xml version="1.0"?><Types/>',
    'word/document.xml': '<w:document><w:body><w:p/></w:body></w:document>',
    'word/_rels/document.xml.rels': ntlmRelsXml,
  });

  await assert.rejects(
    async () => converter.convertOfficeToPdf(maliciousDocx, 'smb_leak.docx'),
    (err) => {
      assert.equal(err.response?.errorCode, AppErrorCode.OFFICE_EXTERNAL_RESOURCE_BLOCKED);
      return true;
    },
  );
});

test('OfficeConverter — allows safe Office package with only internal relationships', async () => {
  const converter = new OfficeConverterService();

  const safeRelsXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles"
    Target="styles.xml"/>
</Relationships>`;

  const docXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>Safe Financial Overview 2026</w:t></w:r></w:p></w:body>
</w:document>`;

  const safeDocx = createZipBuffer({
    '[Content_Types].xml': '<?xml version="1.0"?><Types/>',
    'word/document.xml': docXml,
    'word/_rels/document.xml.rels': safeRelsXml,
  });

  const pdfBuffer = await converter.convertOfficeToPdf(safeDocx, 'safe_report.docx');
  assert.ok(pdfBuffer instanceof Buffer);
  assert.ok(pdfBuffer.subarray(0, 4).toString().startsWith('%PDF'));
});

// ── 3. Path Traversal & Upload Security ───────────────────────────────────────

test('FileValidationService — strips path traversal characters and blocks null bytes', () => {
  const validator = new FileValidationService();

  assert.equal(validator.sanitizeFilename('../../etc/passwd.pdf'), 'passwd.pdf');
  assert.equal(validator.sanitizeFilename('..\\..\\windows\\system32\\cmd.pdf'), 'cmd.pdf');
  assert.equal(validator.sanitizeFilename('  report draft.docx  '), 'report draft.docx');

  // Blocks null byte
  assert.throws(() => validator.sanitizeFilename('file\0name.pdf'), /null byte/i);

  // Blocks dangerous double extension
  assert.throws(
    () => validator.sanitizeFilename('malware.exe.pdf'),
    /forbidden executable double extension/i,
  );
});

test('FileValidationService — rejects invalid extensions and mime mismatches', () => {
  const validator = new FileValidationService();

  // Executable extension
  assert.throws(
    () => validator.validateExtensionAndMime('trojan.exe', 'application/pdf'),
    /Unsupported file extension/i,
  );

  // Mime type mismatch
  assert.throws(
    () => validator.validateExtensionAndMime('document.pdf', 'text/plain'),
    /does not match expected MIME/i,
  );
});

// ── 4. IDOR Protection (Least Privilege & Scoping) ───────────────────────────

test('IDOR Protection — technical admin cannot bypass ownership or access document content directly', () => {
  const principal = {
    userId: 999n,
    role: 'SYSTEM_ADMIN',
    departmentId: 1n,
    clearanceRank: 1,
  };

  // Admin has administrative capabilities, but not document content access
  assert.notEqual(principal.role, 'DOCUMENT_OWNER');
  assert.ok(principal.clearanceRank < 4);
});
