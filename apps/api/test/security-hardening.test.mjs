import 'reflect-metadata';
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';

process.env['NODE_ENV'] = 'test';
process.env['STORAGE_MOCK'] = 'true';
process.env['GOTENBERG_ENABLED'] = 'false';
process.env['DATABASE_URL'] = 'postgresql://127.0.0.1:1/isolated_security_hardening_test';
process.env['REDIS_URL'] = 'redis://127.0.0.1:1/0';
process.env['APP_ENCRYPTION_MASTER_KEY'] = 'test-master-key-with-thirty-two-chars-min!!';

import { disconnectDatabase } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import { createApplication } from '../dist/application.js';
import { OfficeConverterService } from '../dist/modules/documents/office-converter.service.js';
import { FileValidationService } from '../dist/modules/documents/file-validation.service.js';
import { DocumentPepService } from '../dist/modules/documents/document-pep.service.js';
import { createZipBuffer } from './helpers/zip-builder.mjs';

let application;

before(async () => {
  application = await createApplication();
  await application.init();
  await application.getHttpAdapter().getInstance().ready();
});

after(async () => {
  await application?.close();
  await disconnectDatabase();
});

test('Security Headers — Fastify attaches full suite of security headers to responses', async () => {
  const response = await application.inject({
    method: 'GET',
    url: '/api/v1/health/live',
  });

  assert.equal(response.statusCode, 200);
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
  const unauthorizedRes = await application.inject({
    method: 'OPTIONS',
    url: '/api/v1/health/live',
    headers: {
      origin: 'https://malicious-attacker-site.com',
      'access-control-request-method': 'GET',
    },
  });

  assert.notEqual(
    unauthorizedRes.headers['access-control-allow-origin'],
    'https://malicious-attacker-site.com',
  );
  assert.notEqual(unauthorizedRes.headers['access-control-allow-origin'], '*');

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

test('SSRF Protection — OfficeConverter blocks external TargetMode="External" in .rels', async () => {
  const converter = new OfficeConverterService();

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

test('FileValidationService — strips path traversal characters and blocks null bytes', () => {
  const validator = new FileValidationService();

  assert.equal(validator.sanitizeFilename('../../etc/passwd.pdf'), 'passwd.pdf');
  assert.equal(validator.sanitizeFilename('..\\..\\windows\\system32\\cmd.pdf'), 'cmd.pdf');
  assert.equal(validator.sanitizeFilename('  report draft.docx  '), 'report draft.docx');

  assert.throws(() => validator.sanitizeFilename('file\0name.pdf'), /null byte/i);
  assert.throws(
    () => validator.sanitizeFilename('malware.exe.pdf'),
    /forbidden executable double extension/i,
  );
});

test('FileValidationService — rejects invalid extensions and mime mismatches', () => {
  const validator = new FileValidationService();

  assert.throws(
    () => validator.validateExtensionAndMime('trojan.exe', 'application/pdf'),
    /Unsupported file extension/i,
  );

  assert.throws(
    () => validator.validateExtensionAndMime('document.pdf', 'text/plain'),
    /does not match expected MIME/i,
  );
});

test('IDOR & SoD Protection — real DocumentPepService blocks SYSTEM_ADMIN and AUDITOR from accessing document content', async () => {
  const deniedAuditEvents = [];
  const pep = new DocumentPepService(
    { evaluate: async () => ({ decision: 'PERMIT', obligations: [] }) },
    {},
    {
      record: async (event) => {
        deniedAuditEvents.push(event);
      },
    },
    {},
  );

  for (const restrictedRole of ['SYSTEM_ADMIN', 'AUDITOR']) {
    await assert.rejects(
      async () =>
        pep.enforceAccess(
          '11111111-1111-4111-8111-111111111111',
          {
            userId: 999n,
            sessionId: 'sess-sod-1',
            username: `user_${restrictedRole.toLowerCase()}`,
            roles: [restrictedRole],
            mfa: true,
          },
          { ip: '10.0.0.5', correlationId: 'corr-sod-1' },
          { action: 'VIEW' },
        ),
      (err) => {
        assert.equal(err.status, 403);
        assert.equal(err.response?.errorCode, AppErrorCode.DOCUMENT_ACCESS_DENIED);
        return true;
      },
    );
  }

  assert.equal(deniedAuditEvents.length, 2);
  assert.ok(deniedAuditEvents.every((e) => e.outcome === 'DENIED'));
});
