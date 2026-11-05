import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { stripTypeScriptTypes } from 'node:module';
import { test } from 'node:test';
import { AppErrorCode } from '@sda/contracts';
import { buildPgPoolConfig } from '@sda/database';
import { ZipBombGuardService } from '../dist/modules/documents/zip-bomb-guard.service.js';
import { inspectOfficeArchiveSecurity } from '../dist/modules/documents/office-archive-inspector.js';
import {
  createXmlStreamingSecurityScanner,
  inspectOoxmlEntryPathSecurity,
} from '../dist/modules/documents/zip-xml-security.helper.js';
import { WatermarksService } from '../dist/modules/watermarks/watermarks.service.js';
import { createZipBuffer } from './helpers/zip-builder.mjs';

async function loadTsModuleExports(sourceCode) {
  const jsCode = stripTypeScriptTypes(sourceCode);
  return import(`data:text/javascript;base64,${Buffer.from(jsCode, 'utf8').toString('base64')}`);
}

test('[CRITICAL-01] Oversized >5.2 MiB XML with XXE payload is blocked Fail-Closed in both ZipBombGuard and OfficeArchiveInspector', async () => {
  // Use base64 random payload (~1.33:1 deflate ratio) so compression ratio stays well under 100:1
  const largeSafeBody = randomBytes(4 * 1024 * 1024).toString('base64'); // ~5.33 MiB (> both 2 MiB and 5 MiB thresholds)
  const xxeAtTail = `<?xml version="1.0"?><w:document><w:body><w:t>${largeSafeBody}</w:t></w:body><!DOCTYPE xxe [<!ENTITY ext SYSTEM "http://169.254.169.254/latest/meta-data/">]></w:document>`;
  const archive = createZipBuffer([
    { name: '[Content_Types].xml', content: '<?xml version="1.0"?><Types></Types>' },
    { name: 'word/document.xml', content: xxeAtTail },
  ]);

  const zipDefaults = {
    ZIP_MAX_ENTRIES: 1000,
    ZIP_MAX_TOTAL_UNCOMPRESSED_SIZE: 50 * 1024 * 1024,
    ZIP_MAX_DEPTH: 16,
    ZIP_MAX_COMPRESSION_RATIO: 100,
  };
  const guard = new ZipBombGuardService({ get: (key) => zipDefaults[key] });
  await assert.rejects(
    guard.inspectOfficeZip(archive, '.docx'),
    (err) => err.response?.errorCode === AppErrorCode.OFFICE_EXTERNAL_RESOURCE_BLOCKED,
  );
  await assert.rejects(
    inspectOfficeArchiveSecurity(archive),
    (err) => err.response?.errorCode === AppErrorCode.OFFICE_EXTERNAL_RESOURCE_BLOCKED,
  );
});

test('[CRITICAL-01] Split DOCTYPE across chunks, oversized >2 MiB .rels, and canonical xl/externalLinks/externalLink1.xml are blocked', async () => {
  const xmlScanner = createXmlStreamingSecurityScanner(false);
  assert.equal(xmlScanner.push(Buffer.from('<?xml version="1.0"?>\n<!DOC', 'utf8')), null);
  const splitDetected = xmlScanner.push(Buffer.from('TYPE foo SYSTEM "http://evil.test">', 'utf8'));
  assert.equal(
    splitDetected?.getResponse()?.errorCode,
    AppErrorCode.OFFICE_EXTERNAL_RESOURCE_BLOCKED,
  );

  const oversizedRels = randomBytes(1600 * 1024).toString('base64'); // ~2.13 MiB > 2 MiB cap
  const relsArchive = createZipBuffer([
    { name: '[Content_Types].xml', content: '<?xml version="1.0"?><Types></Types>' },
    {
      name: 'word/_rels/document.xml.rels',
      content: `<Relationships>${oversizedRels}</Relationships>`,
    },
  ]);
  await assert.rejects(
    inspectOfficeArchiveSecurity(relsArchive),
    (err) => err.response?.errorCode === AppErrorCode.OFFICE_EXTERNAL_RESOURCE_BLOCKED,
  );

  for (const externalPath of [
    'xl/externallinks/externallink1.xml',
    'externallink1.xml',
    'xl/externallinks/externalallink1.xml',
  ]) {
    const issue = inspectOoxmlEntryPathSecurity(externalPath);
    assert.equal(issue?.getResponse()?.errorCode, AppErrorCode.OFFICE_EXTERNAL_RESOURCE_BLOCKED);
  }
});

test('[CRITICAL-02] buildPgPoolConfig enforces verified TLS by default in production and for Supabase hosts', () => {
  const prevNodeEnv = process.env.NODE_ENV;
  const prevSsl = process.env.DATABASE_SSL;
  const prevReject = process.env.DATABASE_SSL_REJECT_UNAUTHORIZED;

  try {
    delete process.env.DATABASE_SSL;
    delete process.env.DATABASE_SSL_REJECT_UNAUTHORIZED;
    process.env.NODE_ENV = 'production';

    const prodDefault = buildPgPoolConfig(
      'postgresql://app_user:test-placeholder@pg.prod.internal:5432/secure_docs',
    );
    assert.equal(prodDefault.poolConfig.ssl?.rejectUnauthorized, true);
    assert.equal(prodDefault.poolConfig.ssl?.minVersion, 'TLSv1.2');

    process.env.DATABASE_SSL = 'false';
    assert.throws(
      () =>
        buildPgPoolConfig(
          'postgresql://app_user:test-placeholder@pg.prod.internal:5432/secure_docs',
        ),
      /CWE-319/u,
    );
    delete process.env.DATABASE_SSL;

    process.env.NODE_ENV = 'development';
    for (const host of ['db.proj.supabase.co', 'aws-0-ap-southeast-1.pooler.supabase.com']) {
      const supaCfg = buildPgPoolConfig(
        `postgresql://postgres:test-placeholder@${host}:5432/postgres`,
      );
      assert.equal(supaCfg.poolConfig.ssl?.rejectUnauthorized, true);
      assert.equal(supaCfg.poolConfig.ssl?.minVersion, 'TLSv1.2');
    }
  } finally {
    if (prevNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = prevNodeEnv;
    if (prevSsl === undefined) delete process.env.DATABASE_SSL;
    else process.env.DATABASE_SSL = prevSsl;
    if (prevReject === undefined) delete process.env.DATABASE_SSL_REJECT_UNAUTHORIZED;
    else process.env.DATABASE_SSL_REJECT_UNAUTHORIZED = prevReject;
  }
});

test('[CRITICAL-03] Forensic UI helpers fail closed on missing verified flag and never fabricate evidence', async () => {
  const [secHelpersSrc, audHelpersSrc] = await Promise.all([
    readFile(new URL('../../web/app/security/helpers.ts', import.meta.url), 'utf8'),
    readFile(new URL('../../web/app/auditor/helpers.ts', import.meta.url), 'utf8'),
  ]);

  for (const forbidden of [
    '192.168.1.105',
    '192.168.1.10',
    'nguyenvana',
    'hmac-sha256-verified',
    'DOC-SECRET-001',
    'EMP-TRACE',
    'sess-trace',
    "'CONFIDENTIAL'",
    'verified ?? true',
  ]) {
    assert.equal(
      secHelpersSrc.includes(forbidden),
      false,
      `Forbidden literal ${forbidden} in security/helpers.ts`,
    );
    assert.equal(
      audHelpersSrc.includes(forbidden),
      false,
      `Forbidden literal ${forbidden} in auditor/helpers.ts`,
    );
  }

  const [secHelpers, audHelpers] = await Promise.all([
    loadTsModuleExports(secHelpersSrc),
    loadTsModuleExports(audHelpersSrc),
  ]);

  const unverified = secHelpers.mapWatermarkVerifyDto({});
  assert.equal(unverified.verified, false);
  assert.equal(unverified.classificationName, 'Chưa phân loại');
  assert.equal(unverified.ipAddress, '—');

  const mappedAlert = secHelpers.mapAlertDto({ title: 'Test Alert' });
  assert.equal(mappedAlert.ipAddress, '—');
  assert.equal(mappedAlert.detectedUserName, 'Chưa định danh');

  const [mappedLog] = audHelpers.normalizeAuditLogDtos([{}]);
  assert.equal(mappedLog.actorUsername, 'SYSTEM');
  assert.equal(mappedLog.ipAddress, '—');
  assert.equal(mappedLog.entryHash, undefined);

  const wmService = new WatermarksService({
    watermarkInstance: {
      findUnique: async () => ({
        id: 10n,
        watermark_token: 'WM-forensic-ok',
        rendered_text: 'Trace',
        output_sha256_hash: 'a'.repeat(64),
        generated_at: new Date('2026-10-01T00:00:00Z'),
        users: {
          id: 7n,
          username: 'reader1',
          full_name: 'Reader One',
          employee_code: 'E07',
          email: 'r@corp.test',
        },
        access_sessions: {
          id: 'sess-1',
          started_at: new Date('2026-10-01T00:00:00Z'),
          ip_address: '10.0.0.9',
          user_agent: null,
        },
        document_versions: {
          version_no: 1,
          sha256_hash: 'b'.repeat(64),
          document: {
            id: 'doc-1',
            title: 'Real Doc',
            document_code: 'DOC-REAL',
            classification_history: [
              { classification_levels: { code: 'SECRET', name: 'Tối mật' } },
            ],
          },
        },
        watermark_configs: {
          name: 'Default',
          opacity_percent: 25,
          font_size: 14,
          include_qr_code: true,
        },
      }),
    },
  });
  const backendRes = await wmService.verifyWatermarkToken('WM-forensic-ok');
  assert.equal(backendRes.verified, true);
  assert.equal(backendRes.classificationName, 'SECRET');
  assert.equal(secHelpers.mapWatermarkVerifyDto(backendRes).verified, true);
});

test('[CRITICAL-07] CI security workflow enforces blocking Semgrep/Trivy gates and Gitleaks scans test files', async () => {
  const [workflowYml, gitleaksToml] = await Promise.all([
    readFile(new URL('../../../.github/workflows/security.yml', import.meta.url), 'utf8'),
    readFile(new URL('../../../.github/gitleaks.toml', import.meta.url), 'utf8'),
  ]);

  assert.doesNotMatch(workflowYml, /continue-on-error:\s*true/u);
  assert.match(workflowYml, /semgrep scan[^\r\n]*--error/u);
  assert.match(workflowYml, /exit-code:\s*'1'/u);

  assert.doesNotMatch(gitleaksToml, /\(\^\|\/\)test\//u);
  assert.doesNotMatch(gitleaksToml, /\\\.test\\\./u);
  assert.doesNotMatch(gitleaksToml, /\\\.spec\\\./u);
});
