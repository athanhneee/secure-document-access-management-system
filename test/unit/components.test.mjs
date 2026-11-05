import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  ClassificationRank,
  ClassificationLevelSchema,
  resolveClassificationRank,
  canonicalizeJson,
  DEFAULT_SECURITY_DETECTION_RULES,
} from '../../packages/contracts/dist/index.js';
import { SYSTEM_ROLE_PERMISSION_MATRIX } from '../../apps/api/dist/modules/rbac/permission-matrix.js';
import {
  sanitizeCsvCell,
  formatCsvRow,
} from '../../apps/api/dist/modules/reports/csv-formula-sanitizer.js';

describe('Classification Rank Lattice & Contract Schemas (@sda/contracts)', () => {
  it('resolves all canonical classification codes and legacy RESTRICTED alias monotonically', () => {
    assert.equal(resolveClassificationRank('UNCLASSIFIED'), ClassificationRank.UNCLASSIFIED);
    assert.equal(resolveClassificationRank('  restricted '), ClassificationRank.INTERNAL);
    assert.equal(resolveClassificationRank('INTERNAL'), 1);
    assert.equal(resolveClassificationRank('CONFIDENTIAL'), 2);
    assert.equal(resolveClassificationRank('SECRET'), 3);
    assert.equal(resolveClassificationRank('TOP_SECRET'), 4);
    assert.equal(resolveClassificationRank('UNKNOWN_TIER'), null);
  });

  it('enforces strictly ascending Bell-LaPadula ranks and validates ClassificationLevelSchema', () => {
    const orderedCodes = ['UNCLASSIFIED', 'INTERNAL', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET'];
    const ranks = orderedCodes.map((code) => resolveClassificationRank(code));
    for (let i = 0; i < ranks.length - 1; i++) {
      assert.ok(ranks[i] < ranks[i + 1], 'Ranks must be strictly ascending');
    }

    const secretDto = ClassificationLevelSchema.parse({
      id: 3,
      code: 'SECRET',
      name: 'Tối mật',
      rank: ClassificationRank.SECRET,
      allowDownload: false,
      requireWatermark: true,
      isActive: true,
    });
    assert.equal(secretDto.allowDownload, false);
    assert.equal(secretDto.requireWatermark, true);
  });
});

describe('System Role Permission Matrix & Separation of Duties (@sda/api)', () => {
  it('defines all five system roles and enforces Separation of Duties on document content', () => {
    const roles = Object.keys(SYSTEM_ROLE_PERMISSION_MATRIX);
    assert.deepEqual(roles.sort(), [
      'AUDITOR',
      'DOCUMENT_OWNER',
      'DOCUMENT_READER',
      'SECURITY_OFFICER',
      'SYSTEM_ADMIN',
    ]);

    assert.ok(!SYSTEM_ROLE_PERMISSION_MATRIX.SYSTEM_ADMIN.includes('DOCUMENT_VIEW'));
    assert.ok(!SYSTEM_ROLE_PERMISSION_MATRIX.SYSTEM_ADMIN.includes('DOCUMENT_DOWNLOAD'));
    assert.ok(!SYSTEM_ROLE_PERMISSION_MATRIX.AUDITOR.includes('DOCUMENT_VIEW'));
    assert.ok(SYSTEM_ROLE_PERMISSION_MATRIX.DOCUMENT_OWNER.includes('DOCUMENT_VIEW'));
    assert.ok(SYSTEM_ROLE_PERMISSION_MATRIX.DOCUMENT_READER.includes('DOCUMENT_VIEW'));
  });

  it('exports all 6 canonical SOC intrusion detection rule specifications and RFC 8785 canonical JSON', () => {
    assert.equal(DEFAULT_SECURITY_DETECTION_RULES.length, 6);
    assert.equal(
      canonicalizeJson({ b: 2, a: { y: true, x: 1n } }),
      '{"a":{"x":"1","y":true},"b":2}',
    );
  });
});

describe('CSV Formula Injection Sanitization (CsvFormulaSanitizer)', () => {
  it('escapes cells starting with formula/DDE prefixes and leading-whitespace bypasses', () => {
    assert.equal(sanitizeCsvCell('=1+1'), "'=1+1");
    assert.equal(sanitizeCsvCell('+cmd|...'), "'+cmd|...");
    assert.equal(sanitizeCsvCell('-100'), "'-100");
    assert.equal(sanitizeCsvCell('@SUM(A1:A10)'), "'@SUM(A1:A10)");
    assert.equal(sanitizeCsvCell('\t=macro()'), "'\t=macro()");
    assert.equal(sanitizeCsvCell('   =HYPERLINK("http://evil")'), '\'   =HYPERLINK("http://evil")');
    assert.equal(formatCsvRow(['=1+1', 'Safe, Value']), `'=1+1,"Safe, Value"`);
  });

  it('preserves safe Vietnamese and alphanumeric text cells unchanged', () => {
    assert.equal(sanitizeCsvCell('Nguyen Van A'), 'Nguyen Van A');
    assert.equal(sanitizeCsvCell('DOC-2026-001'), 'DOC-2026-001');
    assert.equal(sanitizeCsvCell('Báo cáo an toàn thông tin'), 'Báo cáo an toàn thông tin');
  });
});
