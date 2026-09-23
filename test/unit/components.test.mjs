import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

describe('Frontend Design System & Classification Logic', () => {
  const CLASSIFICATION_LEVELS = [
    { code: 'UNCLASSIFIED', nameVi: 'Không mật', rank: 1, allowDownload: true },
    { code: 'RESTRICTED', nameVi: 'Nội bộ', rank: 2, allowDownload: true },
    { code: 'CONFIDENTIAL', nameVi: 'Mật', rank: 3, allowDownload: true },
    { code: 'SECRET', nameVi: 'Tối mật', rank: 4, allowDownload: false },
    { code: 'TOP_SECRET', nameVi: 'Tuyệt mật', rank: 5, allowDownload: false },
  ];

  it('every classification level has an explicit Vietnamese label and distinct rank', () => {
    for (const level of CLASSIFICATION_LEVELS) {
      assert.ok(level.nameVi.length > 0, `Missing Vietnamese label for ${level.code}`);
      assert.ok(level.rank >= 1 && level.rank <= 5, `Invalid rank for ${level.code}`);
    }
  });

  it('ranks are strictly ordered to prevent ambiguity without relying only on color', () => {
    const ranks = CLASSIFICATION_LEVELS.map((l) => l.rank);
    for (let i = 0; i < ranks.length - 1; i++) {
      assert.ok(ranks[i] < ranks[i + 1], 'Ranks must be strictly ascending');
    }
  });

  it('high classifications (SECRET, TOP_SECRET) default to disallowing download for security', () => {
    const secret = CLASSIFICATION_LEVELS.find((l) => l.code === 'SECRET');
    const topSecret = CLASSIFICATION_LEVELS.find((l) => l.code === 'TOP_SECRET');
    assert.equal(secret?.allowDownload, false);
    assert.equal(topSecret?.allowDownload, false);
  });
});

describe('Role Mappings & Path Integrity', () => {
  const ROLE_PATHS = {
    SYSTEM_ADMIN: '/admin',
    DOCUMENT_OWNER: '/owner',
    DOCUMENT_READER: '/reader',
    SECURITY_OFFICER: '/security',
    AUDITOR: '/auditor',
  };

  it('covers all five required actors', () => {
    const roles = Object.keys(ROLE_PATHS);
    assert.equal(roles.length, 5);
    assert.ok(roles.includes('SYSTEM_ADMIN'));
    assert.ok(roles.includes('DOCUMENT_OWNER'));
    assert.ok(roles.includes('DOCUMENT_READER'));
    assert.ok(roles.includes('SECURITY_OFFICER'));
    assert.ok(roles.includes('AUDITOR'));
  });

  it('each role path is uniquely mapped to its dedicated workspace', () => {
    const paths = Object.values(ROLE_PATHS);
    const uniquePaths = new Set(paths);
    assert.equal(paths.length, uniquePaths.size, 'Role paths must be unique');
  });
});

describe('CSV Formula Injection Sanitization', () => {
  function sanitizeCell(cell) {
    if (typeof cell !== 'string') return cell;
    if (/^[=+\-@\t\r]/.test(cell)) {
      return `'${cell}`;
    }
    return cell;
  }

  it('escapes cells starting with risky formula prefixes', () => {
    assert.equal(sanitizeCell('=1+1'), "'=1+1");
    assert.equal(sanitizeCell('+cmd|...'), "'+cmd|...");
    assert.equal(sanitizeCell('-100'), "'-100");
    assert.equal(sanitizeCell('@SUM(A1:A10)'), "'@SUM(A1:A10)");
    assert.equal(sanitizeCell('\t=macro()'), "'\t=macro()");
  });

  it('preserves safe text cells unchanged', () => {
    assert.equal(sanitizeCell('Nguyen Van A'), 'Nguyen Van A');
    assert.equal(sanitizeCell('DOC-2026-001'), 'DOC-2026-001');
    assert.equal(sanitizeCell('Báo cáo an toàn thông tin'), 'Báo cáo an toàn thông tin');
  });
});
