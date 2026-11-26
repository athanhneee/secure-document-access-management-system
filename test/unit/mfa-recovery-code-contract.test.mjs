import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../..');

/**
 * Thuật toán: Kiểm Chứng Hợp Đồng Bảo Toàn Chữ Hoa/Thường Mã Khôi Phục MFA Base64URL (`BUG-001`)
 * Mục đích: Đảm bảo ô nhập mã khôi phục trên `/mfa` và hộp thoại tắt MFA trên `/sessions` không ép `.toUpperCase()`,
 *   vô hiệu hóa tự viết hoa/sửa lỗi bàn phím (`autoCapitalize="none"`, `autoCorrect="off"`, `spellCheck={false}`),
 *   khớp ràng buộc độ dài `16..64` với Zod schema backend và thông báo rõ tính phân biệt chữ HOA/thường.
 */
describe('BUG-001 — Case-Sensitive Base64URL MFA Recovery Code FE↔BE Contract', () => {
  it('preserves exact casing and disables keyboard auto-capitalization in MfaMethodCards', () => {
    const cardsSrc = fs.readFileSync(
      path.join(repoRoot, 'apps/web/app/mfa/mfa-method-cards.tsx'),
      'utf8',
    );

    assert.doesNotMatch(
      cardsSrc,
      /onChangeRecoveryCode\([^)]*\.toUpperCase\(\)/u,
      'MfaMethodCards must never uppercase Base64URL recovery codes',
    );
    assert.doesNotMatch(
      cardsSrc,
      /ABCD-EFGH-IJKL-MNOP/u,
      'MfaMethodCards must not display obsolete uppercase-grouped placeholder',
    );
    assert.match(cardsSrc, /onChange=\{\(e\) => onChangeRecoveryCode\(e\.target\.value\)\}/u);
    assert.match(cardsSrc, /autoCapitalize="none"/u);
    assert.match(cardsSrc, /autoCorrect="off"/u);
    assert.match(cardsSrc, /spellCheck=\{false\}/u);
    assert.match(cardsSrc, /maxLength=\{64\}/u);
    assert.match(cardsSrc, /HOA\/thường/u);
  });

  it('validates 16..64 length and submits trimmed verbatim recoveryCode in /mfa/page.tsx', () => {
    const pageSrc = fs.readFileSync(path.join(repoRoot, 'apps/web/app/mfa/page.tsx'), 'utf8');

    assert.doesNotMatch(pageSrc, /recoveryCode[^;\n]*\.toUpperCase\(\)/u);
    assert.match(
      pageSrc,
      /trimmedRecoveryCode\.length < 16 \|\| trimmedRecoveryCode\.length > 64/u,
    );
    assert.match(pageSrc, /\{\s*recoveryCode:\s*trimmedRecoveryCode\s*\}/u);
  });

  it('hardens disable-MFA recovery input and clarifies case sensitivity on generated code views', () => {
    const factorsSrc = fs.readFileSync(
      path.join(repoRoot, 'apps/web/app/sessions/mfa-factors-card.tsx'),
      'utf8',
    );
    const recoveryCardSrc = fs.readFileSync(
      path.join(repoRoot, 'apps/web/app/mfa/mfa-recovery-codes-card.tsx'),
      'utf8',
    );
    const passkeyCardSrc = fs.readFileSync(
      path.join(repoRoot, 'apps/web/app/sessions/passkey-enrollment-card.tsx'),
      'utf8',
    );

    assert.doesNotMatch(factorsSrc, /setDisableCode\([^)]*\.toUpperCase\(\)/u);
    assert.match(factorsSrc, /trimmedCode\.length >= 16 && trimmedCode\.length <= 64/u);
    assert.match(factorsSrc, /autoCapitalize="none"/u);
    assert.match(factorsSrc, /autoCorrect="off"/u);
    assert.match(factorsSrc, /spellCheck=\{false\}/u);
    assert.match(factorsSrc, /id="remove-mfa-password"/u);
    assert.match(factorsSrc, /id="remove-mfa-code"/u);
    assert.match(factorsSrc, /currentPassword:\s*removePassword/u);
    assert.match(recoveryCardSrc, /HOA\/thường/u);
    assert.match(passkeyCardSrc, /HOA\/thường/u);
  });

  it('keeps backend Base64URL generation case-sensitive while trimming whitespace in Zod schemas', () => {
    const mfaServiceSrc = fs.readFileSync(
      path.join(repoRoot, 'apps/api/src/modules/auth/mfa.service.ts'),
      'utf8',
    );
    const authSchemasSrc = fs.readFileSync(
      path.join(repoRoot, 'apps/api/src/modules/auth/auth.schemas.ts'),
      'utf8',
    );

    assert.match(mfaServiceSrc, /randomBytes\(16\)\.toString\('base64url'\)/u);
    assert.match(mfaServiceSrc, /code\.normalize\('NFKC'\)/u);
    assert.match(
      authSchemasSrc,
      /recoveryCode:\s*z\.string\(\)\.trim\(\)\.min\(16\)\.max\(64\)\.optional\(\)/u,
    );
  });
});
