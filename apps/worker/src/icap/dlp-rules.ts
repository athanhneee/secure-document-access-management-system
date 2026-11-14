import type { DlpPolicyAction, DlpScanOptions, DlpScanResult, DlpViolation } from './icap.types.js';
import { normalizeDlpText } from './dlp-decoders.js';

/**
 * Thuật toán: Kiểm tra tổng kiểm Luhn (Modulo-10 Checksum) cho dãy số thẻ thanh toán quốc tế (13..19 chữ số).
 */
export function isValidLuhnCard(cardNumber: string): boolean {
  const cleaned = cardNumber.replace(/\D/gu, '');
  if (cleaned.length < 13 || cleaned.length > 19) return false;

  let sum = 0;
  let alternate = false;
  for (let i = cleaned.length - 1; i >= 0; i--) {
    let digit = parseInt(cleaned.charAt(i), 10);
    if (alternate) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

/**
 * Thuật toán: Che giấu thông tin nhạy cảm (Partial Redaction Masking) cho bằng chứng pháp chứng.
 */
export function maskSensitiveSnippet(text: string): string {
  const trimmed = text.trim();
  if (trimmed.length <= 6) return '***';
  return `${trimmed.slice(0, 3)}****${trimmed.slice(-3)}`;
}

/**
 * Thuật toán: Đối sánh tập luật DLP tuyến tính trên mọi bề mặt văn bản đã chuẩn hóa (URI, Header, URL-decoded,
 * Base64-decoded, UTF-16LE, OOXML `.docx`/`.xlsx`), khử trùng lặp vi phạm theo mã `rule`.
 */
export function evaluateDlpTextSurfaces(
  surfaces: readonly string[],
  scannedBytes: number,
  config?: DlpScanOptions,
  initialViolations: DlpViolation[] = [],
): DlpScanResult {
  const violations: DlpViolation[] = [...initialViolations];
  const seenRules = new Set<string>(violations.map((v) => v.rule));
  const recordViolation = (v: DlpViolation): void => {
    if (!seenRules.has(v.rule)) {
      seenRules.add(v.rule);
      violations.push(v);
    }
  };

  const normalizedKeywords = (config?.customKeywords ?? [])
    .map((kw) => normalizeDlpText(kw.trim()))
    .filter((kw) => kw.length > 0);

  for (const text of surfaces) {
    let match: RegExpExecArray | null;

    const topSecretRegex =
      /(?<![\p{L}\p{N}_])(TUYỆT\s*MẬT|TOP\s*SECRET|TỐI\s*MẬT|BÍ\s*MẬT\s*NHÀ\s*NƯỚC|MẬT\s*QUÂN\s*SỰ)(?![\p{L}\p{N}_])/giu;
    if ((match = topSecretRegex.exec(text)) !== null) {
      recordViolation({
        type: 'TOP_SECRET_CLASSIFICATION',
        severity: 'CRITICAL',
        rule: 'RULE_TOP_SECRET_EGRESS_PREVENTION',
        description:
          'Phát hiện dữ liệu chứa dấu hiệu phân loại mật cấp quốc gia (Tuyệt Mật / Tối Mật / Top Secret).',
        matchedSnippet: match[0],
      });
    }

    if (!seenRules.has('RULE_TOP_SECRET_EGRESS_PREVENTION')) {
      const confidentialRegex =
        /(?<![\p{L}\p{N}_])(STRICTLY\s*CONFIDENTIAL|CONFIDENTIAL|BÍ\s*MẬT\s*NỘI\s*BỘ|TÀI\s*LIỆU\s*MẬT)(?![\p{L}\p{N}_])/giu;
      if ((match = confidentialRegex.exec(text)) !== null) {
        recordViolation({
          type: 'TOP_SECRET_CLASSIFICATION',
          severity: 'HIGH',
          rule: 'RULE_CONFIDENTIAL_DATA_EGRESS',
          description:
            'Phát hiện tài liệu phân loại Mật nội bộ doanh nghiệp đang cố gắng gửi ra ngoài biên mạng.',
          matchedSnippet: match[0],
        });
      }
    }

    const privateKeyRegex = /-----BEGIN\s+(?:(?:RSA|EC|DSA|OPENSSH|PGP)\s+)?PRIVATE\s+KEY-----/giu;
    if ((match = privateKeyRegex.exec(text)) !== null) {
      recordViolation({
        type: 'PRIVATE_KEY_CREDENTIAL',
        severity: 'CRITICAL',
        rule: 'RULE_PRIVATE_KEY_LEAK_PREVENTION',
        description:
          'Phát hiện khóa bí mật bất đối xứng (Private Key) chuẩn PEM trong dòng dữ liệu.',
        matchedSnippet: maskSensitiveSnippet(match[0]),
      });
    }

    const awsKeyRegex = /\bAKIA[0-9A-Z]{16}\b/gu;
    if ((match = awsKeyRegex.exec(text)) !== null) {
      recordViolation({
        type: 'PRIVATE_KEY_CREDENTIAL',
        severity: 'CRITICAL',
        rule: 'RULE_CLOUD_CREDENTIAL_LEAK',
        description: 'Phát hiện khóa truy cập AWS Access Key ID trong dòng dữ liệu.',
        matchedSnippet: maskSensitiveSnippet(match[0]),
      });
    }

    const githubTokenRegex = /\bgh[pousr]_[0-9a-zA-Z]{36}\b/gu;
    if ((match = githubTokenRegex.exec(text)) !== null) {
      recordViolation({
        type: 'PRIVATE_KEY_CREDENTIAL',
        severity: 'HIGH',
        rule: 'RULE_API_TOKEN_LEAK',
        description: 'Phát hiện mã định danh GitHub Personal Access Token.',
        matchedSnippet: maskSensitiveSnippet(match[0]),
      });
    }

    const watermarkTokenRegex = /(?<![\p{L}\p{N}_])WM-[0-9a-f]{12,64}(?![\p{L}\p{N}_])/giu;
    if ((match = watermarkTokenRegex.exec(text)) !== null) {
      recordViolation({
        type: 'FORENSIC_WATERMARK_LEAK',
        severity: 'CRITICAL',
        rule: 'RULE_WATERMARK_TOKEN_EXFILTRATION',
        description: 'Phát hiện chuỗi mã Watermark Token pháp chứng gắn với tài liệu mật.',
        matchedSnippet: maskSensitiveSnippet(match[0]),
      });
    }

    if (!seenRules.has('RULE_PCI_DSS_CREDIT_CARD_LEAK')) {
      const cardCandidateRegex = /\b(?:\d{4}[ -]?){3}\d{4}\b|\b\d{13,19}\b/gu;
      while ((match = cardCandidateRegex.exec(text)) !== null) {
        const rawNumber = match[0].replace(/[\s-]/gu, '');
        if (isValidLuhnCard(rawNumber)) {
          recordViolation({
            type: 'PAYMENT_CARD_DATA',
            severity: 'HIGH',
            rule: 'RULE_PCI_DSS_CREDIT_CARD_LEAK',
            description:
              'Phát hiện số thẻ thanh toán quốc tế (Visa/MasterCard) thỏa mãn thuật toán Luhn.',
            matchedSnippet: maskSensitiveSnippet(match[0]),
          });
          break;
        }
      }
    }

    const cccdRegex = /\b0\d{2}[0-3]\d{2}\d{6}\b/gu;
    if ((match = cccdRegex.exec(text)) !== null) {
      recordViolation({
        type: 'CITIZEN_IDENTITY_DATA',
        severity: 'MEDIUM',
        rule: 'RULE_VIETNAM_CCCD_PII_LEAK',
        description: 'Phát hiện số căn cước công dân Việt Nam 12 chữ số hợp lệ.',
        matchedSnippet: maskSensitiveSnippet(match[0]),
      });
    }

    if (normalizedKeywords.length > 0 && !seenRules.has('RULE_CUSTOM_POLICY_KEYWORD_MATCH')) {
      const loweredText = text.toLowerCase();
      for (const kw of normalizedKeywords) {
        if (loweredText.includes(kw.toLowerCase())) {
          const maskedKw = maskSensitiveSnippet(kw);
          recordViolation({
            type: 'CUSTOM_POLICY_KEYWORD',
            severity: 'HIGH',
            rule: 'RULE_CUSTOM_POLICY_KEYWORD_MATCH',
            description: `Phát hiện từ khóa vi phạm chính sách nội bộ: "${maskedKw}".`,
            matchedSnippet: maskedKw,
          });
          break;
        }
      }
    }
  }

  const severityRank: Record<string, number> = {
    CRITICAL: 4,
    HIGH: 3,
    MEDIUM: 2,
    LOW: 1,
  };
  violations.sort((a, b) => (severityRank[b.severity] ?? 0) - (severityRank[a.severity] ?? 0));

  const isClean = violations.length === 0;
  const action: DlpPolicyAction = isClean
    ? 'ALLOW'
    : config?.action === 'AUDIT_ONLY'
      ? 'AUDIT'
      : 'BLOCK';

  return { action, violations, scannedBytes, isClean };
}
