import type { DlpScanResult, DlpViolation, DlpPolicyAction } from './icap.types.js';

export class DlpEngine {
  /**
   * Luhn algorithm validation for credit card numbers (prevents false positives).
   */
  public static isValidLuhn(cardNumber: string): boolean {
    const cleaned = cardNumber.replace(/\D/gu, '');
    if (cleaned.length < 13 || cleaned.length > 19) {
      return false;
    }

    let sum = 0;
    let alternate = false;

    for (let i = cleaned.length - 1; i >= 0; i--) {
      let digit = parseInt(cleaned.charAt(i), 10);

      if (alternate) {
        digit *= 2;
        if (digit > 9) {
          digit -= 9;
        }
      }

      sum += digit;
      alternate = !alternate;
    }

    return sum % 10 === 0;
  }

  /**
   * Masks sensitive string snippet for secure audit logging without leaking full secret.
   */
  public static maskSnippet(text: string): string {
    const trimmed = text.trim();
    if (trimmed.length <= 6) {
      return '***';
    }
    const prefix = trimmed.slice(0, 3);
    const suffix = trimmed.slice(-3);
    return `${prefix}****${suffix}`;
  }

  /**
   * Scans a payload buffer against comprehensive data loss prevention (DLP) rules.
   */
  public static scanPayload(
    buffer: Buffer,
    config?: {
      customKeywords?: string[] | undefined;
      action?: 'BLOCK' | 'AUDIT_ONLY' | undefined;
    },
  ): DlpScanResult {
    const violations: DlpViolation[] = [];
    const text = buffer.toString('utf-8');
    const scannedBytes = buffer.length;

    // Rule 1: National Security Classification & Top Secret Markers
    const topSecretRegex =
      /\b(TUYỆT\s*MẬT|TOP\s*SECRET|TỐI\s*MẬT|BÍ\s*MẬT\s*NHÀ\s*NƯỚC|MẬT\s*QUÂN\s*SỰ)\b/giu;
    let match: RegExpExecArray | null;
    while ((match = topSecretRegex.exec(text)) !== null) {
      violations.push({
        type: 'TOP_SECRET_CLASSIFICATION',
        severity: 'CRITICAL',
        rule: 'RULE_TOP_SECRET_EGRESS_PREVENTION',
        description:
          'Phát hiện dữ liệu chứa dấu hiệu phân loại mật cấp quốc gia (Tuyệt Mật / Tối Mật / Top Secret).',
        matchedSnippet: match[0],
      });
      break; // One match per category is sufficient
    }

    // Rule 1b: Confidential / Restricted Markers
    if (violations.length === 0) {
      const confidentialRegex = /\b(CONFIDENTIAL|BÍ\s*MẬT\s*NỘI\s*BỘ)\b/giu;
      if ((match = confidentialRegex.exec(text)) !== null) {
        violations.push({
          type: 'TOP_SECRET_CLASSIFICATION',
          severity: 'HIGH',
          rule: 'RULE_CONFIDENTIAL_DATA_EGRESS',
          description:
            'Phát hiện tài liệu phân loại Mật nội bộ doanh nghiệp đang cố gắng gửi ra ngoài biên mạng.',
          matchedSnippet: match[0],
        });
      }
    }

    // Rule 2: Cryptographic Private Keys & API Credentials
    const privateKeyRegex = /-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----/giu;
    if ((match = privateKeyRegex.exec(text)) !== null) {
      violations.push({
        type: 'PRIVATE_KEY_CREDENTIAL',
        severity: 'CRITICAL',
        rule: 'RULE_PRIVATE_KEY_LEAK_PREVENTION',
        description:
          'Phát hiện khóa bí mật bất đối xứng (Private Key) chuẩn PEM trong dòng dữ liệu.',
        matchedSnippet: this.maskSnippet(match[0]),
      });
    }

    const awsKeyRegex = /\bAKIA[0-9A-Z]{16}\b/gu;
    if ((match = awsKeyRegex.exec(text)) !== null) {
      violations.push({
        type: 'PRIVATE_KEY_CREDENTIAL',
        severity: 'CRITICAL',
        rule: 'RULE_CLOUD_CREDENTIAL_LEAK',
        description: 'Phát hiện khóa truy cập AWS Access Key ID trong dòng dữ liệu.',
        matchedSnippet: this.maskSnippet(match[0]),
      });
    }

    const githubTokenRegex = /\bgh[pousr]_[0-9a-zA-Z]{36}\b/gu;
    if ((match = githubTokenRegex.exec(text)) !== null) {
      violations.push({
        type: 'PRIVATE_KEY_CREDENTIAL',
        severity: 'HIGH',
        rule: 'RULE_API_TOKEN_LEAK',
        description: 'Phát hiện mã định danh GitHub Personal Access Token.',
        matchedSnippet: this.maskSnippet(match[0]),
      });
    }

    // Rule 3: Forensic Watermark Token Leak Detection (WM-...)
    const watermarkTokenRegex = /\bWM-[a-f0-9]{48}\b/giu;
    if ((match = watermarkTokenRegex.exec(text)) !== null) {
      violations.push({
        type: 'FORENSIC_WATERMARK_LEAK',
        severity: 'CRITICAL',
        rule: 'RULE_WATERMARK_TOKEN_EXFILTRATION',
        description: 'Phát hiện chuỗi mã Watermark Token pháp chứng 48-hex gắn với tài liệu mật.',
        matchedSnippet: this.maskSnippet(match[0]),
      });
    }

    // Rule 4: Payment Card Numbers with Luhn Validation (PCI-DSS)
    const cardCandidateRegex = /\b(?:\d{4}[ -]?){3}\d{4}\b|\b\d{13,19}\b/gu;
    while ((match = cardCandidateRegex.exec(text)) !== null) {
      const rawNumber = match[0].replace(/[\s-]/gu, '');
      if (this.isValidLuhn(rawNumber)) {
        violations.push({
          type: 'PAYMENT_CARD_DATA',
          severity: 'HIGH',
          rule: 'RULE_PCI_DSS_CREDIT_CARD_LEAK',
          description:
            'Phát hiện số thẻ thanh toán quốc tế (Visa/MasterCard) thỏa mãn thuật toán Luhn.',
          matchedSnippet: this.maskSnippet(match[0]),
        });
        break;
      }
    }

    // Rule 5: Vietnam Citizen Identity Card (CCCD 12 digits)
    const cccdRegex = /\b0\d{2}[0-3]\d{2}\d{6}\b/gu;
    if ((match = cccdRegex.exec(text)) !== null) {
      violations.push({
        type: 'CITIZEN_IDENTITY_DATA',
        severity: 'MEDIUM',
        rule: 'RULE_VIETNAM_CCCD_PII_LEAK',
        description: 'Phát hiện số căn cước công dân Việt Nam 12 chữ số hợp lệ.',
        matchedSnippet: this.maskSnippet(match[0]),
      });
    }

    // Rule 6: Custom Organization Keywords
    if (config?.customKeywords && config.customKeywords.length > 0) {
      for (const kw of config.customKeywords) {
        const trimmed = kw.trim();
        if (trimmed && text.toLowerCase().includes(trimmed.toLowerCase())) {
          violations.push({
            type: 'CUSTOM_POLICY_KEYWORD',
            severity: 'HIGH',
            rule: 'RULE_CUSTOM_POLICY_KEYWORD_MATCH',
            description: `Phát hiện từ khóa vi phạm chính sách nội bộ: "${trimmed}".`,
            matchedSnippet: trimmed,
          });
          break;
        }
      }
    }

    // Determine final enforcement action
    const isClean = violations.length === 0;
    let action: DlpPolicyAction = 'ALLOW';

    if (!isClean) {
      const isAuditOnly = config?.action === 'AUDIT_ONLY';
      action = isAuditOnly ? 'AUDIT' : 'BLOCK';
    }

    return {
      action,
      violations,
      scannedBytes,
      isClean,
    };
  }
}
