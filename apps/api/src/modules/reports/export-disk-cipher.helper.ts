/**
 * Module: At-Rest AES-256-GCM Cipher & Integrity Guard for Export Disk Artifacts
 * Thuật toán: Mã hóa xác thực AES-256-GCM gắn ngữ cảnh AAD (`jobId`), dẫn xuất khóa HKDF-SHA256
 *   từ bí mật tiến trình và kiểm chứng lại băm SHA-256 bản rõ trước khi trả tệp `.dat`.
 */
import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

const EXPORT_MAGIC = Buffer.from('SDEA\x01', 'binary');
const IV_BYTES = 12;
const TAG_BYTES = 16;
const EPHEMERAL_FALLBACK_KEY = randomBytes(32);

/**
 * Thuật toán: Dẫn xuất khóa 256-bit bằng HKDF-SHA256 cho vùng lưu trữ tạm `.dat` trên đĩa.
 */
function resolveExportAtRestKey(): Buffer {
  const configured =
    process.env['EXPORT_ENCRYPTION_KEY']?.trim() || process.env['AUDIT_INTEGRITY_KEY']?.trim();
  const ikm = configured ? Buffer.from(configured, 'utf8') : EPHEMERAL_FALLBACK_KEY;
  return Buffer.from(
    hkdfSync(
      'sha256',
      ikm,
      Buffer.from('sda-export-at-rest-salt-v1', 'utf8'),
      Buffer.from('sda-export-artifact-aes-256-gcm', 'utf8'),
      32,
    ),
  );
}

/**
 * Thuật toán: Đóng gói nhị phân `SDEA\x01 || IV(12B) || TAG(16B) || CIPHERTEXT` với AAD = `jobId`.
 */
export function encryptExportArtifactBuffer(jobId: string, plaintext: Buffer): Buffer {
  const key = resolveExportAtRestKey();
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(jobId, 'utf8'));
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([EXPORT_MAGIC, iv, tag, encrypted]);
}

/**
 * Thuật toán: Giải mã xác thực AES-256-GCM kèm đối chiếu `expectedSha256Hash` của bản rõ.
 */
export function decryptAndVerifyExportArtifactBuffer(
  jobId: string,
  payload: Buffer,
  expectedSha256Hash?: string | null,
  requireEncryptedEnvelope = false,
): Buffer | null {
  let plaintext: Buffer;
  const hasEnvelope =
    payload.length >= EXPORT_MAGIC.length + IV_BYTES + TAG_BYTES &&
    payload.subarray(0, EXPORT_MAGIC.length).equals(EXPORT_MAGIC);
  if (hasEnvelope) {
    try {
      const key = resolveExportAtRestKey();
      const ivStart = EXPORT_MAGIC.length;
      const tagStart = ivStart + IV_BYTES;
      const bodyStart = tagStart + TAG_BYTES;
      // CONFLICT-RESOLVED: Khai báo tường minh `authTagLength: TAG_BYTES` (16 byte) cho AES-256-GCM để chống tấn công rút ngắn thẻ xác thực (Semgrep gcm-no-tag-length).
      const decipher = createDecipheriv('aes-256-gcm', key, payload.subarray(ivStart, tagStart), {
        authTagLength: TAG_BYTES,
      });
      decipher.setAAD(Buffer.from(jobId, 'utf8'));
      decipher.setAuthTag(payload.subarray(tagStart, bodyStart));
      plaintext = Buffer.concat([decipher.update(payload.subarray(bodyStart)), decipher.final()]);
    } catch {
      return null;
    }
  } else if (requireEncryptedEnvelope) {
    return null;
  } else {
    plaintext = payload;
  }

  if (expectedSha256Hash) {
    const digest = createHash('sha256').update(plaintext).digest('hex');
    if (digest !== expectedSha256Hash) {
      return null;
    }
  }
  return plaintext;
}

/**
 * Thuật toán: Đọc nguyên tử qua File Descriptor không kiểm tra đường dẫn trước (`O_NOFOLLOW` + `fstatSync(fd)`) chống đua thời gian TOCTOU (`CWE-367`).
 */
export function readContainedExportArtifactBuffer(resolvedTarget: string): Buffer | null {
  let fd: number | undefined;
  try {
    // CONFLICT-RESOLVED: Mở trực tiếp file descriptor một lần với cờ O_NOFOLLOW rồi thẩm định bằng fstatSync(fd) thay vì existsSync/lstatSync trước readFileSync để triệt tiêu TOCTOU (CodeQL js/file-system-race).
    const openFlags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0);
    fd = fs.openSync(resolvedTarget, openFlags);
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) {
      return null;
    }
    return fs.readFileSync(fd);
  } catch {
    return null;
  } finally {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch {
        // Ignore descriptor close failure
      }
    }
  }
}

/**
 * Thuật toán: Xóa an toàn tệp xuất hết hạn có kiểm tra giam cầm đường dẫn (Bounded Path Containment Unlink).
 */
export function unlinkContainedExportArtifact(exportBaseDir: string, filePath: string): boolean {
  const resolvedBase = path.resolve(exportBaseDir);
  const resolvedTarget = path.resolve(filePath);
  const relative = path.relative(resolvedBase, resolvedTarget);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) {
    return false;
  }
  try {
    const stat = fs.lstatSync(resolvedTarget);
    if (!stat.isFile() || stat.isSymbolicLink()) return false;
    fs.unlinkSync(resolvedTarget);
    return true;
  } catch {
    return false;
  }
}
