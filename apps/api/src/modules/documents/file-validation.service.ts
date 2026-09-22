import { BadRequestException, Injectable } from '@nestjs/common';
import path from 'node:path';
import { AppErrorCode } from '@sda/contracts';

export type AllowedExtension = '.pdf' | '.docx' | '.xlsx' | '.pptx';

export interface ValidatedFileInfo {
  sanitizedFilename: string;
  extension: AllowedExtension;
  mimeType: string;
  isOfficeFormat: boolean;
}

const EXTENSION_TO_MIME: Readonly<Record<AllowedExtension, string>> = {
  '.pdf': 'application/pdf',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
};

const DANGEROUS_EXTENSIONS = new Set([
  'exe',
  'dll',
  'bat',
  'cmd',
  'sh',
  'php',
  'phtml',
  'js',
  'vbs',
  'ps1',
  'jar',
  'com',
  'scr',
  'msi',
  'pif',
  'hta',
  'cpl',
  'iso',
  'bin',
  'py',
  'rb',
]);

// Magic byte constants
const PDF_MAGIC = Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2d]); // '%PDF-'
const ZIP_MAGIC = Buffer.from([0x50, 0x4b, 0x03, 0x04]); // 'PK\x03\x04'

// Bidi control characters and zero-width characters (Unicode spoofing)
const BIDI_REGEX = /[\u202A-\u202E\u2066-\u2069\u200E\u200F]/u;
const ZERO_WIDTH_REGEX = /[\u200B-\u200D\uFEFF]/gu;
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS_REGEX = /[\x00-\x1F\x7F-\x9F]/gu;

@Injectable()
export class FileValidationService {
  /**
   * Sanitizes and normalizes the incoming original filename.
   * Defends against:
   * - Null bytes
   * - Path traversal (../, ..\, /, \)
   * - Double extensions (e.g. evil.exe.pdf, test.php.docx)
   * - Unicode spoofing (RTLO, zero-width, non-printable control chars, NFKC)
   * - Filename length limits (1-255 characters)
   */
  sanitizeFilename(rawFilename: string): string {
    if (!rawFilename || typeof rawFilename !== 'string') {
      throw new BadRequestException({
        errorCode: AppErrorCode.INVALID_FILE_TYPE,
        message: 'Filename is required and cannot be empty.',
      });
    }

    // 1. Detect null bytes
    if (rawFilename.includes('\0') || rawFilename.includes('\u0000')) {
      throw new BadRequestException({
        errorCode: AppErrorCode.INVALID_FILE_TYPE,
        message: 'Filename contains forbidden null byte.',
      });
    }

    // 2. Detect Bidi / RTL override spoofing
    if (BIDI_REGEX.test(rawFilename)) {
      throw new BadRequestException({
        errorCode: AppErrorCode.INVALID_FILE_TYPE,
        message: 'Filename contains forbidden bidirectional override characters.',
      });
    }

    // 3. Normalize Unicode to NFKC and strip zero-width characters
    let cleaned = rawFilename.normalize('NFKC').replace(ZERO_WIDTH_REGEX, '');

    // 4. Strip control characters
    cleaned = cleaned.replace(CONTROL_CHARS_REGEX, '');

    // 5. Defend against path traversal: extract basename and strip directory separators
    cleaned = path.basename(cleaned).replace(/[/\\?%*:|"<>]/gu, '_');

    // 6. Check for double extensions with dangerous types
    const parts = cleaned.split('.');
    if (parts.length > 2) {
      // Check intermediate extensions: e.g. ["report", "exe", "pdf"] -> "exe"
      for (let i = 1; i < parts.length - 1; i++) {
        const intermediate = parts[i]!.toLowerCase().trim();
        if (DANGEROUS_EXTENSIONS.has(intermediate)) {
          throw new BadRequestException({
            errorCode: AppErrorCode.INVALID_FILE_TYPE,
            message: `Filename contains forbidden executable double extension: .${intermediate}`,
          });
        }
      }
    }

    // Check final extension as well
    const lastPart = parts[parts.length - 1]?.toLowerCase().trim();
    if (lastPart && DANGEROUS_EXTENSIONS.has(lastPart)) {
      throw new BadRequestException({
        errorCode: AppErrorCode.INVALID_FILE_TYPE,
        message: `Forbidden file extension: .${lastPart}`,
      });
    }

    const trimmed = cleaned.trim();
    if (trimmed.length === 0 || trimmed === '.') {
      throw new BadRequestException({
        errorCode: AppErrorCode.INVALID_FILE_TYPE,
        message: 'Filename cannot be empty after sanitization.',
      });
    }

    if (trimmed.length > 255) {
      throw new BadRequestException({
        errorCode: AppErrorCode.INVALID_FILE_TYPE,
        message: 'Filename length exceeds 255 characters.',
      });
    }

    return trimmed;
  }

  /**
   * Validates filename extension and declared MIME against allowlist (PDF, DOCX, XLSX, PPTX).
   */
  validateExtensionAndMime(
    sanitizedFilename: string,
    declaredMime: string,
  ): { extension: AllowedExtension; mimeType: string; isOfficeFormat: boolean } {
    const rawExt = path.extname(sanitizedFilename).toLowerCase();
    const isAllowedExt = (ext: string): ext is AllowedExtension =>
      ext === '.pdf' || ext === '.docx' || ext === '.xlsx' || ext === '.pptx';

    if (!isAllowedExt(rawExt)) {
      throw new BadRequestException({
        errorCode: AppErrorCode.INVALID_FILE_TYPE,
        message: `Unsupported file extension '${rawExt}'. Allowed formats: PDF, DOCX, XLSX, PPTX.`,
      });
    }

    const expectedMime = EXTENSION_TO_MIME[rawExt];
    const normalizedDeclaredMime = declaredMime.toLowerCase().split(';')[0]?.trim();

    if (normalizedDeclaredMime !== expectedMime) {
      throw new BadRequestException({
        errorCode: AppErrorCode.INVALID_FILE_TYPE,
        message: `MIME type '${declaredMime}' does not match expected MIME '${expectedMime}' for extension '${rawExt}'.`,
      });
    }

    const isOffice = rawExt !== '.pdf';
    return {
      extension: rawExt,
      mimeType: expectedMime,
      isOfficeFormat: isOffice,
    };
  }

  /**
   * Verifies magic bytes of the file header (minimum 512 bytes).
   * Confirms PDF magic (%PDF-) or Zip magic (PK\x03\x04) for Office formats.
   */
  validateMagicBytes(headerChunk: Buffer, extension: AllowedExtension): void {
    if (headerChunk.length < 4) {
      throw new BadRequestException({
        errorCode: AppErrorCode.INVALID_FILE_TYPE,
        message: 'File is too small or truncated to verify magic bytes.',
      });
    }

    if (extension === '.pdf') {
      if (headerChunk.length < 5 || !headerChunk.subarray(0, 5).equals(PDF_MAGIC)) {
        throw new BadRequestException({
          errorCode: AppErrorCode.INVALID_FILE_TYPE,
          message: 'File content does not match PDF format magic bytes (%PDF-).',
        });
      }
    } else {
      // DOCX, XLSX, PPTX must start with PK\x03\x04
      if (!headerChunk.subarray(0, 4).equals(ZIP_MAGIC)) {
        throw new BadRequestException({
          errorCode: AppErrorCode.INVALID_FILE_TYPE,
          message: `File content does not match Office OpenXML zip magic bytes (PK\\x03\\x04) for ${extension}.`,
        });
      }
    }
  }

  /**
   * Combined pre-validation of filename, extension, and declared MIME.
   */
  preValidate(rawFilename: string, declaredMime: string): ValidatedFileInfo {
    const sanitizedFilename = this.sanitizeFilename(rawFilename);
    const { extension, mimeType, isOfficeFormat } = this.validateExtensionAndMime(
      sanitizedFilename,
      declaredMime,
    );
    return {
      sanitizedFilename,
      extension,
      mimeType,
      isOfficeFormat,
    };
  }
}
