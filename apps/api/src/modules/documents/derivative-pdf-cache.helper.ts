/**
 * Module: Session-Bound Encrypted Derivative PDF Cache Helper (`STORAGE_BUCKET_DERIVATIVES`)
 * Thuật toán: Bộ Đệm PDF Đã Đóng Thủy Vân Mã Hóa Theo Phiên (`AES-256-GCM` + `HKDF-SHA256`) Trên Kho `STORAGE_BUCKET_DERIVATIVES`.
 *   1. Dẫn xuất khóa phiên 256-bit bằng `hkdfSync('sha256', masterOrFallbackSecret, accessSessionId, 'sda-derivative-pdf-v1', 32)` và xóa sạch khóa (`fill(0)`) trong khối `finally`.
 *   2. Mã hóa/giải mã bản PDF đã nhúng thủy vân bằng `AES-256-GCM` với dữ liệu xác thực bổ sung AAD `${accessSessionId}:${documentVersionId}`.
 *   3. Lưu đối tượng mã hóa tại `sessions/${accessSessionId}/v${documentVersionId}.pdf.enc` trong `STORAGE_BUCKET_DERIVATIVES` và lưu siêu dữ liệu `{ pageCount, watermarkToken }` trên `DistributedStateService` với TTL 30 phút.
 *   4. Giúp các yêu cầu xem trang 2, 3, 4... giải mã trực tiếp bản PDF phiên mà không cần gọi lại KMS nguồn, không chuyển đổi lại Gotenberg, không đóng lại thủy vân/QR toàn tài liệu.
 */
import crypto from 'node:crypto';
import type { AppConfigService } from '../../config/config.service.js';
import type { DistributedStateService } from '../concurrency/distributed-state.service.js';
import type { ObjectStorageService } from './object-storage.service.js';

const DERIVATIVE_MAGIC = Buffer.from('SDDP', 'ascii');
const DERIVATIVE_VERSION = 0x01;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const HEADER_LENGTH = DERIVATIVE_MAGIC.length + 1 + IV_LENGTH + AUTH_TAG_LENGTH;
const DERIVATIVE_META_NAMESPACE = 'derivative-pdf-meta';
export const DERIVATIVE_CACHE_TTL_MS = 30 * 60_000;

const FALLBACK_PROCESS_SECRET = crypto.randomBytes(32);

export interface CachedDerivativePdfMetadata {
  pageCount: number;
  watermarkToken?: string | undefined;
  outputSha256Hash: string;
}

export interface LoadedDerivativeSessionPdf extends CachedDerivativePdfMetadata {
  pdfBuffer: Buffer;
}

function resolveMasterOrFallbackSecret(config?: AppConfigService): string | Buffer {
  const configured =
    typeof config?.get === 'function' ? config.get('APP_ENCRYPTION_MASTER_KEY') : undefined;
  if (typeof configured === 'string' && configured.trim().length > 0) {
    return configured.trim();
  }
  const envMaster = process.env['APP_ENCRYPTION_MASTER_KEY']?.trim();
  if (envMaster) return envMaster;
  const envAudit = process.env['AUDIT_INTEGRITY_KEY']?.trim();
  if (envAudit) return envAudit;
  return FALLBACK_PROCESS_SECRET;
}

/**
 * Thuật toán: Xây dựng đường dẫn khóa đối tượng chuẩn trên `STORAGE_BUCKET_DERIVATIVES` cho phiên và phiên bản tài liệu.
 */
export function buildDerivativePdfStorageKey(
  accessSessionId: string,
  documentVersionId: bigint | string | number,
): string {
  return `sessions/${accessSessionId}/v${String(documentVersionId)}.pdf.enc`;
}

function buildDerivativeMetaId(
  accessSessionId: string,
  documentVersionId: bigint | string | number,
): string {
  return `${accessSessionId}:v${String(documentVersionId)}`;
}

/**
 * Thuật toán: Dẫn xuất khóa phiên bằng HKDF-SHA256 và mã hóa tài liệu PDF thủy vân bằng AES-256-GCM kèm AAD `${accessSessionId}:${documentVersionId}`.
 */
export function encryptDerivativeSessionPdf(
  pdfBuffer: Buffer,
  accessSessionId: string,
  documentVersionId: bigint | string | number,
  config?: AppConfigService,
): Buffer {
  const secret = resolveMasterOrFallbackSecret(config);
  const derivedKey = Buffer.from(
    crypto.hkdfSync('sha256', secret, accessSessionId, 'sda-derivative-pdf-v1', 32),
  );
  try {
    const iv = crypto.randomBytes(IV_LENGTH);
    const aad = Buffer.from(`${accessSessionId}:${String(documentVersionId)}`, 'utf8');
    const cipher = crypto.createCipheriv('aes-256-gcm', derivedKey, iv, {
      authTagLength: AUTH_TAG_LENGTH,
    });
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(pdfBuffer), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return Buffer.concat([
      DERIVATIVE_MAGIC,
      Buffer.from([DERIVATIVE_VERSION]),
      iv,
      authTag,
      ciphertext,
    ]);
  } finally {
    derivedKey.fill(0);
  }
}

/**
 * Thuật toán: Giải mã và xác thực thẻ toàn vẹn AES-256-GCM cho PDF thủy vân theo phiên với AAD `${accessSessionId}:${documentVersionId}`.
 */
export function decryptDerivativeSessionPdf(
  envelope: Buffer,
  accessSessionId: string,
  documentVersionId: bigint | string | number,
  config?: AppConfigService,
): Buffer {
  if (
    envelope.length < HEADER_LENGTH ||
    !envelope.subarray(0, 4).equals(DERIVATIVE_MAGIC) ||
    envelope[4] !== DERIVATIVE_VERSION
  ) {
    throw new Error('Invalid derivative PDF cache envelope.');
  }

  const secret = resolveMasterOrFallbackSecret(config);
  const derivedKey = Buffer.from(
    crypto.hkdfSync('sha256', secret, accessSessionId, 'sda-derivative-pdf-v1', 32),
  );
  try {
    const iv = envelope.subarray(5, 5 + IV_LENGTH);
    const authTag = envelope.subarray(5 + IV_LENGTH, HEADER_LENGTH);
    const ciphertext = envelope.subarray(HEADER_LENGTH);
    const aad = Buffer.from(`${accessSessionId}:${String(documentVersionId)}`, 'utf8');

    const decipher = crypto.createDecipheriv('aes-256-gcm', derivedKey, iv, {
      authTagLength: AUTH_TAG_LENGTH,
    });
    decipher.setAAD(aad);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } finally {
    derivedKey.fill(0);
  }
}

/**
 * Thuật toán: Thử Nạp & Giải Mã Bản Đệm PDF Phiên Từ `STORAGE_BUCKET_DERIVATIVES` (`tryLoadCachedSessionPdf`)
 * Tự động suy biến an toàn về `null` (để pipeline gốc kết xuất lại) nếu kho đối tượng đang được mock tối giản hoặc mục đệm đã hết hạn.
 */
export async function tryLoadCachedSessionPdf(params: {
  storage: ObjectStorageService;
  stateStore: DistributedStateService | undefined;
  config: AppConfigService | undefined;
  accessSessionId: string;
  documentVersionId: bigint | string | number;
}): Promise<LoadedDerivativeSessionPdf | null> {
  const { storage, stateStore, config, accessSessionId, documentVersionId } = params;
  if (
    !stateStore ||
    typeof storage?.derivativesBucket !== 'string' ||
    !storage.derivativesBucket ||
    typeof storage?.getObject !== 'function'
  ) {
    return null;
  }

  const metaId = buildDerivativeMetaId(accessSessionId, documentVersionId);
  const meta = await stateStore.getJson<CachedDerivativePdfMetadata>(
    DERIVATIVE_META_NAMESPACE,
    metaId,
  );
  if (!meta) return null;

  try {
    const objectKey = buildDerivativePdfStorageKey(accessSessionId, documentVersionId);
    const encryptedBytes = await storage.getObject(storage.derivativesBucket, objectKey);
    const pdfBuffer = decryptDerivativeSessionPdf(
      encryptedBytes,
      accessSessionId,
      documentVersionId,
      config,
    );
    return {
      pdfBuffer,
      pageCount: meta.pageCount,
      watermarkToken: meta.watermarkToken,
      outputSha256Hash: meta.outputSha256Hash,
    };
  } catch {
    await stateStore.deleteKey(DERIVATIVE_META_NAMESPACE, metaId);
    return null;
  }
}

/**
 * Thuật toán: Mã Hóa & Lưu Bản Đệm PDF Đã Thủy Vân Lên `STORAGE_BUCKET_DERIVATIVES` Kèm Siêu Dữ Liệu TTL 30 Phút (`storeCachedSessionPdf`)
 */
export async function storeCachedSessionPdf(params: {
  storage: ObjectStorageService;
  stateStore: DistributedStateService | undefined;
  config: AppConfigService | undefined;
  accessSessionId: string;
  documentVersionId: bigint | string | number;
  pdfBuffer: Buffer;
  pageCount: number;
  watermarkToken?: string | undefined;
  outputSha256Hash: string;
}): Promise<void> {
  const {
    storage,
    stateStore,
    config,
    accessSessionId,
    documentVersionId,
    pdfBuffer,
    pageCount,
    watermarkToken,
    outputSha256Hash,
  } = params;

  if (
    !stateStore ||
    typeof storage?.derivativesBucket !== 'string' ||
    !storage.derivativesBucket ||
    typeof storage?.putObject !== 'function'
  ) {
    return;
  }

  try {
    const encryptedEnvelope = encryptDerivativeSessionPdf(
      pdfBuffer,
      accessSessionId,
      documentVersionId,
      config,
    );
    const objectKey = buildDerivativePdfStorageKey(accessSessionId, documentVersionId);
    await storage.putObject(
      storage.derivativesBucket,
      objectKey,
      encryptedEnvelope,
      'application/octet-stream',
    );
    const metaPayload: CachedDerivativePdfMetadata = {
      pageCount,
      ...(watermarkToken !== undefined ? { watermarkToken } : {}),
      outputSha256Hash,
    };
    await stateStore.putEphemeral(
      DERIVATIVE_META_NAMESPACE,
      buildDerivativeMetaId(accessSessionId, documentVersionId),
      metaPayload,
      DERIVATIVE_CACHE_TTL_MS,
    );
  } catch {
    // Non-fatal cache write failure (e.g. partial unit test mock); preview continues cleanly.
  }
}
