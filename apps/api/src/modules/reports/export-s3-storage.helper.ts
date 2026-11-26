/**
 * Module: Multi-Container Cloudflare R2 / S3 Export Ciphertext Storage Helper
 * Thuật toán: Lưu Trữ & Tải Xuống Đối Tượng Xuất Báo Cáo Mã Hóa `AES-256-GCM` Đa Container Trên S3 / Cloudflare R2 (`ExportS3StorageHelper`).
 *   1. Kích hoạt tự động khi cấu hình `STORAGE_ENDPOINT`, `STORAGE_ACCESS_KEY`, `STORAGE_SECRET_KEY`, `STORAGE_BUCKET_DERIVATIVES` hợp lệ
 *      (khác giá trị giữ chỗ, `STORAGE_MOCK !== 'true'`, `NODE_ENV !== 'test'`).
 *   2. Chuẩn hóa endpoint Cloudflare R2 (`region = 'auto'`), Supabase S3 và MinIO/AWS S3 (`forcePathStyle = true`),
 *      lưu bản mã `SDEA\x01` tại khóa `exports/<safeJobId>.dat` trong `STORAGE_BUCKET_DERIVATIVES`.
 */
import {
  DeleteObjectCommand,
  GetObjectCommand,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import * as path from 'node:path';
import { Readable } from 'node:stream';

export interface ApiExportS3Config {
  endpoint: string;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
  derivativesBucket: string;
}

let cachedClientSignature = '';
let cachedS3Client: S3Client | null = null;

function isPlaceholderSetting(value: string | undefined): boolean {
  if (!value) return true;
  const trimmed = value.trim();
  if (!trimmed) return true;
  const lower = trimmed.toLowerCase();
  return trimmed.startsWith('<') || lower.includes('placeholder');
}

/**
 * Thuật toán: Phân giải cấu hình S3/R2 cho kho lưu trữ tệp xuất `.dat` dùng chung giữa `@sda/api` và `@sda/worker`.
 */
export function resolveApiExportS3Config(
  env: NodeJS.ProcessEnv = process.env,
): ApiExportS3Config | null {
  const nodeEnv = (env['NODE_ENV'] ?? '').trim().toLowerCase();
  const storageMock = (env['STORAGE_MOCK'] ?? '').trim().toLowerCase();
  if (nodeEnv === 'test' || storageMock === 'true') {
    return null;
  }

  const rawEndpoint = env['STORAGE_ENDPOINT']?.trim();
  const accessKeyId = env['STORAGE_ACCESS_KEY']?.trim();
  const secretAccessKey = env['STORAGE_SECRET_KEY']?.trim();
  const derivativesBucket = env['STORAGE_BUCKET_DERIVATIVES']?.trim();

  if (
    !rawEndpoint ||
    !accessKeyId ||
    !secretAccessKey ||
    !derivativesBucket ||
    isPlaceholderSetting(rawEndpoint) ||
    isPlaceholderSetting(accessKeyId) ||
    isPlaceholderSetting(secretAccessKey) ||
    isPlaceholderSetting(derivativesBucket)
  ) {
    return null;
  }

  const isR2 = rawEndpoint.includes('.r2.cloudflarestorage.com');
  const endpoint =
    rawEndpoint.startsWith('http://') || rawEndpoint.startsWith('https://')
      ? isR2
        ? new URL(rawEndpoint).origin
        : rawEndpoint.replace(/\/+$/u, '')
      : rawEndpoint.endsWith('.storage.supabase.co')
        ? `https://${rawEndpoint}/storage/v1/s3`
        : isR2
          ? `https://${rawEndpoint.replace(/\/+$/u, '')}`
          : `${env['STORAGE_USE_SSL'] === 'true' ? 'https' : 'http'}://${rawEndpoint}:${env['STORAGE_PORT']?.trim() || '9000'}`;

  const configuredRegion = env['STORAGE_REGION']?.trim();
  const region =
    isR2 && (!configuredRegion || configuredRegion === 'us-east-1')
      ? 'auto'
      : configuredRegion || 'us-east-1';

  return {
    endpoint,
    region,
    accessKeyId,
    secretAccessKey,
    derivativesBucket,
  };
}

function getOrCreateS3Client(cfg: ApiExportS3Config): S3Client {
  const sig = `${cfg.endpoint}|${cfg.region}|${cfg.accessKeyId}|${cfg.secretAccessKey}`;
  if (cachedS3Client && cachedClientSignature === sig) {
    return cachedS3Client;
  }
  cachedS3Client = new S3Client({
    endpoint: cfg.endpoint,
    region: cfg.region,
    credentials: {
      accessKeyId: cfg.accessKeyId,
      secretAccessKey: cfg.secretAccessKey,
    },
    forcePathStyle: true,
    requestChecksumCalculation: 'WHEN_REQUIRED',
    responseChecksumValidation: 'WHEN_REQUIRED',
  });
  cachedClientSignature = sig;
  return cachedS3Client;
}

function resolveExportObjectTarget(
  derivativesBucketSpec: string,
  safeJobId: string,
): { bucket: string; key: string } {
  const trimmed = derivativesBucketSpec.trim().replace(/^\/+|\/+$/gu, '');
  const slashIdx = trimmed.indexOf('/');
  const exportKey = `exports/${safeJobId}.dat`;
  if (slashIdx === -1) {
    return { bucket: trimmed, key: exportKey };
  }
  const bucket = trimmed.slice(0, slashIdx);
  const prefix = trimmed.slice(slashIdx + 1).replace(/^\/+|\/+$/gu, '');
  return { bucket, key: prefix ? `${prefix}/${exportKey}` : exportKey };
}

/**
 * Thuật toán: Xác minh URI `s3://<bucket>/.../exports/<safeJobId>.dat` khớp đúng định danh tác vụ và không chứa `..`.
 */
export function isValidExportS3UriForJob(filePath: string, safeJobId: string): boolean {
  if (!filePath.startsWith('s3://') || filePath.includes('..') || filePath.includes('\\')) {
    return false;
  }
  const rest = filePath.slice('s3://'.length);
  const slashIdx = rest.indexOf('/');
  if (slashIdx <= 0) return false;
  const key = rest.slice(slashIdx + 1);
  return key === `exports/${safeJobId}.dat` || key.endsWith(`/exports/${safeJobId}.dat`);
}

/**
 * Thuật toán: Nhận diện đường dẫn tệp `.dat` sinh bởi container Worker khác máy chủ để cho phép tải dự phòng từ S3 mà không mở tệp cục bộ.
 */
export function isCrossContainerExportFilename(filePath: string, safeJobId: string): boolean {
  if (!safeJobId || filePath.includes('..') || filePath.includes('\0')) {
    return false;
  }
  const normalized = filePath.replace(/\\/gu, '/');
  return path.posix.basename(normalized) === `${safeJobId}.dat`;
}

/**
 * Thuật toán: Đẩy bản mã `.dat` (`AES-256-GCM`) lên `STORAGE_BUCKET_DERIVATIVES` tại khóa `exports/<safeJobId>.dat`.
 */
export async function uploadEncryptedExportToS3(
  jobId: string,
  encryptedEnvelope: Buffer,
): Promise<string | null> {
  const cfg = resolveApiExportS3Config();
  const safeJobId = jobId.replace(/[^a-zA-Z0-9_-]/gu, '');
  if (!cfg || !safeJobId) return null;

  const client = getOrCreateS3Client(cfg);
  const target = resolveExportObjectTarget(cfg.derivativesBucket, safeJobId);
  await client.send(
    new PutObjectCommand({
      Bucket: target.bucket,
      Key: target.key,
      Body: encryptedEnvelope,
      ContentType: 'application/octet-stream',
      ContentLength: encryptedEnvelope.byteLength,
    }),
  );
  return `s3://${target.bucket}/${target.key}`;
}

/**
 * Thuật toán: Tải bản mã `.dat` từ khóa `exports/<safeJobId>.dat` trên S3/R2 về bộ đệm nhị phân để giải mã và đối chiếu `SHA-256`.
 */
export async function downloadEncryptedExportFromS3(jobId: string): Promise<Buffer | null> {
  const cfg = resolveApiExportS3Config();
  const safeJobId = jobId.replace(/[^a-zA-Z0-9_-]/gu, '');
  if (!cfg || !safeJobId) return null;

  const client = getOrCreateS3Client(cfg);
  const target = resolveExportObjectTarget(cfg.derivativesBucket, safeJobId);
  try {
    const response = await client.send(
      new GetObjectCommand({
        Bucket: target.bucket,
        Key: target.key,
      }),
    );
    if (!response.Body) return null;
    if (typeof response.Body.transformToByteArray === 'function') {
      const bytes = await response.Body.transformToByteArray();
      return Buffer.from(bytes);
    }
    const chunks: Buffer[] = [];
    for await (const chunk of response.Body as Readable) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array));
    }
    return Buffer.concat(chunks);
  } catch (err: unknown) {
    const s3Err = err as { name?: string; $metadata?: { httpStatusCode?: number } };
    if (
      s3Err?.name === 'NoSuchKey' ||
      s3Err?.name === 'NotFound' ||
      s3Err?.$metadata?.httpStatusCode === 404
    ) {
      return null;
    }
    throw err;
  }
}

/**
 * Thuật toán: Xóa đối tượng mã hóa `exports/<safeJobId>.dat` trên S3/R2 trước khi xóa dòng `async_export_jobs` (`BUG-067`).
 * Coi `404`/`NoSuchKey` là đã dọn sạch (`false`), nhưng ném lại các lỗi kết nối/quyền hạn để tầng thu dọn giữ lại bản ghi CSDL chờ thử lại.
 */
export async function deleteEncryptedExportFromS3(
  jobId: string,
  env: NodeJS.ProcessEnv = process.env,
): Promise<boolean> {
  const cfg = resolveApiExportS3Config(env);
  const safeJobId = jobId.replace(/[^a-zA-Z0-9_-]/gu, '');
  if (!cfg || !safeJobId) return false;

  const client = getOrCreateS3Client(cfg);
  const target = resolveExportObjectTarget(cfg.derivativesBucket, safeJobId);
  try {
    await client.send(
      new DeleteObjectCommand({
        Bucket: target.bucket,
        Key: target.key,
      }),
    );
    return true;
  } catch (err: unknown) {
    const s3Err = err as { name?: string; $metadata?: { httpStatusCode?: number } };
    if (
      s3Err?.name === 'NoSuchKey' ||
      s3Err?.name === 'NotFound' ||
      s3Err?.$metadata?.httpStatusCode === 404
    ) {
      return false;
    }
    throw err;
  }
}
