import { DeleteObjectCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';

/**
 * Thuật toán / Tổng quan module:
 * Bộ điều hợp lưu trữ đối tượng S3 / Cloudflare R2 cho tệp kết xuất mã hóa `.dat` của `@sda/worker`:
 * - Tự động nhận diện cấu hình S3 hợp lệ (`STORAGE_ENDPOINT`, `STORAGE_ACCESS_KEY`, `STORAGE_SECRET_KEY`,
 *   `STORAGE_BUCKET_DERIVATIVES` khác giá trị giữ chỗ, `STORAGE_MOCK !== 'true'`, `NODE_ENV !== 'test'`).
 * - Chuẩn hóa endpoint đa đám mây (Cloudflare R2 `region = 'auto'`, Supabase S3, MinIO/AWS S3 `forcePathStyle = true`)
 *   và ánh xạ khóa đối tượng `exports/<safeJobId>.dat` bên trong `STORAGE_BUCKET_DERIVATIVES`.
 */

export interface ResolvedExportS3Config {
  endpoint: string;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
  derivativesBucket: string;
}

let cachedClientKey = '';
let cachedClient: S3Client | null = null;

function isPlaceholderSetting(value: string | undefined): boolean {
  if (!value) return true;
  const trimmed = value.trim();
  if (!trimmed) return true;
  const lower = trimmed.toLowerCase();
  return trimmed.startsWith('<') || lower.includes('placeholder');
}

/**
 * Thuật toán: Phân giải và chuẩn hóa cấu hình S3/R2 tùy chọn trên tiến trình Worker (Least Privilege Safe).
 */
export function resolveWorkerExportS3Config(
  env: NodeJS.ProcessEnv = process.env,
): ResolvedExportS3Config | null {
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

function getOrCreateS3Client(cfg: ResolvedExportS3Config): S3Client {
  const cacheKey = `${cfg.endpoint}|${cfg.region}|${cfg.accessKeyId}|${cfg.secretAccessKey}`;
  if (cachedClient && cachedClientKey === cacheKey) {
    return cachedClient;
  }
  cachedClient = new S3Client({
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
  cachedClientKey = cacheKey;
  return cachedClient;
}

/**
 * Thuật toán: Tách tiền tố ảo của `STORAGE_BUCKET_DERIVATIVES` (`bucket/prefix`) và gắn khóa `exports/<safeJobId>.dat`.
 */
export function resolveDerivativesExportObjectTarget(
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
 * Thuật toán: Thẩm định chuỗi định danh `s3://<bucket>/.../exports/<safeJobId>.dat` chống leo thang khóa đối tượng.
 */
export function isValidExportS3UriForJob(filePath: string, safeJobId: string): boolean {
  if (!filePath.startsWith('s3://') || filePath.includes('..') || filePath.includes('\\')) {
    return false;
  }
  const withoutScheme = filePath.slice('s3://'.length);
  const slashIdx = withoutScheme.indexOf('/');
  if (slashIdx <= 0) return false;
  const key = withoutScheme.slice(slashIdx + 1);
  return key === `exports/${safeJobId}.dat` || key.endsWith(`/exports/${safeJobId}.dat`);
}

/**
 * Thuật toán: Đẩy bản mã `AES-256-GCM` (`SDEA\x01`) lên `STORAGE_BUCKET_DERIVATIVES` tại `exports/<safeJobId>.dat`.
 */
export async function uploadExportCiphertextToS3(
  safeJobId: string,
  encryptedEnvelope: Buffer,
): Promise<string | null> {
  const cfg = resolveWorkerExportS3Config();
  if (!cfg) return null;

  const client = getOrCreateS3Client(cfg);
  const target = resolveDerivativesExportObjectTarget(cfg.derivativesBucket, safeJobId);
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
 * Thuật toán: Xóa đối tượng mã hóa `exports/<safeJobId>.dat` khỏi `STORAGE_BUCKET_DERIVATIVES` khi hết hạn TTL.
 */
export async function deleteExportCiphertextFromS3(safeJobId: string): Promise<boolean> {
  const cfg = resolveWorkerExportS3Config();
  if (!cfg || !safeJobId) return false;

  const client = getOrCreateS3Client(cfg);
  const target = resolveDerivativesExportObjectTarget(cfg.derivativesBucket, safeJobId);
  await client.send(
    new DeleteObjectCommand({
      Bucket: target.bucket,
      Key: target.key,
    }),
  );
  return true;
}
