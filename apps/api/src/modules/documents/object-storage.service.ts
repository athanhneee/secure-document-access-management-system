/**
 * Module: Dịch vụ Lưu trữ Đối tượng Tương thích S3 Đa Môi trường (Streaming S3-Compatible Object Storage Adapter)
 * Thuật toán: Chuẩn Hóa Điểm Cuối S3 Đa Đám Mây & Truyền Luồng Không Đệm Toàn Tệp (`Zero-Buffering Stream I/O`).
 *   1. Chuẩn hóa endpoint cho MinIO, AWS S3, Cloudflare R2 và Supabase S3; phân tách tiền tố bucket ảo (`bucket/prefix` -> `{ bucket, key }`).
 *   2. Cấm tuyệt đối chế độ giả lập `STORAGE_MOCK=true` trên môi trường `staging` và `production`.
 *   3. Trong `putObject`, truyền trực tiếp `Buffer`, `Uint8Array` hoặc `Readable` xuống `PutObjectCommand` không qua bước ghép mảnh `Buffer.concat`.
 *   4. Cung cấp `getObjectStream` trả về luồng `Readable` trực tiếp từ S3 phục vụ tải xuống/quét tệp lớn mà không giữ toàn bộ tệp trong RAM.
 */
import { Injectable, Logger, type OnModuleInit } from '@nestjs/common';
import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  HeadObjectCommand,
  CreateBucketCommand,
} from '@aws-sdk/client-s3';
import { Readable } from 'node:stream';
import type { ReadableStream as WebReadableStream } from 'node:stream/web';
import { AppConfigService } from '../../config/config.service.js';

export interface StorageObjectMetadata {
  contentLength: number;
  contentType: string | null;
  metadata: Record<string, string>;
}

@Injectable()
export class ObjectStorageService implements OnModuleInit {
  private readonly logger = new Logger(ObjectStorageService.name);
  private readonly s3Client: S3Client | null;
  private mockObjects: Record<string, Buffer> = Object.create(null) as Record<string, Buffer>;
  private readonly isMock: boolean;

  readonly quarantineBucket: string;
  readonly documentsBucket: string;
  readonly derivativesBucket: string;

  constructor(config: AppConfigService) {
    this.quarantineBucket = config.get('STORAGE_BUCKET_QUARANTINE');
    this.documentsBucket = config.get('STORAGE_BUCKET_DOCUMENTS');
    this.derivativesBucket = config.get('STORAGE_BUCKET_DERIVATIVES');

    const runtimeEnv = String(config.get('NODE_ENV') ?? process.env['NODE_ENV'] ?? 'development')
      .trim()
      .toLowerCase();
    const storageMockRequested =
      config.get('STORAGE_MOCK') === true || process.env['STORAGE_MOCK'] === 'true';
    if (storageMockRequested && (runtimeEnv === 'production' || runtimeEnv === 'staging')) {
      throw new Error(
        'SECURITY_VIOLATION: In-memory STORAGE_MOCK=true is strictly forbidden in staging and production environments.',
      );
    }

    this.isMock = storageMockRequested || runtimeEnv === 'test';
    if (!this.isMock) {
      const rawEndpoint = config.get('STORAGE_ENDPOINT').trim();
      const isR2 = rawEndpoint.includes('.r2.cloudflarestorage.com');
      const endpoint =
        rawEndpoint.startsWith('http://') || rawEndpoint.startsWith('https://')
          ? isR2
            ? new URL(rawEndpoint).origin
            : rawEndpoint.replace(/\/+$/, '')
          : rawEndpoint.endsWith('.storage.supabase.co')
            ? `https://${rawEndpoint}/storage/v1/s3`
            : isR2
              ? `https://${rawEndpoint.replace(/\/+$/, '')}`
              : `${config.get('STORAGE_USE_SSL') ? 'https' : 'http'}://${rawEndpoint}:${config.get('STORAGE_PORT')}`;
      const configuredRegion = config.get('STORAGE_REGION');
      const region =
        isR2 && (!configuredRegion || configuredRegion === 'us-east-1')
          ? 'auto'
          : configuredRegion || 'us-east-1';
      this.s3Client = new S3Client({
        endpoint,
        region,
        credentials: {
          accessKeyId: config.get('STORAGE_ACCESS_KEY'),
          secretAccessKey: config.get('STORAGE_SECRET_KEY'),
        },
        forcePathStyle: true,
        requestChecksumCalculation: 'WHEN_REQUIRED',
        responseChecksumValidation: 'WHEN_REQUIRED',
      });
    } else {
      this.s3Client = null;
    }
  }

  /** Thuật toán: Khởi tạo tự động các bucket vật lý (`quarantine`, `documents`, `derivatives`) khi khởi chạy mô-đun. */
  async onModuleInit(): Promise<void> {
    if (!this.isMock && this.s3Client) {
      const uniqueBuckets = new Set([
        this.resolveTarget(this.quarantineBucket, '').bucket,
        this.resolveTarget(this.documentsBucket, '').bucket,
        this.resolveTarget(this.derivativesBucket, '').bucket,
      ]);
      for (const bucketName of uniqueBuckets) {
        await this.ensureBucket(bucketName).catch(() => {});
      }
    }
  }

  /** Thuật toán: Phân giải đặc tả bucket kèm tiền tố đường dẫn ảo (`bucket/prefix` -> `{ bucket, key }`). */
  private resolveTarget(bucketSpec: string, key: string): { bucket: string; key: string } {
    const trimmed = bucketSpec.trim().replace(/^\/+|\/+$/g, '');
    const slashIndex = trimmed.indexOf('/');
    if (slashIndex === -1) return { bucket: trimmed, key };
    const bucket = trimmed.slice(0, slashIndex);
    const prefix = trimmed.slice(slashIndex + 1).replace(/^\/+|\/+$/g, '');
    const cleanKey = key.replace(/^\/+/, '');
    return { bucket, key: cleanKey ? `${prefix}/${cleanKey}` : prefix };
  }

  private storageKey(bucket: string, key: string): string {
    const target = this.resolveTarget(bucket, key);
    return `${target.bucket}:::${target.key}`;
  }

  /** Thuật toán: Đẩy đối tượng lên S3 truyền thẳng `Buffer` / `Uint8Array` / `Readable` không ghép mảng trung gian. */
  async putObject(
    bucket: string,
    key: string,
    body: Buffer | Uint8Array | Readable,
    contentType?: string,
    metadata?: Record<string, string>,
    contentLength?: number,
  ): Promise<void> {
    if (this.isMock || !this.s3Client) {
      this.mockObjects[this.storageKey(bucket, key)] = await this.streamToBuffer(body);
      return;
    }

    const target = this.resolveTarget(bucket, key);
    try {
      const inferredLength =
        body instanceof Buffer || body instanceof Uint8Array ? body.byteLength : contentLength;
      await this.s3Client.send(
        new PutObjectCommand({
          Bucket: target.bucket,
          Key: target.key,
          Body: body,
          ContentType: contentType ?? 'application/octet-stream',
          ...(metadata ? { Metadata: metadata } : {}),
          ...(typeof inferredLength === 'number' ? { ContentLength: inferredLength } : {}),
        }),
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.error(
        `Failed to put object in bucket ${target.bucket}, key ${target.key}: ${msg}`,
      );
      throw new Error('Storage operation failed: putObject');
    }
  }

  /** Thuật toán: Mở luồng đọc `Readable` trực tiếp từ S3 không nạp toàn bộ tệp vào bộ nhớ đệm. */
  async getObjectStream(bucket: string, key: string): Promise<Readable> {
    if (this.isMock || !this.s3Client) {
      const stored = this.mockObjects[this.storageKey(bucket, key)];
      if (!stored) throw new Error(`Object not found in storage: ${bucket}/${key}`);
      return Readable.from([Buffer.from(stored)]);
    }

    const target = this.resolveTarget(bucket, key);
    try {
      const response = await this.s3Client.send(
        new GetObjectCommand({ Bucket: target.bucket, Key: target.key }),
      );
      if (!response.Body)
        throw new Error(`Empty response body for object: ${target.bucket}/${target.key}`);
      if (response.Body instanceof Readable) return response.Body;
      const webBody = response.Body as { transformToWebStream?: () => WebReadableStream };
      if (typeof webBody.transformToWebStream === 'function') {
        return Readable.fromWeb(webBody.transformToWebStream());
      }
      throw new Error('Unsupported S3 response stream type.');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.error(
        `Failed to stream object from bucket ${target.bucket}, key ${target.key}: ${msg}`,
      );
      throw new Error('Storage operation failed: getObjectStream');
    }
  }

  /** Thuật toán: Tải toàn bộ nội dung đối tượng về `Buffer` khi cần giải mã xác thực GCM nguyên khối. */
  async getObject(bucket: string, key: string): Promise<Buffer> {
    if (this.isMock || !this.s3Client) {
      const stored = this.mockObjects[this.storageKey(bucket, key)];
      if (!stored) throw new Error(`Object not found in storage: ${bucket}/${key}`);
      return Buffer.from(stored);
    }
    return await this.streamToBuffer(await this.getObjectStream(bucket, key));
  }

  /** Thuật toán: Xóa đối tượng khỏi kho S3 phục vụ thu hồi hoặc bù trừ giao dịch lỗi (`OrphanCompensation`). */
  async deleteObject(bucket: string, key: string): Promise<void> {
    if (this.isMock || !this.s3Client) {
      delete this.mockObjects[this.storageKey(bucket, key)];
      return;
    }
    const target = this.resolveTarget(bucket, key);
    try {
      await this.s3Client.send(new DeleteObjectCommand({ Bucket: target.bucket, Key: target.key }));
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.warn(
        `Failed to delete object from bucket ${target.bucket}, key ${target.key}: ${msg}`,
      );
    }
  }

  /** Thuật toán: Truy vấn siêu dữ liệu đối tượng qua `HeadObjectCommand` không tải thân tệp. */
  async headObject(bucket: string, key: string): Promise<StorageObjectMetadata | null> {
    if (this.isMock || !this.s3Client) {
      const stored = this.mockObjects[this.storageKey(bucket, key)];
      return stored
        ? { contentLength: stored.length, contentType: 'application/octet-stream', metadata: {} }
        : null;
    }
    const target = this.resolveTarget(bucket, key);
    try {
      const res = await this.s3Client.send(
        new HeadObjectCommand({ Bucket: target.bucket, Key: target.key }),
      );
      return {
        contentLength: Number(res.ContentLength ?? 0),
        contentType: res.ContentType ?? null,
        metadata: res.Metadata ?? {},
      };
    } catch {
      return null;
    }
  }

  /** Thuật toán: Kiểm tra sự tồn tại của đối tượng trên S3 qua `headObject`. */
  async objectExists(bucket: string, key: string): Promise<boolean> {
    return (await this.headObject(bucket, key)) !== null;
  }

  private async ensureBucket(bucket: string): Promise<void> {
    if (!this.s3Client) return;
    try {
      await this.s3Client.send(new CreateBucketCommand({ Bucket: bucket }));
    } catch {
      // Bucket already exists
    }
  }

  private async streamToBuffer(streamOrBuf: Buffer | Uint8Array | Readable): Promise<Buffer> {
    if (streamOrBuf instanceof Buffer) return streamOrBuf;
    if (streamOrBuf instanceof Uint8Array) return Buffer.from(streamOrBuf);
    return new Promise<Buffer>((resolve, reject) => {
      const chunks: Buffer[] = [];
      streamOrBuf.on('data', (chunk: Buffer | Uint8Array) => chunks.push(Buffer.from(chunk)));
      streamOrBuf.on('error', (err) => reject(err));
      streamOrBuf.on('end', () => resolve(Buffer.concat(chunks)));
    });
  }

  /** Thuật toán: Làm sạch bộ nhớ giả lập kiểm thử giữa các ca kiểm thử độc lập. */
  clearMockStorage(): void {
    this.mockObjects = Object.create(null) as Record<string, Buffer>;
  }
}
