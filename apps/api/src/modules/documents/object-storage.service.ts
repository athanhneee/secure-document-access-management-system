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
import { AppConfigService } from '../../config/config.service.js';

@Injectable()
export class ObjectStorageService implements OnModuleInit {
  private readonly logger = new Logger(ObjectStorageService.name);
  private readonly s3Client: S3Client | null;
  private readonly inMemoryStorage = new Map<string, Buffer>();
  private readonly isMock: boolean;

  readonly quarantineBucket: string;
  readonly documentsBucket: string;
  readonly derivativesBucket: string;

  constructor(config: AppConfigService) {
    this.quarantineBucket = config.get('STORAGE_BUCKET_QUARANTINE');
    this.documentsBucket = config.get('STORAGE_BUCKET_DOCUMENTS');
    this.derivativesBucket = config.get('STORAGE_BUCKET_DERIVATIVES');

    // Use in-memory mock if STORAGE_MOCK=true or during test if host is unreachable/placeholder
    this.isMock = process.env['STORAGE_MOCK'] === 'true' || config.get('NODE_ENV') === 'test';

    if (!this.isMock) {
      const rawEndpoint = config.get('STORAGE_ENDPOINT').trim();
      const isR2 = rawEndpoint.includes('.r2.cloudflarestorage.com');
      let endpoint: string;
      if (rawEndpoint.startsWith('http://') || rawEndpoint.startsWith('https://')) {
        endpoint = isR2 ? new URL(rawEndpoint).origin : rawEndpoint.replace(/\/+$/, '');
      } else if (rawEndpoint.endsWith('.storage.supabase.co')) {
        endpoint = `https://${rawEndpoint}/storage/v1/s3`;
      } else if (isR2) {
        endpoint = `https://${rawEndpoint.replace(/\/+$/, '')}`;
      } else {
        endpoint = `${config.get('STORAGE_USE_SSL') ? 'https' : 'http'}://${rawEndpoint}:${config.get('STORAGE_PORT')}`;
      }
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

  private resolveTarget(bucketSpec: string, key: string): { bucket: string; key: string } {
    const trimmed = bucketSpec.trim().replace(/^\/+|\/+$/g, '');
    const slashIndex = trimmed.indexOf('/');
    if (slashIndex === -1) {
      return { bucket: trimmed, key };
    }
    const bucket = trimmed.slice(0, slashIndex);
    const prefix = trimmed.slice(slashIndex + 1).replace(/^\/+|\/+$/g, '');
    const cleanKey = key.replace(/^\/+/, '');
    return {
      bucket,
      key: cleanKey ? `${prefix}/${cleanKey}` : prefix,
    };
  }

  private storageKey(bucket: string, key: string): string {
    const target = this.resolveTarget(bucket, key);
    return `${target.bucket}:::${target.key}`;
  }

  async putObject(
    bucket: string,
    key: string,
    body: Buffer | Uint8Array | Readable,
    contentType?: string,
    metadata?: Record<string, string>,
  ): Promise<void> {
    if (this.isMock || !this.s3Client) {
      const buffer = await this.streamToBuffer(body);
      this.inMemoryStorage.set(this.storageKey(bucket, key), buffer);
      return;
    }

    const target = this.resolveTarget(bucket, key);
    try {
      const payload = body instanceof Buffer ? body : await this.streamToBuffer(body);
      const command = new PutObjectCommand({
        Bucket: target.bucket,
        Key: target.key,
        Body: payload,
        ContentType: contentType ?? 'application/octet-stream',
        Metadata: metadata,
      });
      await this.s3Client.send(command);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.error(
        `Failed to put object in bucket ${target.bucket}, key ${target.key}: ${msg}`,
      );
      throw new Error(`Storage operation failed: putObject`);
    }
  }

  async getObject(bucket: string, key: string): Promise<Buffer> {
    if (this.isMock || !this.s3Client) {
      const stored = this.inMemoryStorage.get(this.storageKey(bucket, key));
      if (!stored) {
        throw new Error(`Object not found in storage: ${bucket}/${key}`);
      }
      return Buffer.from(stored);
    }

    const target = this.resolveTarget(bucket, key);
    try {
      const command = new GetObjectCommand({
        Bucket: target.bucket,
        Key: target.key,
      });
      const response = await this.s3Client.send(command);
      if (!response.Body) {
        throw new Error(`Empty response body for object: ${target.bucket}/${target.key}`);
      }
      return await this.streamToBuffer(response.Body as Readable);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.error(
        `Failed to get object from bucket ${target.bucket}, key ${target.key}: ${msg}`,
      );
      throw new Error(`Storage operation failed: getObject`);
    }
  }

  async deleteObject(bucket: string, key: string): Promise<void> {
    if (this.isMock || !this.s3Client) {
      this.inMemoryStorage.delete(this.storageKey(bucket, key));
      return;
    }

    const target = this.resolveTarget(bucket, key);
    try {
      const command = new DeleteObjectCommand({
        Bucket: target.bucket,
        Key: target.key,
      });
      await this.s3Client.send(command);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.warn(
        `Failed to delete object from bucket ${target.bucket}, key ${target.key}: ${msg}`,
      );
    }
  }

  async objectExists(bucket: string, key: string): Promise<boolean> {
    if (this.isMock || !this.s3Client) {
      return this.inMemoryStorage.has(this.storageKey(bucket, key));
    }

    const target = this.resolveTarget(bucket, key);
    try {
      const command = new HeadObjectCommand({
        Bucket: target.bucket,
        Key: target.key,
      });
      await this.s3Client.send(command);
      return true;
    } catch {
      return false;
    }
  }

  private async ensureBucket(bucket: string): Promise<void> {
    if (!this.s3Client) return;
    try {
      await this.s3Client.send(new CreateBucketCommand({ Bucket: bucket }));
    } catch {
      // Bucket may already exist
    }
  }

  private async streamToBuffer(streamOrBuf: Buffer | Uint8Array | Readable): Promise<Buffer> {
    if (streamOrBuf instanceof Buffer) return streamOrBuf;
    if (streamOrBuf instanceof Uint8Array) return Buffer.from(streamOrBuf);

    return new Promise<Buffer>((resolve, reject) => {
      const chunks: Buffer[] = [];
      streamOrBuf.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
      streamOrBuf.on('error', (err) => reject(err));
      streamOrBuf.on('end', () => resolve(Buffer.concat(chunks)));
    });
  }

  /**
   * Clears internal in-memory test storage (for testing).
   */
  clearMockStorage(): void {
    this.inMemoryStorage.clear();
  }
}
