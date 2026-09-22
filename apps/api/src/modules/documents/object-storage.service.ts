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
      const endpoint = `${config.get('STORAGE_USE_SSL') ? 'https' : 'http'}://${config.get('STORAGE_ENDPOINT')}:${config.get('STORAGE_PORT')}`;
      this.s3Client = new S3Client({
        endpoint,
        region: 'us-east-1',
        credentials: {
          accessKeyId: config.get('STORAGE_ACCESS_KEY'),
          secretAccessKey: config.get('STORAGE_SECRET_KEY'),
        },
        forcePathStyle: true,
      });
    } else {
      this.s3Client = null;
    }
  }

  async onModuleInit(): Promise<void> {
    if (!this.isMock && this.s3Client) {
      await this.ensureBucket(this.quarantineBucket).catch(() => {});
      await this.ensureBucket(this.documentsBucket).catch(() => {});
      await this.ensureBucket(this.derivativesBucket).catch(() => {});
    }
  }

  private storageKey(bucket: string, key: string): string {
    return `${bucket}:::${key}`;
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

    try {
      const payload = body instanceof Buffer ? body : await this.streamToBuffer(body);
      const command = new PutObjectCommand({
        Bucket: bucket,
        Key: key,
        Body: payload,
        ContentType: contentType ?? 'application/octet-stream',
        Metadata: metadata,
      });
      await this.s3Client.send(command);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.error(`Failed to put object in bucket ${bucket}, key ${key}: ${msg}`);
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

    try {
      const command = new GetObjectCommand({
        Bucket: bucket,
        Key: key,
      });
      const response = await this.s3Client.send(command);
      if (!response.Body) {
        throw new Error(`Empty response body for object: ${bucket}/${key}`);
      }
      return await this.streamToBuffer(response.Body as Readable);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.error(`Failed to get object from bucket ${bucket}, key ${key}: ${msg}`);
      throw new Error(`Storage operation failed: getObject`);
    }
  }

  async deleteObject(bucket: string, key: string): Promise<void> {
    if (this.isMock || !this.s3Client) {
      this.inMemoryStorage.delete(this.storageKey(bucket, key));
      return;
    }

    try {
      const command = new DeleteObjectCommand({
        Bucket: bucket,
        Key: key,
      });
      await this.s3Client.send(command);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.warn(`Failed to delete object from bucket ${bucket}, key ${key}: ${msg}`);
    }
  }

  async objectExists(bucket: string, key: string): Promise<boolean> {
    if (this.isMock || !this.s3Client) {
      return this.inMemoryStorage.has(this.storageKey(bucket, key));
    }

    try {
      const command = new HeadObjectCommand({
        Bucket: bucket,
        Key: key,
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
