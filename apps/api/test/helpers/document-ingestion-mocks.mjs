process.env.STORAGE_MOCK = 'true';
process.env.NODE_ENV = 'test';
process.env.DATABASE_URL = 'postgresql://localhost:5432/secure_docs?schema=public';
process.env.APP_ENCRYPTION_MASTER_KEY = 'test-master-key-32-chars-long-000000000';

import { AppConfigService } from '../../dist/config/config.service.js';
import { FileValidationService } from '../../dist/modules/documents/file-validation.service.js';
import { ZipBombGuardService } from '../../dist/modules/documents/zip-bomb-guard.service.js';
import { ObjectStorageService } from '../../dist/modules/documents/object-storage.service.js';
import { AntivirusScannerService } from '../../dist/modules/documents/antivirus-scanner.service.js';
import { LocalKmsService } from '../../dist/modules/documents/kms.service.js';
import { DocumentEncryptionService } from '../../dist/modules/documents/document-encryption.service.js';
import { DocumentIngestionService } from '../../dist/modules/documents/document-ingestion.service.js';
import { OrphanCompensationService } from '../../dist/modules/documents/orphan-compensation.service.js';

export function createMockConfig(overrides = {}) {
  const env = {
    NODE_ENV: 'test',
    APP_ENCRYPTION_MASTER_KEY: 'test-master-key-32-chars-long-000000000',
    STORAGE_ENDPOINT: '127.0.0.1',
    STORAGE_PORT: 9000,
    STORAGE_ACCESS_KEY: 'test-access-key',
    STORAGE_SECRET_KEY: 'test-secret-key',
    STORAGE_BUCKET_DOCUMENTS: 'test-documents',
    STORAGE_BUCKET_QUARANTINE: 'test-quarantine',
    STORAGE_BUCKET_DERIVATIVES: 'test-derivatives',
    STORAGE_USE_SSL: false,
    CLAMAV_HOST: '127.0.0.1',
    CLAMAV_PORT: 3310,
    UPLOAD_MAX_FILE_SIZE_BYTES: 1_048_576,
    ZIP_MAX_TOTAL_UNCOMPRESSED_SIZE: 5_242_880,
    ZIP_MAX_ENTRIES: 50,
    ZIP_MAX_DEPTH: 5,
    ZIP_MAX_COMPRESSION_RATIO: 20,
    DOCUMENT_AUDIT_HMAC_KEY: 'test-document-audit-hmac-key-0000000000',
    ...overrides,
  };
  return new AppConfigService(env);
}

export function createIngestionHarness({ configOverrides = {}, mockDb: customDb } = {}) {
  const config = createMockConfig(configOverrides);
  const fileValidation = new FileValidationService();
  const zipBombGuard = new ZipBombGuardService(config);
  const storage = new ObjectStorageService(config);
  const antivirus = new AntivirusScannerService(config);
  const kms = new LocalKmsService(config);
  const encryption = new DocumentEncryptionService(kms);
  const compensation = new OrphanCompensationService(storage);

  const recordedAudits = [];
  const mockAudit = {
    record: async (event) => recordedAudits.push(event),
  };

  const mockDb = customDb ?? {
    $transaction: async (fn) =>
      fn({
        document: {
          findUnique: async () => null,
          create: async () => ({}),
        },
        documentVersion: {
          create: async () => ({}),
        },
      }),
  };

  const ingestion = new DocumentIngestionService(
    config,
    fileValidation,
    zipBombGuard,
    storage,
    antivirus,
    encryption,
    mockAudit,
    compensation,
    mockDb,
  );

  return {
    config,
    storage,
    encryption,
    compensation,
    recordedAudits,
    ingestion,
  };
}
