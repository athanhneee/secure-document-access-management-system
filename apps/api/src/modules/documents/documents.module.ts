import { Module } from '@nestjs/common';
import { AppConfigModule } from '../../config/config.module.js';
import { AuthModule } from '../auth/auth.module.js';
import { RbacModule } from '../rbac/rbac.module.js';
import { DocumentIngestionController } from './document-ingestion.controller.js';
import { DocumentsController } from './documents.controller.js';
import { DocumentIngestionService } from './document-ingestion.service.js';
import { FileValidationService } from './file-validation.service.js';
import { ZipBombGuardService } from './zip-bomb-guard.service.js';
import { ObjectStorageService } from './object-storage.service.js';
import { AntivirusScannerService } from './antivirus-scanner.service.js';
import { LocalKmsService } from './kms.service.js';
import { DocumentEncryptionService } from './document-encryption.service.js';
import { DocumentAuditService } from './document-audit.service.js';
import { OrphanCompensationService } from './orphan-compensation.service.js';
import { DocumentsService } from './documents.service.js';
import { DocumentSearchService } from './document-search.service.js';

@Module({
  imports: [AppConfigModule, AuthModule, RbacModule],
  controllers: [DocumentIngestionController, DocumentsController],
  providers: [
    FileValidationService,
    ZipBombGuardService,
    ObjectStorageService,
    AntivirusScannerService,
    LocalKmsService,
    DocumentEncryptionService,
    DocumentAuditService,
    OrphanCompensationService,
    DocumentIngestionService,
    DocumentsService,
    DocumentSearchService,
  ],
  exports: [
    DocumentIngestionService,
    FileValidationService,
    ZipBombGuardService,
    ObjectStorageService,
    AntivirusScannerService,
    LocalKmsService,
    DocumentEncryptionService,
    DocumentAuditService,
    OrphanCompensationService,
    DocumentsService,
    DocumentSearchService,
  ],
})
export class DocumentsModule {}
