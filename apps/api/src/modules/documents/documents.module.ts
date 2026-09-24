import { Module } from '@nestjs/common';
import { AppConfigModule } from '../../config/config.module.js';
import { AuthModule } from '../auth/auth.module.js';
import { RbacModule } from '../rbac/rbac.module.js';
import { AbacModule } from '../abac/abac.module.js';
import { AccessGrantsModule } from '../access-grants/access-grants.module.js';
import { WatermarksModule } from '../watermarks/watermarks.module.js';
import { DocumentIngestionController } from './document-ingestion.controller.js';
import { DocumentsController } from './documents.controller.js';
import { DocumentIngestionService } from './document-ingestion.service.js';
import { FileValidationService } from './file-validation.service.js';
import { ZipBombGuardService } from './zip-bomb-guard.service.js';
import { ObjectStorageService } from './object-storage.service.js';
import { AntivirusScannerService } from './antivirus-scanner.service.js';
import {
  LocalKmsService,
  UnifiedKmsService,
  HsmPkcs11KmsService,
  VaultTransitKmsService,
  CloudKmsService,
} from './kms.service.js';
import { DocumentEncryptionService } from './document-encryption.service.js';
import { DocumentAuditService } from './document-audit.service.js';
import { OrphanCompensationService } from './orphan-compensation.service.js';
import { DocumentsService } from './documents.service.js';
import { DocumentSearchService } from './document-search.service.js';
import { DocumentPepService } from './document-pep.service.js';
import { OfficeConverterService } from './office-converter.service.js';
import { DocumentDeliveryService } from './document-delivery.service.js';
import { DocumentDeliveryAuditService } from './document-delivery-audit.service.js';

@Module({
  imports: [
    AppConfigModule,
    AuthModule,
    RbacModule,
    AbacModule,
    AccessGrantsModule,
    WatermarksModule,
  ],
  controllers: [DocumentIngestionController, DocumentsController],
  providers: [
    FileValidationService,
    ZipBombGuardService,
    ObjectStorageService,
    AntivirusScannerService,
    HsmPkcs11KmsService,
    VaultTransitKmsService,
    CloudKmsService,
    UnifiedKmsService,
    {
      provide: LocalKmsService,
      useExisting: UnifiedKmsService,
    },
    DocumentEncryptionService,
    DocumentAuditService,
    OrphanCompensationService,
    DocumentIngestionService,
    DocumentsService,
    DocumentSearchService,
    DocumentPepService,
    OfficeConverterService,
    DocumentDeliveryService,
    DocumentDeliveryAuditService,
  ],
  exports: [
    DocumentIngestionService,
    FileValidationService,
    ZipBombGuardService,
    ObjectStorageService,
    AntivirusScannerService,
    LocalKmsService,
    UnifiedKmsService,
    HsmPkcs11KmsService,
    VaultTransitKmsService,
    CloudKmsService,
    DocumentEncryptionService,
    DocumentAuditService,
    OrphanCompensationService,
    DocumentsService,
    DocumentSearchService,
    DocumentPepService,
    OfficeConverterService,
    DocumentDeliveryService,
    DocumentDeliveryAuditService,
  ],
})
export class DocumentsModule {}
