import { Module } from '@nestjs/common';
import { AppConfigModule } from '../../config/config.module.js';
import { AuthModule } from '../auth/auth.module.js';
import { RbacModule } from '../rbac/rbac.module.js';
import { AuditRedactionService } from './audit-redaction.service.js';
import { AuditWriterService } from './audit-writer.service.js';
import { AuditVerifierService } from './audit-verifier.service.js';
import { AuditService } from './audit.service.js';
import { AuditController } from './audit.controller.js';

@Module({
  imports: [AppConfigModule, AuthModule, RbacModule],
  controllers: [AuditController],
  providers: [AuditRedactionService, AuditWriterService, AuditVerifierService, AuditService],
  exports: [AuditRedactionService, AuditWriterService, AuditVerifierService, AuditService],
})
export class AuditModule {}
