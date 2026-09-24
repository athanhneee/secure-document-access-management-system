import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module.js';
import { AuditModule } from '../audit/audit.module.js';
import { SecurityDetectionService } from './security-detection.service.js';
import { SecurityAlertsService } from './security-alerts.service.js';
import { IncidentsService } from './incidents.service.js';
import { SecurityOperationsController } from './security-operations.controller.js';

@Module({
  imports: [AuthModule, AuditModule],
  controllers: [SecurityOperationsController],
  providers: [SecurityDetectionService, SecurityAlertsService, IncidentsService],
  exports: [SecurityDetectionService, SecurityAlertsService, IncidentsService],
})
export class SecurityOperationsModule {}
