import { Module } from '@nestjs/common';
import { RbacController } from './rbac.controller.js';
import { RbacService } from './rbac.service.js';
import { AuthModule } from '../auth/auth.module.js';
import { AuthorizationCache } from './authorization-cache.js';
import { AuthorizationService } from './authorization.service.js';
import { RbacAuditService } from './rbac-audit.service.js';

@Module({
  imports: [AuthModule],
  controllers: [RbacController],
  providers: [RbacService, AuthorizationCache, AuthorizationService, RbacAuditService],
  exports: [RbacService, AuthorizationCache, AuthorizationService, RbacAuditService],
})
export class RbacModule {}
