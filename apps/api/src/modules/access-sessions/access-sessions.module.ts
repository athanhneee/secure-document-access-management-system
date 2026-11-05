import { Module } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module.js';
import { AuthModule } from '../auth/auth.module.js';
import { RbacModule } from '../rbac/rbac.module.js';
import { AccessSessionsController } from './access-sessions.controller.js';
import { AccessSessionsService } from './access-sessions.service.js';

@Module({
  imports: [AuthModule, RbacModule, AuditModule],
  controllers: [AccessSessionsController],
  providers: [AccessSessionsService],
  exports: [AccessSessionsService],
})
export class AccessSessionsModule {}
