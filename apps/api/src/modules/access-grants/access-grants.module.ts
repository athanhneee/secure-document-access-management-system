import { Module } from '@nestjs/common';
import { AppConfigModule } from '../../config/config.module.js';
import { AuthModule } from '../auth/auth.module.js';
import { RbacModule } from '../rbac/rbac.module.js';
import { AbacModule } from '../abac/abac.module.js';
import { AccessGrantsController } from './access-grants.controller.js';
import { AccessGrantsService } from './access-grants.service.js';
import { AccessGrantAuditService } from './access-grant-audit.service.js';

@Module({
  imports: [AppConfigModule, AuthModule, RbacModule, AbacModule],
  controllers: [AccessGrantsController],
  providers: [AccessGrantsService, AccessGrantAuditService],
  exports: [AccessGrantsService, AccessGrantAuditService],
})
export class AccessGrantsModule {}
