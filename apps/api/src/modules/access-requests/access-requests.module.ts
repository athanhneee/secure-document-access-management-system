import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module.js';
import { RbacModule } from '../rbac/rbac.module.js';
import { AccessGrantsModule } from '../access-grants/access-grants.module.js';
import { AccessRequestsController } from './access-requests.controller.js';
import { AccessRequestsService } from './access-requests.service.js';

@Module({
  imports: [AuthModule, RbacModule, AccessGrantsModule],
  controllers: [AccessRequestsController],
  providers: [AccessRequestsService],
  exports: [AccessRequestsService],
})
export class AccessRequestsModule {}
