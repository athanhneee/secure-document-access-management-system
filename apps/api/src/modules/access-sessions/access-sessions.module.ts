import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module.js';
import { RbacModule } from '../rbac/rbac.module.js';
import { AccessSessionsController } from './access-sessions.controller.js';
import { AccessSessionsService } from './access-sessions.service.js';

@Module({
  imports: [AuthModule, RbacModule],
  controllers: [AccessSessionsController],
  providers: [AccessSessionsService],
  exports: [AccessSessionsService],
})
export class AccessSessionsModule {}
