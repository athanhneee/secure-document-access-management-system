import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module.js';
import { AbacAuditService } from './abac-audit.service.js';
import { AbacController } from './abac.controller.js';
import { AbacRepository } from './abac.repository.js';
import { AbacService } from './abac.service.js';
import { PolicyCache } from './policy-cache.js';

@Module({
  imports: [AuthModule],
  controllers: [AbacController],
  providers: [AbacService, AbacRepository, AbacAuditService, PolicyCache],
  exports: [AbacService],
})
export class AbacModule {}
