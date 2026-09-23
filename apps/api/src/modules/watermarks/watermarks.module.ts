import { Module } from '@nestjs/common';
import { RbacModule } from '../rbac/rbac.module.js';
import { AuditModule } from '../audit/audit.module.js';
import { WatermarksController } from './watermarks.controller.js';
import { WatermarksService } from './watermarks.service.js';
import { WatermarkEngineService } from './watermark-engine.service.js';

@Module({
  imports: [RbacModule, AuditModule],
  controllers: [WatermarksController],
  providers: [WatermarksService, WatermarkEngineService],
  exports: [WatermarksService, WatermarkEngineService],
})
export class WatermarksModule {}
