import { Module } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module.js';
import { ExportJobService } from './export-job.service.js';
import { ReportsController } from './reports.controller.js';

@Module({
  imports: [AuditModule],
  controllers: [ReportsController],
  providers: [ExportJobService],
  exports: [ExportJobService],
})
export class ReportsModule {}
