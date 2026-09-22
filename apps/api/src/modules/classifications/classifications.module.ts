import { Module } from '@nestjs/common';
import { ClassificationsController } from './classifications.controller.js';
import { ClassificationsService } from './classifications.service.js';

@Module({
  controllers: [ClassificationsController],
  providers: [ClassificationsService],
  exports: [ClassificationsService],
})
export class ClassificationsModule {}
