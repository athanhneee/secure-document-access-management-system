import { Module } from '@nestjs/common';
import { AccessGrantsController } from './access-grants.controller.js';
import { AccessGrantsService } from './access-grants.service.js';

@Module({
  controllers: [AccessGrantsController],
  providers: [AccessGrantsService],
  exports: [AccessGrantsService],
})
export class AccessGrantsModule {}
