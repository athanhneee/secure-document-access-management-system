import { Module } from '@nestjs/common';
import { AccessSessionsController } from './access-sessions.controller.js';
import { AccessSessionsService } from './access-sessions.service.js';

@Module({
  controllers: [AccessSessionsController],
  providers: [AccessSessionsService],
  exports: [AccessSessionsService],
})
export class AccessSessionsModule {}
