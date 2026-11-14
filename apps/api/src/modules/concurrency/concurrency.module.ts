import { Module, Global } from '@nestjs/common';
import { AppConfigModule } from '../../config/config.module.js';
import { DistributedStateService } from './distributed-state.service.js';
import { RedlockService } from './redlock.service.js';

@Global()
@Module({
  imports: [AppConfigModule],
  providers: [RedlockService, DistributedStateService],
  exports: [RedlockService, DistributedStateService],
})
export class ConcurrencyModule {}
