import { Module, Global } from '@nestjs/common';
import { AppConfigModule } from '../../config/config.module.js';
import { RedlockService } from './redlock.service.js';

@Global()
@Module({
  imports: [AppConfigModule],
  providers: [RedlockService],
  exports: [RedlockService],
})
export class ConcurrencyModule {}
