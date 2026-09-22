import { Injectable } from '@nestjs/common';

@Injectable()
export class WatermarksService {
  listConfigs(): { data: unknown[] } {
    return { data: [] };
  }
}
