import { Injectable } from '@nestjs/common';

@Injectable()
export class ClassificationsService {
  listClassificationLevels(): { data: unknown[] } {
    return { data: [] };
  }

  listBusinessCategories(): { data: unknown[] } {
    return { data: [] };
  }
}
