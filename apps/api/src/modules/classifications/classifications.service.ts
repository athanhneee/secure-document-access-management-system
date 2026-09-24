import { Injectable, Optional } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import type { ClassificationLevelDto } from '@sda/contracts';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface BusinessCategoryDto {
  id: number;
  code: string;
  name: string;
  departmentId: number | null;
  departmentName: string | null;
  description: string | null;
  isActive: boolean;
}

@Injectable()
export class ClassificationsService {
  private readonly database: PrismaClient;

  constructor(@Optional() databaseClient?: PrismaClient) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
  }

  async listClassificationLevels(): Promise<{ data: ClassificationLevelDto[] }> {
    const levels = await this.database.classificationLevel.findMany({
      where: { is_active: true },
      orderBy: { rank: 'asc' },
    });

    const data: ClassificationLevelDto[] = levels.map((lvl) => ({
      id: Number(lvl.id),
      code: lvl.code,
      name: lvl.name,
      rank: lvl.rank,
      description: lvl.description,
      defaultViewDays: lvl.default_view_days,
      allowDownload: lvl.allow_download,
      requireWatermark: lvl.require_watermark,
      isActive: lvl.is_active,
    }));

    return { data };
  }

  async listBusinessCategories(): Promise<{ data: BusinessCategoryDto[] }> {
    const categories = await this.database.businessCategory.findMany({
      where: { is_active: true },
      orderBy: { code: 'asc' },
      include: {
        departments: {
          select: {
            id: true,
            code: true,
            name: true,
          },
        },
      },
    });

    const data: BusinessCategoryDto[] = categories.map((cat) => ({
      id: Number(cat.id),
      code: cat.code,
      name: cat.name,
      departmentId: cat.department_id !== null ? Number(cat.department_id) : null,
      departmentName: cat.departments?.name ?? null,
      description: cat.description,
      isActive: cat.is_active,
    }));

    return { data };
  }
}
