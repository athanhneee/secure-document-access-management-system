/**
 * Module: ClassificationsService — Quản lý danh mục phân loại độ mật chuẩn dàn xếp tuyến tính Bell-LaPadula (`rank` tăng dần) và danh mục nghiệp vụ phòng ban.
 */
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

  /**
   * Thuật toán: Chiếu dàn phân loại độ mật theo thứ tự hạng bảo mật tăng dần (Ordered Security Lattice Level Projection)
   * Mục đích: Cung cấp danh sách các mức độ mật đang hoạt động sắp xếp nghiêm ngặt theo trọng số `rank` phục vụ kiểm tra trội Bell-LaPadula và giao diện gắn nhãn.
   * Cơ chế hoạt động:
   *   - Truy vấn `classificationLevel` với điều kiện `is_active: true`, sắp xếp `orderBy: { rank: 'asc' }` và ánh xạ chính sách đi kèm (`defaultViewDays`, `allowDownload`, `requireWatermark`).
   */
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

  /**
   * Thuật toán: Chiếu danh mục phân loại nghiệp vụ gắn kết đơn vị phòng ban (Active Business Category Taxonomy Projection)
   * Mục đích: Liệt kê các nhóm hồ sơ nghiệp vụ đang hiệu lực sắp xếp từ điển theo mã `code` kèm tên phòng ban quản lý.
   * Cơ chế hoạt động:
   *   - Lọc các bản ghi `is_active: true`, kết nối bảng `departments` để lấy tên phòng ban và chuẩn hóa khóa nguyên từ `BigInt` sang `number`.
   */
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
