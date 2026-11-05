/**
 * Module: WatermarksService — Quản lý cấu hình thủy vân pháp y (Forensic Watermark Policy Configuration) và truy vết nguồn rò rỉ tài liệu mật theo mã token (UC28).
 */
import {
  Injectable,
  NotFoundException,
  BadRequestException,
  Logger,
  Optional,
} from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import { AuditWriterService } from '../audit/audit-writer.service.js';
import type { AuthPrincipal } from '../auth/auth.types.js';
import {
  traceWatermarkToken,
  type WatermarkVerificationResult,
} from './watermark-forensics.helper.js';

export type { WatermarkVerificationResult };

type PrismaClient = ReturnType<typeof getDatabaseClient>;

@Injectable()
export class WatermarksService {
  private readonly logger = new Logger(WatermarksService.name);
  private readonly database: PrismaClient;

  constructor(
    @Optional() databaseClient?: PrismaClient,
    @Optional() private readonly auditWriter?: AuditWriterService,
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
  }

  /**
   * Thuật toán: Chiếu danh mục cấu hình thủy vân đang kích hoạt kèm cấp độ mật (Active Watermark Catalog Projection)
   * Mục đích: Liệt kê các mẫu thủy vân đang áp dụng theo thứ tự thời gian khởi tạo cùng thông tin hạng bảo mật `rank` của mức phân loại gắn kèm.
   * Cơ chế hoạt động:
   *   - Truy vấn `watermarkConfig` với bộ lọc `is_active: true` kèm quan hệ `classification_levels`, chuẩn hóa các trường `BigInt`/`Date` sang DTO.
   *
   * Algorithm: Active Watermark Configuration Catalog Projection.
   * Queries active watermark templates ordered by creation time with classification level metadata.
   */
  async listConfigs(): Promise<{ data: unknown[] }> {
    const configs = await this.database.watermarkConfig.findMany({
      where: { is_active: true },
      include: {
        classification_levels: {
          select: { id: true, code: true, name: true, rank: true },
        },
      },
      orderBy: { created_at: 'asc' },
    });

    return {
      data: configs.map((c) => ({
        id: c.id.toString(),
        name: c.name,
        classificationLevelId: c.classification_level_id?.toString() ?? null,
        classificationLevel: c.classification_levels
          ? {
              id: Number(c.classification_levels.id),
              code: c.classification_levels.code,
              name: c.classification_levels.name,
              rank: c.classification_levels.rank,
            }
          : null,
        isDefault: c.is_default,
        isVisible: c.is_visible,
        templateText: c.template_text,
        opacityPercent: c.opacity_percent,
        rotationDegrees: c.rotation_degrees,
        fontSize: c.font_size,
        colorHex: c.color_hex,
        includeQrCode: c.include_qr_code,
        createdAt: c.created_at.toISOString(),
      })),
    };
  }

  /**
   * Thuật toán: Cập nhật cấu hình thủy vân có chốt chặn chính sách hiển thị & biên độ mờ đục (Policy-Constrained Watermark Config Mutation)
   * Mục đích: Cho phép tinh chỉnh giao diện thủy vân nhưng ngăn chặn hành vi tắt thủy vân pháp y hoặc đặt độ mờ quá nhạt/quá đặc làm hỏng khả năng truy vết.
   * Cơ chế hoạt động:
   *   - Chặn tuyệt đối yêu cầu tắt hiển thị (`input.isVisible === false`) và cưỡng chế độ mờ nằm trong đoạn đóng `[10%, 90%]`.
   *   - Làm tròn số nguyên các tham số hình học (`opacityPercent`, `fontSize`, `rotationDegrees`), cập nhật CSDL và ghi nhật ký kiểm toán `WATERMARK_CONFIG_UPDATED`.
   *
   * Algorithm: Policy-Constrained Watermark Configuration Mutation.
   * Rejects attempts to disable visible forensic watermarks or set opacity outside [10%, 90%],
   * persists rounded numeric settings, and emits `WATERMARK_CONFIG_UPDATED` audit log.
   */
  async updateConfig(
    id: bigint,
    input: {
      opacityPercent?: number;
      fontSize?: number;
      includeQrCode?: boolean;
      colorHex?: string;
      rotationDegrees?: number;
      templateText?: string;
      isVisible?: boolean;
    },
    actor?: AuthPrincipal,
  ): Promise<Record<string, unknown>> {
    if (input.isVisible === false) {
      throw new BadRequestException('Disabling visible forensic watermarks is prohibited.');
    }
    if (
      input.opacityPercent !== undefined &&
      (input.opacityPercent < 10 || input.opacityPercent > 90)
    ) {
      throw new BadRequestException('Watermark opacity must be between 10% and 90%.');
    }

    const existing = await this.database.watermarkConfig.findUnique({
      where: { id },
    });
    if (!existing) {
      throw new NotFoundException('Watermark configuration not found.');
    }

    const updated = await this.database.watermarkConfig.update({
      where: { id },
      data: {
        ...(input.opacityPercent !== undefined
          ? { opacity_percent: Math.round(input.opacityPercent) }
          : {}),
        ...(input.fontSize !== undefined ? { font_size: Math.round(input.fontSize) } : {}),
        ...(input.includeQrCode !== undefined ? { include_qr_code: input.includeQrCode } : {}),
        ...(input.colorHex !== undefined ? { color_hex: input.colorHex } : {}),
        ...(input.rotationDegrees !== undefined
          ? { rotation_degrees: Math.round(input.rotationDegrees) }
          : {}),
        ...(input.templateText !== undefined ? { template_text: input.templateText } : {}),
        ...(input.isVisible !== undefined ? { is_visible: input.isVisible } : {}),
        updated_at: new Date(),
      },
    });

    if (this.auditWriter && actor) {
      await this.auditWriter.writeLog({
        actorUserId: actor.userId,
        actorUsername: actor.username,
        action: 'WATERMARK_CONFIG_UPDATED',
        objectType: 'WATERMARK_CONFIG',
        objectId: updated.id.toString(),
        outcome: 'SUCCESS',
        chainPartition: 'RBAC',
        details: {
          opacityPercent: updated.opacity_percent,
          fontSize: updated.font_size,
          includeQrCode: updated.include_qr_code,
          colorHex: updated.color_hex,
          rotationDegrees: updated.rotation_degrees,
          isVisible: updated.is_visible,
        },
      });
    }

    return {
      id: updated.id.toString(),
      name: updated.name,
      opacityPercent: updated.opacity_percent,
      fontSize: updated.font_size,
      includeQrCode: updated.include_qr_code,
      colorHex: updated.color_hex,
      rotationDegrees: updated.rotation_degrees,
      templateText: updated.template_text,
      isVisible: updated.is_visible,
      updatedAt: updated.updated_at.toISOString(),
    };
  }

  /**
   * Thuật toán: Truy vết định danh pháp y từ mã thủy vân tài liệu rò rỉ (Forensic Watermark Token Attribution - UC28)
   * Mục đích: Đối chiếu chuỗi `watermark_token` thu được từ bản chụp/tệp rò rỉ để xác định chính xác người xem, phiên truy cập, địa chỉ IP, phiên bản tài liệu và mã băm SHA-256.
   * Cơ chế hoạt động:
   *   - Ủy quyền cho `traceWatermarkToken` thực hiện phép kết nối 4 bảng (`users`, `access_sessions`, `document_versions`, `watermark_configs`) và ghi vết kiểm toán `WATERMARK_TRACE_PERFORMED`.
   *
   * UC28: Trace a watermark token to verify the user, session, document, version, and generation time.
   */
  async verifyWatermarkToken(
    token: string,
    actor?: AuthPrincipal,
  ): Promise<WatermarkVerificationResult> {
    return traceWatermarkToken(this.database, this.auditWriter, this.logger, token, actor);
  }
}
