/**
 * @module WatermarksService
 * Thuật toán: Quản lý cấu hình watermark pháp y có ràng buộc độ mờ `[10%, 90%]`, tương phản màu tối thiểu,
 * cưỡng chế mã QR hoặc `{watermarkToken}` đầy đủ đối với cấp độ mật `SECRET` / `TOP_SECRET`, và truy vết nguồn rò rỉ (UC28).
 */
import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
  Optional,
} from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import { AuditWriterService } from '../audit/audit-writer.service.js';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { DistributedStateService } from '../concurrency/distributed-state.service.js';
import {
  DERIVATIVE_CACHE_TTL_MS,
  WATERMARK_CONFIG_EPOCH_KEY,
  WATERMARK_CONFIG_EPOCH_NAMESPACE,
} from '../documents/derivative-pdf-cache.helper.js';
import { AuthorizationService } from '../rbac/authorization.service.js';
import {
  traceWatermarkToken,
  type WatermarkVerificationResult,
} from './watermark-forensics.helper.js';

export type { WatermarkVerificationResult };

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Thuật toán: Kiểm tra chính sách bắt buộc nhúng mã QR hoặc `{watermarkToken}` đầy đủ trên các mức mật `SECRET` / `TOP_SECRET`.
 */
export function assertHighClassificationWatermarkIntegrity(params: {
  classificationCode?: string | null | undefined;
  classificationRank?: number | null | undefined;
  includeQrCode: boolean;
  templateText: string;
}): void {
  const { classificationCode, classificationRank, includeQrCode, templateText } = params;
  const isHighClassification =
    classificationCode === 'SECRET' ||
    classificationCode === 'TOP_SECRET' ||
    (typeof classificationRank === 'number' && classificationRank >= 3);
  if (!isHighClassification) return;

  const hasFullTokenPlaceholder = /\{\{?watermarkToken\}?\}/u.test(templateText);
  if (!includeQrCode && !hasFullTokenPlaceholder) {
    throw new BadRequestException(
      'Watermark configurations bound to SECRET or TOP_SECRET classifications cannot disable QR codes unless {watermarkToken} is included in templateText.',
    );
  }
}

@Injectable()
export class WatermarksService {
  private readonly logger = new Logger(WatermarksService.name);
  private readonly database: PrismaClient;

  constructor(
    @Optional() databaseClient?: PrismaClient,
    @Optional() private readonly auditWriter?: AuditWriterService,
    @Optional() private readonly authorization?: AuthorizationService,
    @Optional() private readonly stateStore?: DistributedStateService,
  ) {
    try {
      this.database = databaseClient ?? getDatabaseClient();
    } catch {
      this.database = (databaseClient ?? null) as unknown as PrismaClient;
    }
  }

  /**
   * Thuật toán: Chiếu danh mục cấu hình watermark đang kích hoạt kèm cấp độ mật (`Active Watermark Catalog Projection`).
   */
  async listConfigs(): Promise<{ data: unknown[] }> {
    const configs = await this.database.watermarkConfig.findMany({
      where: { is_active: true },
      take: 200,
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
   * Thuật toán: Cập nhật cấu hình watermark có chốt chặn hiển thị, biên độ mờ đục, tương phản màu và bảo toàn QR cho `SECRET`/`TOP_SECRET`.
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
    if (input.colorHex !== undefined) {
      const hex = input.colorHex.slice(1);
      const r = Number.parseInt(hex.slice(0, 2), 16) / 255;
      const g = Number.parseInt(hex.slice(2, 4), 16) / 255;
      const b = Number.parseInt(hex.slice(4, 6), 16) / 255;
      const luminance = 0.2126 * r + 0.7152 * g + 0.0722 * b;
      if (luminance > 0.88) {
        throw new BadRequestException(
          'Watermark color cannot be near-white; sufficient contrast on light pages is required.',
        );
      }
    }

    const existing = await this.database.watermarkConfig.findUnique({
      where: { id },
      include: {
        classification_levels: {
          select: { code: true, rank: true },
        },
      },
    });
    if (!existing) {
      throw new NotFoundException('Watermark configuration not found.');
    }

    const existingWithClass = existing as typeof existing & {
      classification_levels?: { code?: string; rank?: number } | null;
    };
    let classCode = existingWithClass.classification_levels?.code ?? null;
    let classRank = existingWithClass.classification_levels?.rank ?? null;
    if (
      classCode === null &&
      existing.classification_level_id !== null &&
      typeof this.database.classificationLevel?.findUnique === 'function'
    ) {
      const level = await this.database.classificationLevel.findUnique({
        where: { id: existing.classification_level_id },
        select: { code: true, rank: true },
      });
      classCode = level?.code ?? null;
      classRank = level?.rank ?? null;
    }

    assertHighClassificationWatermarkIntegrity({
      classificationCode: classCode,
      classificationRank: classRank,
      includeQrCode: input.includeQrCode ?? existing.include_qr_code,
      templateText: input.templateText ?? existing.template_text,
    });

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

    if (typeof this.stateStore?.putEphemeral === 'function') {
      try {
        await this.stateStore.putEphemeral(
          WATERMARK_CONFIG_EPOCH_NAMESPACE,
          WATERMARK_CONFIG_EPOCH_KEY,
          {
            updatedAt: updated.updated_at.toISOString(),
            configId: updated.id.toString(),
          },
          DERIVATIVE_CACHE_TTL_MS,
        );
      } catch {
        // Non-fatal cache epoch bump failure; new sessions still load fresh DB config.
      }
    }

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
   * Thuật toán: Truy vết định danh pháp y từ mã watermark tài liệu rò rỉ (`Forensic Watermark Token Attribution - UC28`).
   */
  async verifyWatermarkToken(
    token: string,
    actor?: AuthPrincipal,
    context?: Partial<RequestContext>,
  ): Promise<WatermarkVerificationResult> {
    return traceWatermarkToken(
      this.database,
      this.auditWriter,
      this.logger,
      token,
      actor,
      this.authorization,
      context,
    );
  }
}
