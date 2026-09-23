import { Injectable, NotFoundException, Logger, Optional } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import { AuditWriterService } from '../audit/audit-writer.service.js';
import type { AuthPrincipal } from '../auth/auth.types.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface WatermarkVerificationResult {
  watermarkToken: string;
  renderedText: string;
  outputSha256Hash: string | null;
  generatedAt: string;
  user: {
    id: string;
    username: string;
    fullName: string | null;
    employeeCode: string | null;
    email: string;
  };
  session: {
    id: string;
    startedAt: string;
    ipAddress: string;
    userAgent: string | null;
  };
  document: {
    id: string;
    title: string;
    documentCode: string | null;
    versionNo: number;
    originalSha256Hash: string;
  };
  config: {
    name: string;
    opacityPercent: number;
    fontSize: number;
    includeQrCode: boolean;
  };
}

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
   * List all active watermark configurations.
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
        classificationLevel: c.classification_levels,
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
   * UC28: Trace a watermark token to verify the user, session, document, version, and generation time.
   * Essential for forensic investigation of document leaks.
   */
  async verifyWatermarkToken(
    token: string,
    actor?: AuthPrincipal,
  ): Promise<WatermarkVerificationResult> {
    this.logger.log(`Verifying watermark token: ${token}`);
    const instance = await this.database.watermarkInstance.findUnique({
      where: { watermark_token: token },
      include: {
        users: {
          select: {
            id: true,
            username: true,
            full_name: true,
            employee_code: true,
            email: true,
          },
        },
        access_sessions: {
          select: {
            id: true,
            started_at: true,
            ip_address: true,
            user_agent: true,
          },
        },
        document_versions: {
          select: {
            version_no: true,
            sha256_hash: true,
            document: {
              select: {
                id: true,
                title: true,
                document_code: true,
              },
            },
          },
        },
        watermark_configs: {
          select: {
            name: true,
            opacity_percent: true,
            font_size: true,
            include_qr_code: true,
          },
        },
      },
    });

    if (!instance) {
      throw new NotFoundException({
        errorCode: AppErrorCode.WATERMARK_TOKEN_NOT_FOUND,
        message: 'Watermark token was not found in the reconciliation registry.',
      });
    }

    if (this.auditWriter && actor) {
      await this.auditWriter.writeLog({
        actorUserId: actor.userId,
        actorUsername: actor.username,
        action: 'WATERMARK_TRACE_PERFORMED',
        objectType: 'WATERMARK_INSTANCE',
        objectId: instance.id,
        documentId: instance.document_versions.document.id,
        accessSessionId: instance.access_sessions.id,
        outcome: 'SUCCESS',
        chainPartition: 'ACCESS_SESSION',
        details: {
          watermarkToken: token,
          tracedUserId: instance.users.id.toString(),
          tracedUsername: instance.users.username,
        },
      });
    }

    return {
      watermarkToken: instance.watermark_token,
      renderedText: instance.rendered_text,
      outputSha256Hash: instance.output_sha256_hash,
      generatedAt: instance.generated_at.toISOString(),
      user: {
        id: instance.users.id.toString(),
        username: instance.users.username,
        fullName: instance.users.full_name,
        employeeCode: instance.users.employee_code,
        email: instance.users.email,
      },
      session: {
        id: instance.access_sessions.id,
        startedAt: instance.access_sessions.started_at.toISOString(),
        ipAddress: instance.access_sessions.ip_address,
        userAgent: instance.access_sessions.user_agent,
      },
      document: {
        id: instance.document_versions.document.id,
        title: instance.document_versions.document.title,
        documentCode: instance.document_versions.document.document_code,
        versionNo: instance.document_versions.version_no,
        originalSha256Hash: instance.document_versions.sha256_hash,
      },
      config: {
        name: instance.watermark_configs.name,
        opacityPercent: instance.watermark_configs.opacity_percent,
        fontSize: instance.watermark_configs.font_size,
        includeQrCode: instance.watermark_configs.include_qr_code,
      },
    };
  }
}
