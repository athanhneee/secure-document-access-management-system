/**
 * @module WatermarkForensicsHelper
 * Thuật toán: Truy vết ngược nguồn gốc rò rỉ tài liệu từ cả mã đầy đủ `WM-<48-hex>` (khớp chính xác)
 * lẫn tiền tố hiển thị 15 ký tự `WM-<12-hex>` (`startsWith` giới hạn `take: 2`, báo xung đột `AMBIGUOUS_WATERMARK_TOKEN`
 * nếu trùng 2 bản ghi) kèm kiểm soát phạm vi phòng ban và ghi nhật ký `WATERMARK_TRACE_PERFORMED`.
 */
import {
  ConflictException,
  ForbiddenException,
  NotFoundException,
  type Logger,
} from '@nestjs/common';
import type { getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AuditWriterService } from '../audit/audit-writer.service.js';
import type { AuthPrincipal } from '../auth/auth.types.js';
import type { AuthorizationService } from '../rbac/authorization.service.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export interface WatermarkVerificationResult {
  verified: true;
  watermarkToken: string;
  renderedText: string;
  outputSha256Hash: string | null;
  generatedAt: string;
  classificationName: string | null;
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
    classificationName: string | null;
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

const SHORT_WATERMARK_TOKEN_REGEX = /^WM-[0-9a-f]{12}$/iu;

const FORENSIC_INSTANCE_INCLUDE = {
  users: {
    select: { id: true, username: true, full_name: true, employee_code: true, email: true },
  },
  access_sessions: { select: { id: true, started_at: true, ip_address: true, user_agent: true } },
  document_versions: {
    select: {
      version_no: true,
      sha256_hash: true,
      document: {
        select: {
          id: true,
          title: true,
          document_code: true,
          department_id: true,
          classification_history: {
            where: { effective_to: null },
            take: 1,
            select: { classification_levels: { select: { code: true, name: true, rank: true } } },
          },
        },
      },
    },
  },
  watermark_configs: {
    select: { name: true, opacity_percent: true, font_size: true, include_qr_code: true },
  },
} as const;

/**
 * Thuật toán: Đối soát sổ cái thủy vân hỗ trợ đồng thời mã đầy đủ `WM-<48-hex>` và tiền tố ngắn `WM-<12-hex>`.
 */
export async function traceWatermarkToken(
  database: PrismaClient,
  auditWriter: AuditWriterService | undefined,
  logger: Logger,
  token: string,
  actor?: AuthPrincipal,
  authorization?: AuthorizationService,
): Promise<WatermarkVerificationResult> {
  if (authorization && !actor) {
    throw new ForbiddenException({
      errorCode: AppErrorCode.FORBIDDEN,
      message: 'Authenticated principal is required for watermark forensic attribution.',
    });
  }
  const normalizedToken = token.trim();
  logger.log(`Verifying watermark token: ${normalizedToken.slice(0, 11)}...`);

  const findExactInstance = () =>
    database.watermarkInstance.findUnique({
      where: { watermark_token: normalizedToken },
      include: FORENSIC_INSTANCE_INCLUDE,
    });
  type ForensicInstanceRecord = Awaited<ReturnType<typeof findExactInstance>>;
  let instance: ForensicInstanceRecord = null;
  if (
    normalizedToken.length === 15 &&
    SHORT_WATERMARK_TOKEN_REGEX.test(normalizedToken) &&
    typeof database.watermarkInstance?.findMany === 'function'
  ) {
    const matches = await database.watermarkInstance.findMany({
      where: { watermark_token: { startsWith: normalizedToken } },
      take: 2,
      include: FORENSIC_INSTANCE_INCLUDE,
    });
    if (matches.length > 1) {
      throw new ConflictException({
        code: 'AMBIGUOUS_WATERMARK_TOKEN',
        errorCode: 'AMBIGUOUS_WATERMARK_TOKEN',
        message:
          'Multiple watermark instances match this short token prefix; please scan or provide the full QR watermark token.',
      });
    }
    instance = matches[0] ?? null;
  } else {
    instance = await findExactInstance();
  }

  if (!instance) {
    throw new NotFoundException({
      errorCode: AppErrorCode.WATERMARK_TOKEN_NOT_FOUND,
      message: 'Watermark token was not found in the reconciliation registry.',
    });
  }

  const typedInstance = instance as NonNullable<typeof instance> & {
    users: {
      id: bigint;
      username: string;
      full_name: string | null;
      employee_code: string | null;
      email: string;
    };
    access_sessions: {
      id: string;
      started_at: Date;
      ip_address: string;
      user_agent: string | null;
    };
    document_versions: {
      version_no: number;
      sha256_hash: string;
      document: {
        id: string;
        title: string;
        document_code: string | null;
        department_id?: bigint;
        classification_history?: Array<{
          classification_levels?: { code?: string; name?: string; rank?: number } | null;
        }>;
      };
    };
    watermark_configs: {
      name: string;
      opacity_percent: number;
      font_size: number;
      include_qr_code: boolean;
    };
  };

  const docWithClass = typedInstance.document_versions.document;
  const activeLevel = docWithClass.classification_history?.[0]?.classification_levels;

  // CONFLICT-RESOLVED: Giới hạn phạm vi phòng ban và chặn cán bộ cấp phòng ban truy vết thủy vân liên phòng ban hoặc tài liệu `TOP_SECRET` (HIGH-06).
  if (authorization && actor && typeof authorization.visibleDepartmentIds === 'function') {
    const visibleDepts = await authorization.visibleDepartmentIds(
      actor,
      'WATERMARK_INSTANCE',
      'TRACE',
    );
    if (visibleDepts !== null) {
      const isTopSecret = activeLevel?.code === 'TOP_SECRET' || (activeLevel?.rank ?? 0) >= 4;
      const inScope =
        docWithClass.department_id !== undefined &&
        visibleDepts.includes(docWithClass.department_id);
      if (!inScope || isTopSecret) {
        throw new NotFoundException({
          errorCode: AppErrorCode.WATERMARK_TOKEN_NOT_FOUND,
          message: 'Watermark token was not found in the reconciliation registry.',
        });
      }
    }
  }

  if (auditWriter && actor) {
    await auditWriter.writeLog({
      actorUserId: actor.userId,
      actorUsername: actor.username,
      action: 'WATERMARK_TRACE_PERFORMED',
      objectType: 'WATERMARK_INSTANCE',
      objectId: typedInstance.id,
      documentId: docWithClass.id,
      accessSessionId: typedInstance.access_sessions.id,
      outcome: 'SUCCESS',
      chainPartition: 'ACCESS_SESSION',
      details: {
        watermarkToken: typedInstance.watermark_token,
        queriedToken: normalizedToken,
        tracedUserId: typedInstance.users.id.toString(),
        tracedUsername: typedInstance.users.username,
      },
    });
  }

  const classificationName = activeLevel?.code ?? activeLevel?.name ?? null;

  return {
    verified: true,
    watermarkToken: typedInstance.watermark_token,
    renderedText: typedInstance.rendered_text,
    outputSha256Hash: typedInstance.output_sha256_hash,
    generatedAt: typedInstance.generated_at.toISOString(),
    classificationName,
    user: {
      id: typedInstance.users.id.toString(),
      username: typedInstance.users.username,
      fullName: typedInstance.users.full_name,
      employeeCode: typedInstance.users.employee_code,
      email: typedInstance.users.email,
    },
    session: {
      id: typedInstance.access_sessions.id,
      startedAt: typedInstance.access_sessions.started_at.toISOString(),
      ipAddress: typedInstance.access_sessions.ip_address,
      userAgent: typedInstance.access_sessions.user_agent,
    },
    document: {
      id: docWithClass.id,
      title: docWithClass.title,
      documentCode: docWithClass.document_code,
      classificationName,
      versionNo: typedInstance.document_versions.version_no,
      originalSha256Hash: typedInstance.document_versions.sha256_hash,
    },
    config: {
      name: typedInstance.watermark_configs.name,
      opacityPercent: typedInstance.watermark_configs.opacity_percent,
      fontSize: typedInstance.watermark_configs.font_size,
      includeQrCode: typedInstance.watermark_configs.include_qr_code,
    },
  };
}
