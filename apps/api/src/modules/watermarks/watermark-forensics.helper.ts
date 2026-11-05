/**
 * Module: WatermarkForensicsHelper — Truy vết ngược nguồn gốc rò rỉ tài liệu từ mã `watermark_token` (Forensic Leak Attribution Engine - UC28).
 */
import { ForbiddenException, NotFoundException, type Logger } from '@nestjs/common';
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

/**
 * Thuật toán: Đối soát sổ cái thủy vân & dựng hồ sơ quy kết trách nhiệm rò rỉ (Forensic Watermark Token Trace & Audit Attribution)
 * Mục đích: Xác minh mã thủy vân từ bản tài liệu nghi lộ lọt để truy ra người nhận, phiên truy cập, địa chỉ IP, mức độ mật thực tế và mã băm gốc/dẫn xuất.
 * Cơ chế hoạt động:
 *   - Tra cứu khóa duy nhất `watermark_token` trong `watermarkInstance` kết hợp nạp quan hệ `users`, `access_sessions`, `document_versions.document` (kèm `classification_history` hiện hành) và `watermark_configs`.
 *   - Ghi nhật ký kiểm toán bất biến `WATERMARK_TRACE_PERFORMED` vào phân vùng `ACCESS_SESSION` và trả cờ xác thực tường minh `verified: true` phục vụ giao diện Fail-Closed.
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
  logger.log(`Verifying watermark token: ${token.slice(0, 11)}...`);
  const instance = await database.watermarkInstance.findUnique({
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
              department_id: true,
              classification_history: {
                where: { effective_to: null },
                take: 1,
                select: {
                  classification_levels: {
                    select: { code: true, name: true, rank: true },
                  },
                },
              },
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

  const docWithClass = instance.document_versions.document as {
    id: string;
    title: string;
    document_code: string | null;
    department_id?: bigint;
    classification_history?: Array<{
      classification_levels?: { code?: string; name?: string; rank?: number } | null;
    }>;
  };
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

  const classificationName = activeLevel?.code ?? activeLevel?.name ?? null;

  return {
    verified: true,
    watermarkToken: instance.watermark_token,
    renderedText: instance.rendered_text,
    outputSha256Hash: instance.output_sha256_hash,
    generatedAt: instance.generated_at.toISOString(),
    classificationName,
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
      id: docWithClass.id,
      title: docWithClass.title,
      documentCode: docWithClass.document_code,
      classificationName,
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
