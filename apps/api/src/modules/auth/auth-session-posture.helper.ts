/**
 * @module AuthSessionPostureHelper
 * Thuật toán: Đánh Giá Trạng Thái Bảo Mật Cấp Phiên Thời Gian Thực Chỉ Đọc (`evaluateSessionSecurityPosture`).
 * Mục đích:
 *   - Cung cấp ảnh chụp trạng thái phiên hiện tại (`mfaVerified`, `mfaEnabled`, `trustedNetwork`, `deviceTrust`,
 *     `riskScore`, `sensitiveRiskScore`, `riskFactors`) cho giao diện `/reader` và `/owner` để cảnh báo sớm
 *     người dùng trước khi bấm mở tài liệu mà không làm lộ quy tắc ABAC nội bộ hay tạo bản ghi phiên giả.
 *   - Tái sử dụng đúng bộ đối chiếu CIDR `resolvePepTrustedNetwork` và bộ chấm điểm `evaluatePepSessionRisk` của PEP.
 */
import type { getDatabaseClient } from '@sda/database';
import type { AppConfigService } from '../../config/config.service.js';
import { evaluatePepSessionRisk } from '../abac/session-risk-scorer.helper.js';
import { resolvePepTrustedNetwork } from '../documents/pep-context-builder.js';
import type { AuthPrincipal, RequestContext } from './auth.types.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export const HIGH_RISK_SESSION_THRESHOLD = 80;
const SENSITIVE_NO_MFA_INCREMENT = 10;

export interface SessionSecurityPosture {
  mfaVerified: boolean;
  mfaEnabled: boolean;
  trustedNetwork: boolean;
  deviceTrust: boolean;
  riskScore: number;
  sensitiveRiskScore: number;
  riskThreshold: number;
  highRiskBlocked: boolean;
  sensitiveHighRiskBlocked: boolean;
  topSecretRequiresMfa: boolean;
  riskFactors: string[];
  evaluatedAt: string;
}

/**
 * Thuật toán: Chuẩn Hóa Tiêu Đề Dấu Vân Tay Thiết Bị An Toàn (`sanitizeDeviceFingerprintHeader`)
 * Chỉ nhận chuỗi đơn, loại bỏ khoảng trắng hai đầu và chặn giới hạn `<= 255` ký tự khớp `CreateAccessSessionSchema`.
 */
export function sanitizeDeviceFingerprintHeader(raw: unknown): string | undefined {
  if (typeof raw !== 'string') return undefined;
  const trimmed = raw.trim();
  if (trimmed.length === 0 || trimmed.length > 255) return undefined;
  return trimmed;
}

/**
 * Thuật toán: Đánh Giá Trạng Thái An Ninh Phiên Thời Gian Thực Không Ghi Trạng Thái (`evaluateSessionSecurityPosture`).
 */
export async function evaluateSessionSecurityPosture(params: {
  database: PrismaClient | undefined;
  config: AppConfigService | undefined;
  principal: AuthPrincipal;
  context: RequestContext;
  deviceFingerprint?: string | undefined;
  now?: Date | undefined;
}): Promise<SessionSecurityPosture> {
  const { database, config, principal, context, deviceFingerprint } = params;
  const now = params.now ?? new Date();
  const trustedNetwork = resolvePepTrustedNetwork(config, context.ip);

  const [riskAssessment, activeMfaCount] = await Promise.all([
    evaluatePepSessionRisk({
      database: database as PrismaClient,
      principal,
      context,
      trustedNetwork,
      classificationRank: 1,
      deviceFingerprint,
      now,
    }),
    typeof database?.mfaMethod?.count === 'function'
      ? database.mfaMethod
          .count({
            where: {
              user_id: principal.userId,
              enabled_at: { not: null },
              disabled_at: null,
            },
          })
          .catch(() => 0)
      : Promise.resolve(0),
  ]);

  const mfaVerified = Boolean(principal.mfa);
  const sensitiveRiskScore = mfaVerified
    ? riskAssessment.riskScore
    : Math.min(100, riskAssessment.riskScore + SENSITIVE_NO_MFA_INCREMENT);

  return {
    mfaVerified,
    mfaEnabled: activeMfaCount > 0,
    trustedNetwork,
    deviceTrust: riskAssessment.deviceTrust,
    riskScore: riskAssessment.riskScore,
    sensitiveRiskScore,
    riskThreshold: HIGH_RISK_SESSION_THRESHOLD,
    highRiskBlocked: riskAssessment.riskScore >= HIGH_RISK_SESSION_THRESHOLD,
    sensitiveHighRiskBlocked: sensitiveRiskScore >= HIGH_RISK_SESSION_THRESHOLD,
    topSecretRequiresMfa: !mfaVerified,
    riskFactors: riskAssessment.factors,
    evaluatedAt: now.toISOString(),
  };
}
