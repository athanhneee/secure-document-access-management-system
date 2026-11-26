/**
 * @module SessionRiskScorerHelper
 * Thuật toán: Chấm Điểm Rủi Ro Phiên Thời Gian Thực Tất Định (Deterministic Runtime Session Risk Scoring 0–100).
 * Mục đích: Thay thế giá trị tĩnh `riskScore: 0` tại cổng thực thi PEP bằng điểm rủi ro cộng dồn từ các tín hiệu
 * ngữ cảnh thực tế (mạng ngoài tin cậy, lệch IP/User-Agent so với phiên đăng nhập, thiếu MFA, thiết bị chưa tin cậy,
 * truy cập ngoài giờ hành chính, số lần đăng nhập sai gần đây và cảnh báo an ninh HIGH/CRITICAL đang mở),
 * giúp luật `POL-DENY-HIGH-RISK-SESSION` (`environment.riskScore >= 80`) phát huy hiệu lực thực sự khi vận hành.
 */
import type { getDatabaseClient } from '@sda/database';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

export const SESSION_RISK_TIMEZONE = 'Asia/Ho_Chi_Minh';
export const BUSINESS_HOURS_START = 7;
export const BUSINESS_HOURS_END = 20;

export interface SessionRiskSignals {
  trustedNetwork: boolean;
  mfa: boolean;
  deviceTrust: boolean;
  ipChangedFromAuthSession: boolean;
  userAgentChangedFromAuthSession: boolean;
  failedLoginCount: number;
  openHighAlertCount: number;
  openCriticalAlertCount: number;
  classificationRank: number;
  now: Date;
}

export interface SessionRiskAssessment {
  riskScore: number;
  deviceTrust: boolean;
  factors: string[];
}

import { canonicalizeIpAddress } from './cidr.js';

function normalizeComparableIp(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;
  const withoutZone = trimmed.includes('%') ? trimmed.slice(0, trimmed.indexOf('%')) : trimmed;
  return canonicalizeIpAddress(withoutZone) ?? withoutZone.toLowerCase();
}

function isOffBusinessHours(now: Date): boolean {
  try {
    const hourText = new Intl.DateTimeFormat('en-GB', {
      timeZone: SESSION_RISK_TIMEZONE,
      hour: '2-digit',
      hour12: false,
    }).format(now);
    const parsedHour = Number.parseInt(hourText, 10);
    if (!Number.isFinite(parsedHour)) return false;
    const hour = parsedHour % 24;
    return hour < BUSINESS_HOURS_START || hour >= BUSINESS_HOURS_END;
  } catch {
    return false;
  }
}

/**
 * Thuật toán: Tính Điểm Rủi Ro Phiên Cộng Dồn Có Chặn Biên `[0, 100]` (`computeSessionRiskScore`).
 * Bảng trọng số tất định:
 *   - Mạng ngoài dải CIDR tin cậy (`!trustedNetwork`): `+30`
 *   - Địa chỉ IP yêu cầu lệch khỏi phiên đăng nhập (`ipChangedFromAuthSession`): `+25`
 *   - Trình duyệt/User-Agent lệch khỏi phiên đăng nhập (`userAgentChangedFromAuthSession`): `+15`
 *   - Phiên chưa xác thực MFA (`!mfa`): `+15` (cộng thêm `+10` nếu truy cập tài liệu hạng `>= 3` SECRET/TOP_SECRET)
 *   - Thiết bị chưa được xác nhận tin cậy (`!deviceTrust`): `+15`
 *   - Truy cập ngoài khung giờ hành chính `07:00–20:00` (`Asia/Ho_Chi_Minh`): `+10`
 *   - Số lần đăng nhập thất bại tích lũy (`>= 5`: `+20`, `>= 3`: `+10`)
 *   - Cảnh báo an ninh đang mở (`OPEN` / `INVESTIGATING`): `CRITICAL` (`+40`), `>= 2 HIGH` (`+30`), `1 HIGH` (`+20`).
 */
export function computeSessionRiskScore(signals: SessionRiskSignals): SessionRiskAssessment {
  let score = 0;
  const factors: string[] = [];

  if (!signals.trustedNetwork) {
    score += 30;
    factors.push('UNTRUSTED_NETWORK');
  }
  if (signals.ipChangedFromAuthSession) {
    score += 25;
    factors.push('SESSION_IP_DRIFT');
  }
  if (signals.userAgentChangedFromAuthSession) {
    score += 15;
    factors.push('SESSION_UA_DRIFT');
  }
  if (!signals.mfa) {
    score += 15;
    factors.push('NO_MFA');
    if (signals.classificationRank >= 3) {
      score += 10;
      factors.push('SENSITIVE_NO_MFA');
    }
  }
  if (!signals.deviceTrust) {
    score += 15;
    factors.push('UNTRUSTED_DEVICE');
  }
  if (isOffBusinessHours(signals.now)) {
    score += 10;
    factors.push('OFF_HOURS_ACCESS');
  }
  if (signals.failedLoginCount >= 5) {
    score += 20;
    factors.push('REPEATED_FAILED_LOGINS');
  } else if (signals.failedLoginCount >= 3) {
    score += 10;
    factors.push('RECENT_FAILED_LOGINS');
  }
  if (signals.openCriticalAlertCount >= 1) {
    score += 40;
    factors.push('ACTIVE_CRITICAL_SECURITY_ALERT');
  } else if (signals.openHighAlertCount >= 2) {
    score += 30;
    factors.push('MULTIPLE_HIGH_SECURITY_ALERTS');
  } else if (signals.openHighAlertCount === 1) {
    score += 20;
    factors.push('ACTIVE_HIGH_SECURITY_ALERT');
  }

  return {
    riskScore: Math.max(0, Math.min(100, score)),
    deviceTrust: signals.deviceTrust,
    factors,
  };
}

/**
 * Thuật toán: Thu Thập Tín Hiệu An Ninh Thời Gian Thực Từ CSDL & Tính Điểm Rủi Ro PEP (`evaluatePepSessionRisk`).
 * Cơ chế hoạt động:
 *   - Truy vấn song song phiên đăng nhập `auth_sessions`, số lần sai mật khẩu `users.failed_login_count`,
 *     cảnh báo SOC đang mở (`OPEN`/`INVESTIGATING`) và lịch sử dấu vân tay thiết bị `access_sessions`.
 *   - An toàn với môi trường kiểm thử nhẹ khi một số phương thức mock không được khai báo.
 */
export async function evaluatePepSessionRisk(params: {
  database: PrismaClient;
  principal: AuthPrincipal;
  context: RequestContext;
  trustedNetwork: boolean;
  classificationRank: number;
  deviceFingerprint?: string | null | undefined;
  now: Date;
}): Promise<SessionRiskAssessment> {
  const { database, principal, context, trustedNetwork, classificationRank, now } = params;
  const trimmedFingerprint = params.deviceFingerprint?.trim() || null;

  const [authSession, userRecord, openAlerts, knownDeviceSession] = await Promise.all([
    principal.sessionId && typeof database?.authSession?.findUnique === 'function'
      ? database.authSession
          .findUnique({
            where: { id: principal.sessionId },
            select: {
              login_ip_address: true,
              login_user_agent: true,
              ip_address: true,
              user_agent: true,
            },
          })
          .catch(() => null)
      : Promise.resolve(null),
    typeof database?.user?.findUnique === 'function'
      ? database.user
          .findUnique({
            where: { id: principal.userId },
            select: { failed_login_count: true },
          })
          .catch(() => null)
      : Promise.resolve(null),
    typeof database?.securityAlert?.findMany === 'function'
      ? database.securityAlert
          .findMany({
            where: {
              detected_user_id: principal.userId,
              status: { in: ['OPEN', 'INVESTIGATING'] },
              severity: { in: ['HIGH', 'CRITICAL'] },
            },
            select: { severity: true },
            take: 20,
          })
          .catch(() => [])
      : Promise.resolve([]),
    trimmedFingerprint &&
    trimmedFingerprint.length >= 8 &&
    typeof database?.accessSession?.findFirst === 'function'
      ? database.accessSession
          .findFirst({
            where: {
              user_id: principal.userId,
              device_fingerprint: trimmedFingerprint,
              status: { in: ['ACTIVE', 'ENDED'] },
            },
            select: { id: true },
          })
          .catch(() => null)
      : Promise.resolve(null),
  ]);

  const sessionBaseline = authSession as {
    login_ip_address?: string | null;
    login_user_agent?: string | null;
    ip_address?: string | null;
    user_agent?: string | null;
  } | null;
  const authIp = normalizeComparableIp(
    sessionBaseline?.login_ip_address ?? sessionBaseline?.ip_address,
  );
  const currentIp = normalizeComparableIp(context?.ip);
  const ipChangedFromAuthSession = Boolean(authIp && currentIp && authIp !== currentIp);

  const authUa = (sessionBaseline?.login_user_agent ?? sessionBaseline?.user_agent)?.trim() || null;
  const currentUa = context?.userAgent?.trim() || null;
  const userAgentChangedFromAuthSession = Boolean(authUa && currentUa && authUa !== currentUa);

  const rawFailedCount = (userRecord as { failed_login_count?: number } | null)?.failed_login_count;
  const failedLoginCount =
    typeof rawFailedCount === 'number' && Number.isFinite(rawFailedCount) ? rawFailedCount : 0;

  let openHighAlertCount = 0;
  let openCriticalAlertCount = 0;
  for (const alert of openAlerts as Array<{ severity?: string }>) {
    if (alert.severity === 'CRITICAL') openCriticalAlertCount += 1;
    else if (alert.severity === 'HIGH') openHighAlertCount += 1;
  }

  return computeSessionRiskScore({
    trustedNetwork,
    mfa: Boolean(principal.mfa),
    deviceTrust: Boolean(knownDeviceSession),
    ipChangedFromAuthSession,
    userAgentChangedFromAuthSession,
    failedLoginCount,
    openHighAlertCount,
    openCriticalAlertCount,
    classificationRank,
    now,
  });
}
