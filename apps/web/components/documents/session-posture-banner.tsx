'use client';

import Link from 'next/link';
import { AlertTriangle, Laptop, ShieldAlert, ShieldCheck, Wifi } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { formatSessionRiskFactorLabels } from '@/lib/api-error-messages';
import type { SessionSecurityPosture } from '@/lib/use-session-posture';

export interface SessionPostureBannerProps {
  posture: SessionSecurityPosture | null;
  mfaActionHref: string;
  userClearanceRank?: number | undefined;
  hasTopSecretDocuments?: boolean | undefined;
  suppressProactiveAlert?: boolean | undefined;
}

/**
 * Thuật toán: Hiển Thị Trạng Thái Bảo Mật Cấp Phiên (MFA, Mạng, Rủi Ro) & Cảnh Báo Tiền Kiểm Chủ Động (`SessionPostureBanner`)
 * Mục đích:
 *   - Giúp người đọc và chủ sở hữu nhận biết ngay trên không gian làm việc liệu phiên hiện tại đã xác thực MFA,
 *     có đang ở mạng tin cậy và có chạm ngưỡng rủi ro chặn tài liệu hay chưa — trước khi bấm mở tài liệu.
 *   - Tuân thủ tuyệt đối chuẩn thiết kế `staff-001` (nhãn phẳng không hộp capsule, bảng 13 mã màu chuẩn, icon Lucide 16px).
 */
export function SessionPostureBanner({
  posture,
  mfaActionHref,
  userClearanceRank,
  hasTopSecretDocuments = false,
  suppressProactiveAlert = false,
}: SessionPostureBannerProps) {
  if (!posture) {
    return null;
  }

  const mfaLabel = posture.mfaEnabled ? 'Xác thực MFA ngay' : 'Thiết lập MFA (TOTP / Passkey)';
  const factorLabels = formatSessionRiskFactorLabels(posture.riskFactors);
  const riskVariant = posture.highRiskBlocked
    ? 'danger'
    : posture.riskScore >= 50 || posture.sensitiveHighRiskBlocked
      ? 'warning'
      : 'success';
  const riskSummaryLabel = posture.highRiskBlocked
    ? `Rủi ro cao (${posture.riskScore}/${posture.riskThreshold}) · Tạm chặn mở tài liệu`
    : posture.riskScore >= 50 || posture.sensitiveHighRiskBlocked
      ? `Rủi ro trung bình (${posture.riskScore}/${posture.riskThreshold})`
      : `Phiên an toàn (rủi ro ${posture.riskScore}/${posture.riskThreshold})`;

  const needsTopSecretMfaNotice =
    !posture.mfaVerified &&
    (hasTopSecretDocuments ||
      (typeof userClearanceRank === 'number' && userClearanceRank >= 4) ||
      posture.sensitiveHighRiskBlocked);

  return (
    <div className="space-y-2.5">
      <div className="flex flex-col sm:flex-row sm:flex-wrap sm:items-center sm:justify-between gap-2 rounded-[14px] border border-[#ebebeb] bg-[#ffffff] px-3.5 py-2.5 text-xs text-[#717171]">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
          <Badge variant={posture.mfaVerified ? 'success' : 'warning'}>
            {posture.mfaVerified ? 'Phiên đã xác thực MFA' : 'Phiên chưa xác thực MFA'}
          </Badge>

          <Badge variant={riskVariant}>{riskSummaryLabel}</Badge>

          <span
            className={`inline-flex items-center gap-1 font-medium whitespace-nowrap ${
              posture.trustedNetwork ? 'text-[#008A05]' : 'text-[#222222]'
            }`}
          >
            <Wifi
              size={16}
              strokeWidth={1.75}
              className={posture.trustedNetwork ? 'text-[#008A05]' : 'text-[#E07912]'}
              aria-hidden="true"
            />
            <span>{posture.trustedNetwork ? 'Mạng tin cậy' : 'Mạng ngoài dải tin cậy'}</span>
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {!posture.mfaVerified && (
            <Link
              href={mfaActionHref}
              className="inline-flex min-h-11 sm:min-h-8 items-center gap-1 font-semibold text-[#E31C5F] hover:underline"
            >
              <ShieldCheck size={16} strokeWidth={1.75} aria-hidden="true" />
              <span>{posture.mfaEnabled ? 'Xác thực MFA' : 'Thiết lập MFA'}</span>
            </Link>
          )}
          <Link
            href="/sessions"
            className="hidden sm:inline-flex min-h-8 items-center gap-1 font-medium text-[#008489] hover:underline"
          >
            <Laptop size={16} strokeWidth={1.75} aria-hidden="true" />
            <span>Phiên &amp; thiết bị</span>
          </Link>
        </div>
      </div>

      {!suppressProactiveAlert && posture.highRiskBlocked && (
        <Alert variant="destructive" className="text-xs">
          <ShieldAlert
            size={16}
            strokeWidth={1.75}
            className="shrink-0 text-[#C13515]"
            aria-hidden="true"
          />
          <div className="ml-2 flex flex-col gap-2 w-full">
            <AlertDescription className="leading-relaxed">
              Phiên hiện tại đang có điểm rủi ro vượt ngưỡng an toàn ({posture.riskScore}/
              {posture.riskThreshold})
              {factorLabels.length > 0 ? ` do: ${factorLabels.join(', ')}` : ''}. Thao tác xem và
              tải tài liệu tạm thời bị chặn theo chính sách bảo mật.
            </AlertDescription>
            <div className="flex flex-wrap items-center gap-2">
              {!posture.mfaVerified && (
                <Link
                  href={mfaActionHref}
                  className="inline-flex min-h-11 sm:min-h-8 items-center gap-1.5 rounded-full bg-[#FF385C] px-3.5 py-1.5 text-xs font-semibold text-[#ffffff] hover:bg-[#E31C5F] transition-colors"
                >
                  <ShieldCheck size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>{mfaLabel}</span>
                </Link>
              )}
              <Link
                href="/sessions"
                className="inline-flex min-h-11 sm:min-h-8 items-center gap-1.5 rounded-full border border-[#dddddd] bg-[#ffffff] px-3.5 py-1.5 text-xs font-semibold text-[#222222] hover:bg-[#f7f7f7] transition-colors"
              >
                <Laptop size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>Kiểm tra phiên &amp; thiết bị</span>
              </Link>
            </div>
          </div>
        </Alert>
      )}

      {!suppressProactiveAlert && !posture.highRiskBlocked && needsTopSecretMfaNotice && (
        <Alert variant="warning" className="text-xs">
          <AlertTriangle
            size={16}
            strokeWidth={1.75}
            className="shrink-0 text-[#E07912]"
            aria-hidden="true"
          />
          <div className="ml-2 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 w-full">
            <AlertDescription className="leading-relaxed">
              {posture.sensitiveHighRiskBlocked
                ? `Phiên hiện chưa xác thực MFA và sẽ vượt ngưỡng rủi ro (${posture.sensitiveRiskScore}/${posture.riskThreshold}) khi mở tài liệu Tối mật / Tuyệt mật. Hãy xác thực MFA trước để truy cập ổn định.`
                : 'Phiên đăng nhập hiện tại chưa xác thực đa yếu tố (MFA). Tài liệu mức Tuyệt mật yêu cầu hoàn tất xác thực MFA trước khi xem.'}
            </AlertDescription>
            <Link
              href={mfaActionHref}
              className="inline-flex shrink-0 min-h-11 sm:min-h-8 items-center gap-1.5 rounded-full bg-[#FF385C] px-3.5 py-1.5 text-xs font-semibold text-[#ffffff] hover:bg-[#E31C5F] transition-colors self-start sm:self-center"
            >
              <ShieldCheck size={16} strokeWidth={1.75} aria-hidden="true" />
              <span>{mfaLabel}</span>
            </Link>
          </div>
        </Alert>
      )}
    </div>
  );
}
