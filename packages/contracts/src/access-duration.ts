/**
 * @module AccessDurationContracts
 * Algorithm: Deterministic Document Retention Ceiling & Smart Access Duration Preset Resolution (`O(1)`).
 * Thống nhất quy tắc tính trần thời hạn truy cập (`min(GRANT_MAX_DURATION_DAYS, retention_until)`),
 * thời hạn mặc định theo mức độ mật (`default_view_days`) và danh sách mốc chọn nhanh hợp lệ cho cả Backend & Frontend.
 */
import { resolveClassificationDefaultViewDays } from './classifications.js';
import { DEFAULT_GRANT_MAX_DURATION_DAYS } from './dto/access-control.dto.js';

export const ACCESS_DURATION_DAY_MS = 86_400_000;
const ISO_DATE_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

export interface EffectiveAccessCeiling {
  maxUntil: Date;
  retentionCeiling: Date | null;
  retentionIso: string | null;
  isRetentionExpired: boolean;
  cappedByRetention: boolean;
  maxWholeDays: number;
  maxDurationDays: number;
}

export interface AccessDurationPresetOption {
  key: string;
  mode: 'DAYS' | 'UNTIL_RETENTION' | 'KEEP_GRANT';
  days?: number | undefined;
  untilIso?: string | undefined;
  label: string;
  isDefaultRecommended?: boolean | undefined;
}

export interface AccessDurationPlan {
  ceiling: EffectiveAccessCeiling;
  policyDefaultDays: number;
  recommendedDays: number;
  options: AccessDurationPresetOption[];
  defaultOptionKey: string;
}

/**
 * Algorithm / Thuật toán: Chuẩn hóa ngày lưu trữ (`Date` hoặc `YYYY-MM-DD`) sang chuỗi ISO `YYYY-MM-DD`.
 */
export function formatRetentionDateIso(
  retentionUntil: Date | string | null | undefined,
): string | null {
  if (!retentionUntil) return null;
  if (retentionUntil instanceof Date) {
    if (Number.isNaN(retentionUntil.getTime())) return null;
    return retentionUntil.toISOString().substring(0, 10);
  }
  const trimmed = String(retentionUntil).trim();
  if (!trimmed) return null;
  if (ISO_DATE_RE.test(trimmed)) return trimmed;
  const parsed = new Date(trimmed);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString().substring(0, 10);
}

/**
 * Algorithm / Thuật toán: Định dạng ngày lưu trữ ISO `YYYY-MM-DD` sang hiển thị tiếng Việt `DD/MM/YYYY`.
 */
export function formatRetentionDateVi(retentionUntil: Date | string | null | undefined): string {
  const iso = formatRetentionDateIso(retentionUntil);
  if (!iso) return '';
  const [year, month, day] = iso.split('-');
  return `${day}/${month}/${year}`;
}

/**
 * Algorithm / Thuật toán: Tính mốc trần cuối ngày UTC (`YYYY-MM-DDT23:59:59.999Z`) cho ngày `retention_until`.
 */
export function resolveRetentionCeilingUtc(
  retentionUntil: Date | string | null | undefined,
): Date | null {
  const iso = formatRetentionDateIso(retentionUntil);
  if (!iso) return null;
  const match = ISO_DATE_RE.exec(iso);
  if (!match) return null;
  return new Date(
    Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]), 23, 59, 59, 999),
  );
}

/**
 * Algorithm / Thuật toán: Tính mốc trần an toàn múi giờ cho trình duyệt (`min(local 23:59:59.999, UTC 23:59:59.999)`).
 * Bảo đảm ở mọi múi giờ (kể cả UTC+7 lẫn UTC-5), mốc tối đa trình duyệt cho phép không bao giờ vượt quá cuối ngày lịch địa phương cũng như cuối ngày UTC phía máy chủ.
 */
export function resolveRetentionCeilingSafeLocal(
  retentionUntil: Date | string | null | undefined,
): Date | null {
  const iso = formatRetentionDateIso(retentionUntil);
  if (!iso) return null;
  const match = ISO_DATE_RE.exec(iso);
  if (!match) return null;
  const year = Number(match[1]);
  const monthIdx = Number(match[2]) - 1;
  const day = Number(match[3]);
  const localEnd = new Date(year, monthIdx, day, 23, 59, 59, 999);
  const utcEnd = new Date(Date.UTC(year, monthIdx, day, 23, 59, 59, 999));
  return localEnd.getTime() <= utcEnd.getTime() ? localEnd : utcEnd;
}

/**
 * Algorithm / Thuật toán: Tính trần thời hạn truy cập hiệu lực kết hợp `GRANT_MAX_DURATION_DAYS` và `retention_until`.
 */
export function computeEffectiveAccessCeiling(params: {
  fromDate: Date;
  maxDurationDays?: number | undefined;
  retentionUntil?: Date | string | null | undefined;
  timezoneMode?: 'utc' | 'safe-local' | undefined;
}): EffectiveAccessCeiling {
  const maxDurationDays =
    typeof params.maxDurationDays === 'number' &&
    Number.isFinite(params.maxDurationDays) &&
    params.maxDurationDays >= 1
      ? Math.floor(params.maxDurationDays)
      : DEFAULT_GRANT_MAX_DURATION_DAYS;
  const durationCap = new Date(
    params.fromDate.getTime() + maxDurationDays * ACCESS_DURATION_DAY_MS,
  );
  const retentionIso = formatRetentionDateIso(params.retentionUntil);
  const retentionCeiling =
    params.timezoneMode === 'utc'
      ? resolveRetentionCeilingUtc(params.retentionUntil)
      : resolveRetentionCeilingSafeLocal(params.retentionUntil);

  if (!retentionCeiling) {
    return {
      maxUntil: durationCap,
      retentionCeiling: null,
      retentionIso: null,
      isRetentionExpired: false,
      cappedByRetention: false,
      maxWholeDays: maxDurationDays,
      maxDurationDays,
    };
  }

  const isRetentionExpired = retentionCeiling.getTime() <= params.fromDate.getTime();
  const cappedByRetention = retentionCeiling.getTime() < durationCap.getTime();
  const maxUntil = cappedByRetention ? retentionCeiling : durationCap;
  const maxWholeDays = isRetentionExpired
    ? 0
    : Math.min(
        maxDurationDays,
        Math.max(
          0,
          Math.floor((maxUntil.getTime() - params.fromDate.getTime()) / ACCESS_DURATION_DAY_MS),
        ),
      );

  return {
    maxUntil,
    retentionCeiling,
    retentionIso,
    isRetentionExpired,
    cappedByRetention,
    maxWholeDays,
    maxDurationDays,
  };
}

/**
 * Algorithm / Thuật toán: Tổng hợp danh sách nút chọn nhanh thời hạn hợp lệ và lựa chọn mặc định thông minh (`buildAccessDurationPresets`).
 * Cơ chế hoạt động:
 *   1. Tính trần `ceiling` từ `min(maxDurationDays, retention_until)` và thời hạn mặc định theo mức mật `default_view_days`.
 *   2. Loại bỏ toàn bộ các mốc vượt quá `ceiling.maxWholeDays`; khi tài liệu bị cắt trần bởi `retention_until`, bổ sung mốc chẵn sát trần hoặc `"Đến hết hạn"`.
 *   3. Khi người dùng xin nâng quyền tải (`UPGRADE_DOWNLOAD`) trên giấy phép đang hiệu lực, tự động thêm và chọn mặc định `"Giữ hạn hiện có"` tránh vô tình kéo dài hạn.
 */
export function buildAccessDurationPresets(params: {
  maxDurationDays?: number | undefined;
  retentionUntil?: string | null | undefined;
  defaultViewDays?: number | null | undefined;
  classificationCode?: string | null | undefined;
  existingGrantValidUntil?: string | null | undefined;
  intent?: 'NEW' | 'UPGRADE_DOWNLOAD' | 'RENEW' | undefined;
  now?: Date | undefined;
}): AccessDurationPlan {
  const now = params.now ?? new Date();
  const ceiling = computeEffectiveAccessCeiling({
    fromDate: now,
    maxDurationDays: params.maxDurationDays,
    retentionUntil: params.retentionUntil,
    timezoneMode: 'safe-local',
  });
  const policyDefaultDays = Math.min(
    ceiling.maxDurationDays,
    resolveClassificationDefaultViewDays(params.classificationCode, params.defaultViewDays),
  );

  if (ceiling.isRetentionExpired) {
    return {
      ceiling,
      policyDefaultDays,
      recommendedDays: 0,
      options: [],
      defaultOptionKey: '',
    };
  }

  const recommendedDays =
    ceiling.maxWholeDays > 0 ? Math.min(policyDefaultDays, ceiling.maxWholeDays) : 0;

  const candidateDays = new Set<number>();
  if (ceiling.maxWholeDays > 0) {
    const baseCandidates =
      ceiling.maxWholeDays <= 6 ? [1, 2, 3, ceiling.maxWholeDays] : [1, 3, 7, 14, 30];
    for (const d of baseCandidates) {
      if (d >= 1 && d <= ceiling.maxWholeDays) {
        candidateDays.add(d);
      }
    }
    if (recommendedDays >= 1 && recommendedDays <= ceiling.maxWholeDays) {
      candidateDays.add(recommendedDays);
    }
    if (ceiling.cappedByRetention && ceiling.maxWholeDays >= 1) {
      candidateDays.add(ceiling.maxWholeDays);
    }
  }

  const sortedDays = [...candidateDays].sort((a, b) => a - b);
  const options: AccessDurationPresetOption[] = [];

  const existingGrantMs = params.existingGrantValidUntil
    ? Date.parse(params.existingGrantValidUntil)
    : Number.NaN;
  const hasUsableExistingGrant =
    !Number.isNaN(existingGrantMs) &&
    existingGrantMs > now.getTime() + 60_000 &&
    existingGrantMs <= ceiling.maxUntil.getTime();

  if (hasUsableExistingGrant && params.existingGrantValidUntil) {
    options.push({
      key: 'KEEP_GRANT',
      mode: 'KEEP_GRANT',
      untilIso: new Date(existingGrantMs).toISOString(),
      label: 'Giữ hạn hiện có',
      isDefaultRecommended: params.intent === 'UPGRADE_DOWNLOAD',
    });
  }

  for (const days of sortedDays) {
    const isRecommended = params.intent !== 'UPGRADE_DOWNLOAD' && days === recommendedDays;
    options.push({
      key: `DAYS:${days}`,
      mode: 'DAYS',
      days,
      label: isRecommended ? `${days} ngày (mặc định)` : `${days} ngày`,
      isDefaultRecommended: isRecommended,
    });
  }

  const remainingMsBeyondWholeDays =
    ceiling.maxUntil.getTime() - (now.getTime() + ceiling.maxWholeDays * ACCESS_DURATION_DAY_MS);
  if (
    ceiling.cappedByRetention &&
    ceiling.retentionIso &&
    (ceiling.maxWholeDays === 0 || remainingMsBeyondWholeDays >= 3_600_000)
  ) {
    const shortDate = formatRetentionDateVi(ceiling.retentionIso).slice(0, 5);
    options.push({
      key: 'UNTIL_RETENTION',
      mode: 'UNTIL_RETENTION',
      untilIso: ceiling.maxUntil.toISOString(),
      label: ceiling.maxWholeDays === 0 ? `Đến hết hạn (${shortDate})` : `Hết hạn (${shortDate})`,
      isDefaultRecommended: ceiling.maxWholeDays === 0 && params.intent !== 'UPGRADE_DOWNLOAD',
    });
  }

  let defaultOptionKey = '';
  if (params.intent === 'UPGRADE_DOWNLOAD' && hasUsableExistingGrant) {
    defaultOptionKey = 'KEEP_GRANT';
  } else if (recommendedDays > 0) {
    defaultOptionKey = `DAYS:${recommendedDays}`;
  } else if (options.some((o) => o.key === 'UNTIL_RETENTION')) {
    defaultOptionKey = 'UNTIL_RETENTION';
  } else if (options[0]) {
    defaultOptionKey = options[0].key;
  }

  return {
    ceiling,
    policyDefaultDays,
    recommendedDays,
    options,
    defaultOptionKey,
  };
}
