import {
  ACCESS_DURATION_DAY_MS,
  DEFAULT_GRANT_MAX_DURATION_DAYS,
  formatRetentionDateVi,
  resolveRetentionCeilingSafeLocal,
} from '@sda/contracts';
import type { DocumentItem, UserLookupItem } from './types';

export const GRANT_MAX_DURATION_DAYS = DEFAULT_GRANT_MAX_DURATION_DAYS;
const DAY_MS = ACCESS_DURATION_DAY_MS;

function formatLocalDateTimeInput(d: Date): string {
  const pad = (n: number) => n.toString().padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/**
 * Thuật toán: Lọc Danh Sách Tài Liệu Đủ Điều Kiện Cấp Quyền Trực Tiếp (`filterGrantableDocuments`)
 * Mục đích: Chỉ giữ lại tài liệu đang ở trạng thái `ACTIVE` (loại bỏ `DRAFT` và `ARCHIVED`) khớp chặt tiền điều kiện máy chủ.
 */
export function filterGrantableDocuments(documents: ReadonlyArray<DocumentItem>): DocumentItem[] {
  return documents.filter((doc) => doc.status === 'ACTIVE');
}

/**
 * Thuật toán: Lọc Danh Sách Người Nhận Quyền Hợp Lệ Loại Trừ Chính Chủ Sở Hữu (`filterGrantEligibleUsers`)
 * Mục đích: Phòng thủ chiều sâu phía giao diện loại bỏ tài khoản chủ sở hữu hiện tại khỏi danh sách cấp quyền trực tiếp.
 */
export function filterGrantEligibleUsers(
  users: ReadonlyArray<UserLookupItem>,
  currentUserId?: string | number | null,
): UserLookupItem[] {
  if (
    currentUserId === null ||
    currentUserId === undefined ||
    String(currentUserId).trim() === ''
  ) {
    return [...users];
  }
  const normalizedSelf = String(currentUserId).trim();
  return users.filter((u) => String(u.id).trim() !== normalizedSelf);
}

/**
 * Thuật toán: Nhận Diện Cấp Thẩm Quyền Bảo Mật Bị Ẩn Theo Phạm Vi Phòng Ban (`isUserClearanceRedacted`)
 */
export function isUserClearanceRedacted(
  user?: Pick<UserLookupItem, 'clearanceCode'> | null,
): boolean {
  return (user?.clearanceCode ?? '').trim().toUpperCase() === 'REDACTED';
}

/**
 * Thuật toán: Định Dạng Nhãn Tùy Chọn Người Dùng An Toàn Cho Độ Mật Bị Che (`formatUserLookupOptionLabel`)
 * Mục đích: Hiển thị `"Độ mật ẩn"` thay vì `"Cấp 0"` khi máy chủ che giấu cấp thẩm quyền (`REDACTED`) của nhân sự ngoài phòng ban.
 */
export function formatUserLookupOptionLabel(user: UserLookupItem): string {
  const deptLabel = user.departmentName?.trim() || 'Chưa phân phòng ban';
  const clearanceLabel = isUserClearanceRedacted(user) ? 'Độ mật ẩn' : `Cấp ${user.clearanceRank}`;
  return `${user.fullName} (${user.username}) · ${deptLabel} · ${clearanceLabel}`;
}

/**
 * Thuật toán: Kiểm Định Cảnh Báo Thống Trị Độ Mật Bell-LaPadula Không Báo Giả Khi Bị Che (`shouldWarnGrantClearance`)
 * Mục đích: Chỉ cảnh báo/chặn khi biết chắc `clearanceRank` (không phải `REDACTED`) và `clearanceRank < documentRank`.
 */
export function shouldWarnGrantClearance(params: {
  principalType: 'USER' | 'ROLE';
  document?: Pick<DocumentItem, 'classificationRank'> | null | undefined;
  user?: Pick<UserLookupItem, 'clearanceRank' | 'clearanceCode'> | null | undefined;
}): boolean {
  const { principalType, document, user } = params;
  if (principalType !== 'USER' || !document || !user) return false;
  if (isUserClearanceRedacted(user)) return false;
  return user.clearanceRank < (document.classificationRank ?? 0);
}

/**
 * Thuật toán: Chuẩn Hóa Nhãn Quyền Hạn Đơn Nhất Cho Bảng Quyền Truy Cập (`formatGrantPermissionSummary`)
 * Mục đích: Gộp tập quyền `['VIEW', 'DOWNLOAD']` thành một nhãn duy nhất `"Xem & Tải về"` để tránh hiển thị mâu thuẫn kép `"Chỉ xem"` + `"Xem & Tải về"`.
 */
export function formatGrantPermissionSummary(permissions: ReadonlyArray<string>): {
  label: string;
  includesDownload: boolean;
} {
  const normalized = permissions.map((p) => p.trim().toUpperCase());
  if (normalized.includes('DOWNLOAD')) {
    return { label: 'Xem & Tải về', includesDownload: true };
  }
  return { label: 'Chỉ xem', includesDownload: false };
}

/**
 * Thuật toán: Kiểm Định Khoảng Thời Hạn Cấp Quyền Trực Tiếp Phía Giao Diện (`validateDirectGrantTimeRange`)
 * Mục đích: Bảo đảm `validUntil > validFrom`, `validUntil > now` (không tạo quyền đã hết hạn trong quá khứ),
 * tổng thời lượng không vượt quá trần `maxDurationDays` (mặc định 30 ngày) và không vượt quá ngày lưu trữ bảo mật `retentionUntil` của tài liệu.
 */
export function validateDirectGrantTimeRange(
  validFrom: string,
  validUntil: string,
  options?: {
    now?: Date | undefined;
    maxDurationDays?: number | undefined;
    retentionUntil?: string | null | undefined;
  },
): string | null {
  if (!validFrom || !validUntil) {
    return 'Vui lòng nhập đầy đủ thời điểm bắt đầu và kết thúc hiệu lực.';
  }
  const fromDate = new Date(validFrom);
  const untilDate = new Date(validUntil);
  if (Number.isNaN(fromDate.getTime()) || Number.isNaN(untilDate.getTime())) {
    return 'Khoảng thời gian hiệu lực không hợp lệ.';
  }
  if (untilDate <= fromDate) {
    return 'Thời điểm kết thúc phải sau thời điểm bắt đầu.';
  }
  const now = options?.now ?? new Date();
  if (untilDate <= now) {
    return 'Thời điểm kết thúc phải nằm sau thời điểm hiện tại.';
  }
  const maxDays = options?.maxDurationDays ?? GRANT_MAX_DURATION_DAYS;
  if (untilDate.getTime() - fromDate.getTime() > maxDays * DAY_MS) {
    return `Thời hạn cấp quyền tối đa là ${maxDays} ngày. Vui lòng rút ngắn khoảng hiệu lực.`;
  }
  const retentionCeiling = resolveRetentionCeilingSafeLocal(options?.retentionUntil);
  if (retentionCeiling) {
    const retentionLabel = formatRetentionDateVi(options?.retentionUntil);
    if (retentionCeiling.getTime() <= now.getTime()) {
      return `Tài liệu đã quá thời hạn lưu trữ bảo mật (${retentionLabel}) nên không thể cấp quyền mới.`;
    }
    if (untilDate.getTime() > retentionCeiling.getTime()) {
      return `Thời điểm kết thúc không được vượt quá thời hạn lưu trữ bảo mật của tài liệu (${retentionLabel}).`;
    }
  }
  return null;
}

/**
 * Thuật toán: Tính Mốc Thời Điểm Kết Thúc Tối Đa Cho Ô `datetime-local` Có Cắt Trần Theo `retentionUntil` (`computeMaxGrantValidUntilLocal`)
 */
export function computeMaxGrantValidUntilLocal(
  validFrom: string,
  maxDurationDays: number = GRANT_MAX_DURATION_DAYS,
  retentionUntil?: string | null,
): string | undefined {
  const parsed = new Date(validFrom);
  if (Number.isNaN(parsed.getTime())) return undefined;
  const durationMax = new Date(parsed.getTime() + maxDurationDays * DAY_MS);
  const retentionCeiling = resolveRetentionCeilingSafeLocal(retentionUntil);
  const effectiveMax =
    retentionCeiling && retentionCeiling.getTime() < durationMax.getTime()
      ? retentionCeiling
      : durationMax;
  return formatLocalDateTimeInput(effectiveMax);
}
