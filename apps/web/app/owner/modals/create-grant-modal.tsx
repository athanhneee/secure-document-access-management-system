'use client';

import { AlertTriangle, Download, Eye, KeyRound, Lock } from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import {
  computeMaxGrantValidUntilLocal,
  formatUserLookupOptionLabel,
  GRANT_MAX_DURATION_DAYS,
  shouldWarnGrantClearance,
  validateDirectGrantTimeRange,
} from '../grant-helpers';
import { toLocalISO } from '../helpers';
import type { useOwnerGrants } from '../hooks/use-owner-grants';
import type { RoleLookupItem } from '../types';

interface CreateGrantModalProps {
  grantsControl: ReturnType<typeof useOwnerGrants>;
  rolesLookup: RoleLookupItem[];
}

/**
 * Thuật toán: Hộp Thoại Cấp Quyền Truy Cập Trực Tiếp Có Ràng Buộc Bảo Mật Chủ Động (`CreateGrantModal`)
 * Mục đích:
 *   - Chỉ cho phép chọn tài liệu `ACTIVE` và danh sách người dùng hợp lệ (không gồm chính chủ sở hữu và tài khoản SoD).
 *   - Tự động khóa tùy chọn `Xem & Tải về` khi mức độ mật của tài liệu cấm tải xuống (`allowDownload === false`).
 *   - Kiểm định thống trị độ mật Bell-LaPadula (bỏ qua báo giả với `REDACTED`), trần thời hạn 30 ngày và mốc tương lai ngay trước khi gửi.
 */
export function CreateGrantModal({ grantsControl, rolesLookup }: CreateGrantModalProps) {
  const {
    grantableDocuments,
    eligibleUsers,
    directGrantOpen,
    setDirectGrantOpen,
    directDocId,
    setDirectDocId,
    directPrincipalType,
    setDirectPrincipalType,
    directUserId,
    setDirectUserId,
    directRoleId,
    setDirectRoleId,
    directPermissionMode,
    setDirectPermissionMode,
    directValidFrom,
    setDirectValidFrom,
    directValidUntil,
    setDirectValidUntil,
    isSubmittingDirectGrant,
    handleCreateDirectGrant,
  } = grantsControl;

  const selectedDirectDoc = grantableDocuments.find((d) => d.id === directDocId);
  const selectedDirectUser = eligibleUsers.find((u) => u.id === directUserId);
  const canDownloadSelectedDoc = selectedDirectDoc?.allowDownload ?? false;
  const effectivePermissionMode =
    !canDownloadSelectedDoc && directPermissionMode === 'DOWNLOAD' ? 'VIEW' : directPermissionMode;

  const isClearanceWarning = shouldWarnGrantClearance({
    principalType: directPrincipalType,
    document: selectedDirectDoc,
    user: selectedDirectUser,
  });

  const timeRangeError = validateDirectGrantTimeRange(directValidFrom, directValidUntil, {
    maxDurationDays: GRANT_MAX_DURATION_DAYS,
  });

  const nowLocalIso = toLocalISO(new Date());
  const minValidUntil =
    directValidFrom && directValidFrom > nowLocalIso ? directValidFrom : nowLocalIso;
  const maxValidUntil = computeMaxGrantValidUntilLocal(directValidFrom, GRANT_MAX_DURATION_DAYS);

  const hasValidPrincipal =
    directPrincipalType === 'USER'
      ? Boolean(selectedDirectUser)
      : rolesLookup.some((r) => r.id === directRoleId);

  const isSubmitBlocked =
    isSubmittingDirectGrant ||
    !selectedDirectDoc ||
    !hasValidPrincipal ||
    isClearanceWarning ||
    Boolean(timeRangeError);

  return (
    <Dialog open={directGrantOpen} onOpenChange={setDirectGrantOpen}>
      <DialogContent className="max-w-lg border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <div className="flex items-center gap-2">
            <KeyRound size={20} strokeWidth={1.75} className="text-[#FF385C]" aria-hidden="true" />
            <DialogTitle className="text-base font-semibold text-[#222222]">
              Cấp quyền truy cập trực tiếp
            </DialogTitle>
          </div>
          <DialogDescription className="text-xs text-[#717171]">
            Cấp quyền xem hoặc tải về có thời hạn (tối đa {GRANT_MAX_DURATION_DAYS} ngày) cho người
            dùng hoặc vai trò đủ thẩm quyền.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleCreateDirectGrant} className="space-y-3.5 py-2 text-xs">
          <div className="space-y-1">
            <label htmlFor="direct-doc" className="font-medium text-[#222222]">
              Chọn tài liệu cấp quyền <span className="text-[#C13515]">*</span>
            </label>
            <select
              id="direct-doc"
              value={directDocId}
              disabled={grantableDocuments.length === 0}
              onChange={(e) => setDirectDocId(e.target.value)}
              className="w-full min-h-11 sm:h-9 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer disabled:bg-[#f7f7f7] disabled:text-[#717171] disabled:cursor-not-allowed"
            >
              {grantableDocuments.length === 0 ? (
                <option value="">Chưa có tài liệu đang hiệu lực để cấp quyền</option>
              ) : (
                grantableDocuments.map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.title} (Cấp {d.classificationRank ?? 0})
                  </option>
                ))
              )}
            </select>
          </div>

          <fieldset className="space-y-1 border-0 p-0 m-0 min-w-0">
            <legend className="font-medium text-[#222222] block mb-1">
              Loại đối tượng được cấp
            </legend>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {(['USER', 'ROLE'] as const).map((pType) => (
                <button
                  key={pType}
                  type="button"
                  aria-pressed={directPrincipalType === pType}
                  onClick={() => setDirectPrincipalType(pType)}
                  className={`min-h-11 sm:min-h-9 py-2 px-3 rounded-full border text-xs font-semibold cursor-pointer transition-colors ${
                    directPrincipalType === pType
                      ? 'border-[#FF385C] bg-[#FF385C] text-[#ffffff]'
                      : 'border-[#dddddd] bg-[#ffffff] text-[#222222] hover:border-[#222222]'
                  }`}
                >
                  {pType === 'USER' ? 'Người dùng' : 'Vai trò'}
                </button>
              ))}
            </div>
          </fieldset>

          {directPrincipalType === 'USER' ? (
            <div className="space-y-1">
              <label htmlFor="direct-user" className="font-medium text-[#222222]">
                Chọn người dùng <span className="text-[#C13515]">*</span>
              </label>
              <select
                id="direct-user"
                value={directUserId}
                disabled={eligibleUsers.length === 0}
                onChange={(e) => setDirectUserId(e.target.value)}
                className="w-full min-h-11 sm:h-9 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer disabled:bg-[#f7f7f7] disabled:text-[#717171] disabled:cursor-not-allowed"
              >
                {eligibleUsers.length === 0 ? (
                  <option value="">Không có người dùng đủ điều kiện nhận quyền</option>
                ) : (
                  eligibleUsers.map((u) => (
                    <option key={u.id} value={u.id}>
                      {formatUserLookupOptionLabel(u)}
                    </option>
                  ))
                )}
              </select>
            </div>
          ) : (
            <div className="space-y-1">
              <label htmlFor="direct-role" className="font-medium text-[#222222]">
                Chọn vai trò <span className="text-[#C13515]">*</span>
              </label>
              <select
                id="direct-role"
                value={directRoleId}
                disabled={rolesLookup.length === 0}
                onChange={(e) => setDirectRoleId(e.target.value)}
                className="w-full min-h-11 sm:h-9 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer disabled:bg-[#f7f7f7] disabled:text-[#717171] disabled:cursor-not-allowed"
              >
                {rolesLookup.length === 0 ? (
                  <option value="">Không có vai trò phù hợp để cấp quyền</option>
                ) : (
                  rolesLookup.map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.name}
                    </option>
                  ))
                )}
              </select>
            </div>
          )}

          {isClearanceWarning && (
            <div
              role="alert"
              className="rounded-[20px] border border-[#C13515]/30 bg-[#C13515]/5 p-3 text-xs text-[#C13515] space-y-1"
            >
              <div className="flex items-center gap-1.5 font-bold">
                <AlertTriangle size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>Không đủ cấp thẩm quyền bảo mật</span>
              </div>
              <div>
                Người dùng {selectedDirectUser?.fullName} đang có cấp thẩm quyền Cấp{' '}
                {selectedDirectUser?.clearanceRank}, thấp hơn mức độ mật của tài liệu (Cấp{' '}
                {selectedDirectDoc?.classificationRank}). Hệ thống chặn cấp quyền theo nguyên tắc
                Bell-LaPadula.
              </div>
            </div>
          )}

          <fieldset className="space-y-1.5 border-0 p-0 m-0 min-w-0">
            <legend className="font-medium text-[#222222] block mb-1">Quyền được cấp</legend>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <button
                type="button"
                aria-pressed={effectivePermissionMode === 'VIEW'}
                onClick={() => setDirectPermissionMode('VIEW')}
                className={`min-h-11 sm:min-h-9 flex items-center justify-center gap-1.5 px-3 py-2 rounded-full border text-xs font-semibold cursor-pointer transition-colors ${
                  effectivePermissionMode === 'VIEW'
                    ? 'border-[#FF385C] bg-[#FF385C] text-[#ffffff]'
                    : 'border-[#dddddd] bg-[#ffffff] text-[#222222] hover:border-[#222222]'
                }`}
              >
                <Eye size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>Chỉ xem trực tuyến</span>
              </button>
              <button
                type="button"
                aria-pressed={effectivePermissionMode === 'DOWNLOAD'}
                disabled={!canDownloadSelectedDoc}
                onClick={() => {
                  if (canDownloadSelectedDoc) setDirectPermissionMode('DOWNLOAD');
                }}
                className={`min-h-11 sm:min-h-9 flex items-center justify-center gap-1.5 px-3 py-2 rounded-full border text-xs font-semibold transition-colors ${
                  !canDownloadSelectedDoc
                    ? 'border-[#ebebeb] bg-[#f7f7f7] text-[#b0b0b0] cursor-not-allowed'
                    : effectivePermissionMode === 'DOWNLOAD'
                      ? 'border-[#FF385C] bg-[#FF385C] text-[#ffffff] cursor-pointer'
                      : 'border-[#dddddd] bg-[#ffffff] text-[#222222] hover:border-[#222222] cursor-pointer'
                }`}
              >
                <Download size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>Xem &amp; Tải về có watermark</span>
              </button>
            </div>
            {selectedDirectDoc && !canDownloadSelectedDoc && (
              <p className="flex items-center gap-1.5 text-xs text-[#717171] pt-0.5">
                <Lock size={16} strokeWidth={1.75} className="shrink-0" aria-hidden="true" />
                <span>
                  Tài liệu Cấp {selectedDirectDoc.classificationRank ?? 0} không cho phép tải về
                  (chỉ cấp quyền xem trực tuyến).
                </span>
              </p>
            )}
          </fieldset>

          <div className="space-y-1.5">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="space-y-1">
                <label htmlFor="valid-from" className="font-medium text-[#222222]">
                  Thời điểm bắt đầu
                </label>
                <Input
                  id="valid-from"
                  type="datetime-local"
                  value={directValidFrom}
                  onChange={(e) => setDirectValidFrom(e.target.value)}
                  className="min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd]"
                />
              </div>
              <div className="space-y-1">
                <label htmlFor="valid-until" className="font-medium text-[#222222]">
                  Thời điểm kết thúc
                </label>
                <Input
                  id="valid-until"
                  type="datetime-local"
                  value={directValidUntil}
                  min={minValidUntil}
                  max={maxValidUntil}
                  onChange={(e) => setDirectValidUntil(e.target.value)}
                  className="min-h-11 sm:h-9 text-xs rounded-full bg-[#ffffff] border-[#dddddd]"
                />
              </div>
            </div>
            {timeRangeError ? (
              <p role="alert" className="text-xs font-medium text-[#C13515]">
                {timeRangeError}
              </p>
            ) : (
              <p className="text-xs text-[#717171]">
                Thời hạn hiệu lực tối đa {GRANT_MAX_DURATION_DAYS} ngày và thời điểm kết thúc phải ở
                tương lai.
              </p>
            )}
          </div>

          <DialogFooter className="pt-2">
            <InteractiveHoverButton
              type="button"
              variant="ghost"
              size="sm"
              text="Hủy"
              onClick={() => setDirectGrantOpen(false)}
            />
            <InteractiveHoverButton
              type="submit"
              variant="primary"
              size="sm"
              text={isSubmittingDirectGrant ? 'Đang cấp quyền…' : 'Xác nhận cấp quyền'}
              disabled={isSubmitBlocked}
              isLoading={isSubmittingDirectGrant}
            />
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
