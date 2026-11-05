'use client';

import { KeyRound, AlertTriangle } from 'lucide-react';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Input } from '@/components/ui/input';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import type { useOwnerGrants } from '../hooks/use-owner-grants';
import type { DocumentItem, RoleLookupItem, UserLookupItem } from '../types';

interface CreateGrantModalProps {
  grantsControl: ReturnType<typeof useOwnerGrants>;
  documents: DocumentItem[];
  usersLookup: UserLookupItem[];
  rolesLookup: RoleLookupItem[];
}

export function CreateGrantModal({
  grantsControl,
  documents,
  usersLookup,
  rolesLookup,
}: CreateGrantModalProps) {
  const {
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
    directPermissions,
    setDirectPermissions,
    directValidFrom,
    setDirectValidFrom,
    directValidUntil,
    setDirectValidUntil,
    isSubmittingDirectGrant,
    handleCreateDirectGrant,
  } = grantsControl;

  // Thuật toán: Kiểm tra Thống trị Độ mật Bell-LaPadula Phía Giao diện (Simple Security Property — No Read Up: clearanceRank >= classificationRank)
  const selectedDirectDoc = documents.find((d) => d.id === directDocId);
  const selectedDirectUser = usersLookup.find((u) => u.id === directUserId);
  const isClearanceWarning =
    directPrincipalType === 'USER' &&
    selectedDirectDoc &&
    selectedDirectUser &&
    selectedDirectUser.clearanceRank < (selectedDirectDoc.classificationRank ?? 0);

  return (
    <Dialog open={directGrantOpen} onOpenChange={setDirectGrantOpen}>
      <DialogContent className="max-w-lg border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <div className="flex items-center gap-2">
            <KeyRound size={20} strokeWidth={1.75} className="text-[#FF385C]" aria-hidden="true" />
            <DialogTitle className="text-base font-semibold text-[#222222]">
              Cấp quyền truy cập trực tiếp (Direct Grant)
            </DialogTitle>
          </div>
          <DialogDescription className="text-xs text-[#717171]">
            Chủ sở hữu cấp quyền đọc/tải có thời hạn cho Người dùng hoặc Vai trò cụ thể
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
              onChange={(e) => setDirectDocId(e.target.value)}
              className="w-full h-8 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
            >
              {documents.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.title} ({d.classificationCode})
                </option>
              ))}
            </select>
          </div>

          <fieldset className="space-y-1 border-0 p-0 m-0 min-w-0">
            <legend className="font-medium text-[#222222] block mb-1">
              Loại đối tượng được cấp:
            </legend>
            <div className="grid grid-cols-2 gap-2">
              {(['USER', 'ROLE'] as const).map((pType) => (
                <button
                  key={pType}
                  type="button"
                  aria-pressed={directPrincipalType === pType}
                  onClick={() => setDirectPrincipalType(pType)}
                  className={`py-2 px-3 rounded-full border text-xs font-semibold cursor-pointer ${
                    directPrincipalType === pType
                      ? 'border-[#FF385C] bg-[#FF385C] text-white'
                      : 'border-[#dddddd] bg-white text-[#222222]'
                  }`}
                >
                  {pType === 'USER' ? 'Người dùng (USER)' : 'Vai trò (ROLE)'}
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
                onChange={(e) => setDirectUserId(e.target.value)}
                className="w-full h-8 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
              >
                {usersLookup.map((u) => (
                  <option key={u.id} value={u.id}>
                    {u.fullName} ({u.username}) · {u.departmentName} · Cấp mật Rank{' '}
                    {u.clearanceRank}
                  </option>
                ))}
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
                onChange={(e) => setDirectRoleId(e.target.value)}
                className="w-full h-8 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer"
              >
                {rolesLookup.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.name} ({r.code})
                  </option>
                ))}
              </select>
            </div>
          )}

          {isClearanceWarning && (
            <div className="rounded-[20px] border border-[#C13515]/30 bg-[#C13515]/5 p-3 text-[11px] text-[#C13515] space-y-1">
              <div className="flex items-center gap-1.5 font-bold">
                <AlertTriangle size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>Cảnh báo Clearance (D-BR04):</span>
              </div>
              <div>
                Người dùng {selectedDirectUser?.fullName} có bậc Clearance Rank{' '}
                {selectedDirectUser?.clearanceRank}, thấp hơn mức mật của tài liệu (Rank{' '}
                {selectedDirectDoc?.classificationRank}). Hệ thống ABAC sẽ từ chối cấp quyền hoặc
                người dùng không thể giải mã tài liệu!
              </div>
            </div>
          )}

          <div className="space-y-1">
            <span className="font-medium text-[#222222] block">Quyền hạn cấp:</span>
            <div className="flex gap-4">
              {(['VIEW', 'DOWNLOAD'] as const).map((perm) => {
                const checkboxId = `direct-perm-${perm.toLowerCase()}`;
                return (
                  <label
                    key={perm}
                    htmlFor={checkboxId}
                    className="flex items-center gap-2 cursor-pointer"
                  >
                    <input
                      id={checkboxId}
                      type="checkbox"
                      checked={directPermissions.includes(perm)}
                      onChange={(e) => {
                        setDirectPermissions((prev) =>
                          e.target.checked
                            ? Array.from(new Set([...prev, perm]))
                            : prev.filter((p) => p !== perm),
                        );
                      }}
                      className="rounded border-[#dddddd] text-[#FF385C] focus:ring-[#FF385C]"
                    />
                    <span>
                      {perm === 'VIEW'
                        ? 'Chỉ xem trực tuyến (VIEW)'
                        : 'Tải về có Watermark (DOWNLOAD)'}
                    </span>
                  </label>
                );
              })}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <label htmlFor="valid-from" className="font-medium text-[#222222]">
                Thời điểm bắt đầu:
              </label>
              <Input
                id="valid-from"
                type="datetime-local"
                value={directValidFrom}
                onChange={(e) => setDirectValidFrom(e.target.value)}
                className="h-8 text-xs rounded-full bg-white border-[#dddddd]"
              />
            </div>
            <div className="space-y-1">
              <label htmlFor="valid-until" className="font-medium text-[#222222]">
                Thời điểm kết thúc:
              </label>
              <Input
                id="valid-until"
                type="datetime-local"
                value={directValidUntil}
                onChange={(e) => setDirectValidUntil(e.target.value)}
                className="h-8 text-xs rounded-full bg-white border-[#dddddd]"
              />
            </div>
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
              text={isSubmittingDirectGrant ? 'Đang cấp...' : 'Xác nhận cấp quyền'}
              disabled={isSubmittingDirectGrant}
              isLoading={isSubmittingDirectGrant}
            />
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
