'use client';

import { CheckCircle2, RefreshCw } from 'lucide-react';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import { Badge } from '@/components/ui/badge';
import { formatSafeDateVi, formatScanStatusLabel } from '@/lib/ui-labels';
import type { DocumentItem, DocumentVersionItem } from '../types';

interface VersionHistoryModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  document: DocumentItem | null;
  versions: DocumentVersionItem[];
  isLoading: boolean;
  canSetCurrentVersion?: boolean | undefined;
  settingVersionNo?: number | null | undefined;
  onSetCurrentVersion?:
    ((doc: DocumentItem, versionNo: number) => Promise<void> | void) | undefined;
  onOpenClassHistory: (doc: DocumentItem) => void;
}

/**
 * Thuật toán: Ánh Xạ Màu Sắc Trạng Thái Quét Mã Độc Đúng Ngữ Nghĩa (`resolveScanBadgeVariant`, BUG-120)
 * `CLEAN` -> `'success'`, `PENDING` -> `'warning'` (cam `#E07912`), `INFECTED`/`FAILED` -> `'destructive'` (đỏ `#C13515`).
 */
function resolveScanBadgeVariant(scanStatus: string) {
  const normalized = scanStatus.trim().toUpperCase();
  if (normalized === 'CLEAN') return 'success' as const;
  if (normalized === 'PENDING') return 'warning' as const;
  return 'destructive' as const;
}

export function VersionHistoryModal({
  open,
  onOpenChange,
  document,
  versions,
  isLoading,
  canSetCurrentVersion = false,
  settingVersionNo = null,
  onSetCurrentVersion,
  onOpenClassHistory,
}: VersionHistoryModalProps) {
  const isBusySetting = settingVersionNo !== null;
  return (
    <Dialog open={open} onOpenChange={(next) => !isBusySetting && onOpenChange(next)}>
      <DialogContent
        showClose={!isBusySetting}
        className="max-w-2xl border-[#ebebeb] bg-[#ffffff] text-[#222222]"
      >
        <DialogHeader className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 pr-12">
          <div>
            <DialogTitle className="text-base font-semibold text-[#222222]">
              Lịch sử phiên bản: {document?.title}
            </DialogTitle>
            <DialogDescription className="text-xs text-[#717171]">
              Danh sách các phiên bản tệp đã tải lên và kết quả kiểm tra an toàn mã độc.
            </DialogDescription>
          </div>
          <InteractiveHoverButton
            variant="ghost"
            size="sm"
            text="Xem lịch sử phân loại"
            onClick={() => {
              onOpenChange(false);
              if (document) {
                onOpenClassHistory(document);
              }
            }}
          />
        </DialogHeader>

        <div className="py-2 text-xs">
          {isLoading ? (
            <div className="text-center py-6 text-[#717171]">
              <RefreshCw
                size={20}
                strokeWidth={1.75}
                className="animate-spin mx-auto mb-2 text-[#FF385C]"
                aria-hidden="true"
              />
              Đang tải lịch sử phiên bản…
            </div>
          ) : versions.length === 0 ? (
            <div className="text-center py-6 text-[#717171]">Không có dữ liệu phiên bản.</div>
          ) : (
            <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
              {versions.map((v) => {
                const isCurrentVersion = document?.currentVersionNo === v.versionNo;
                const isCleanVersion = v.scanStatus.trim().toUpperCase() === 'CLEAN';
                const canPromoteVersion =
                  Boolean(canSetCurrentVersion) &&
                  Boolean(onSetCurrentVersion) &&
                  Boolean(document) &&
                  document?.status !== 'ARCHIVED' &&
                  isCleanVersion &&
                  !isCurrentVersion;
                const isSettingThis = settingVersionNo === v.versionNo;

                return (
                  <div
                    key={v.id}
                    className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-2"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-bold text-[#222222]">Phiên bản {v.versionNo}</span>
                        {isCurrentVersion && <Badge variant="success">Hiện hành</Badge>}
                      </div>
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge variant={resolveScanBadgeVariant(v.scanStatus)}>
                          {formatScanStatusLabel(v.scanStatus)}
                        </Badge>
                        {canPromoteVersion && document && onSetCurrentVersion && (
                          <InteractiveHoverButton
                            type="button"
                            variant="secondary"
                            size="sm"
                            text={isSettingThis ? 'Đang cập nhật…' : 'Đặt làm hiện hành'}
                            icon={<CheckCircle2 size={16} strokeWidth={1.75} aria-hidden="true" />}
                            isLoading={isSettingThis}
                            disabled={isBusySetting}
                            onClick={() => onSetCurrentVersion(document, v.versionNo)}
                          />
                        )}
                      </div>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-1 text-xs text-[#717171]">
                      <div className="min-w-0">
                        Tệp:{' '}
                        <strong className="text-[#222222] break-all">{v.originalFilename}</strong>
                      </div>
                      <div>Kích thước: {(Number(v.fileSizeBytes) / 1024).toFixed(1)} KB</div>
                      <div>Thời điểm: {formatSafeDateVi(v.createdAt, { includeTime: true })}</div>
                      <div className="break-words">Ghi chú: {v.changeNote || '—'}</div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <DialogFooter>
          <InteractiveHoverButton
            variant="secondary"
            size="sm"
            text="Đóng"
            onClick={() => onOpenChange(false)}
          />
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
