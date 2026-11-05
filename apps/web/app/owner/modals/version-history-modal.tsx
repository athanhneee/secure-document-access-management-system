'use client';

import { RefreshCw } from 'lucide-react';
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
import type { DocumentItem, DocumentVersionItem } from '../types';

interface VersionHistoryModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  document: DocumentItem | null;
  versions: DocumentVersionItem[];
  isLoading: boolean;
  onOpenClassHistory: (doc: DocumentItem) => void;
}

export function VersionHistoryModal({
  open,
  onOpenChange,
  document,
  versions,
  isLoading,
  onOpenClassHistory,
}: VersionHistoryModalProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader className="flex flex-row items-center justify-between">
          <div>
            <DialogTitle className="text-base font-semibold text-[#222222]">
              Lịch sử các phiên bản: {document?.title}
            </DialogTitle>
            <DialogDescription className="text-xs text-[#717171]">
              Danh sách các tệp nguồn, băm SHA-256 và trạng thái quét virus từng phiên bản
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
              Đang tải lịch sử phiên bản...
            </div>
          ) : versions.length === 0 ? (
            <div className="text-center py-6 text-[#717171]">Không có dữ liệu phiên bản</div>
          ) : (
            <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
              {versions.map((v) => (
                <div
                  key={v.id}
                  className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-[#222222]">Phiên bản v{v.versionNo}.0</span>
                    <Badge
                      variant={v.scanStatus === 'CLEAN' ? 'success' : 'destructive'}
                      className="text-[13px]"
                    >
                      {v.scanStatus}
                    </Badge>
                  </div>
                  <div className="grid grid-cols-2 gap-1 text-xs text-[#717171]">
                    <div>
                      Tệp: <strong className="text-[#222222]">{v.originalFilename}</strong>
                    </div>
                    <div>Kích thước: {(Number(v.fileSizeBytes) / 1024).toFixed(1)} KB</div>
                    <div>Thời điểm: {new Date(v.createdAt).toLocaleString('vi-VN')}</div>
                    <div>Ghi chú: {v.changeNote || '—'}</div>
                  </div>
                  <div className="text-[13px] text-[#717171] font-mono truncate">
                    SHA-256: {v.sha256Hash}
                  </div>
                </div>
              ))}
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
