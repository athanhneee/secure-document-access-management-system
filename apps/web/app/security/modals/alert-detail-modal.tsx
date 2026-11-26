'use client';

import { useEffect, useState } from 'react';
import { Check, FilePlus2 } from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import { useAuth } from '@/lib/auth-context';
import { formatAlertStatusLabel, formatDetectionRuleLabel } from '@/lib/ui-labels';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { Select } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { mapAlertDto } from '../helpers';
import type { OptimisticAlertPatch } from '../hooks/use-security-data';
import type { AlertApiDto, AlertNoteItem, IncidentDraftPrefill, SecurityAlertItem } from '../types';
import { AlertNotesHistory } from './alert-notes-history';
import { STATUS_LABELS, VALID_TRANSITIONS } from './alert-status-config';

interface AlertDetailModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  alert: SecurityAlertItem | null;
  canManageAlerts?: boolean | undefined;
  canCreateIncident?: boolean | undefined;
  onCreateIncidentFromAlert?: ((prefill: IncidentDraftPrefill) => void) | undefined;
  onClearError: () => void;
  onOptimisticUpdate?: ((alertId: string, patch: OptimisticAlertPatch) => () => void) | undefined;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

export function AlertDetailModal({
  open,
  onOpenChange,
  alert,
  canManageAlerts = true,
  canCreateIncident = false,
  onCreateIncidentFromAlert,
  onClearError,
  onOptimisticUpdate,
  onSuccess,
  onError,
}: AlertDetailModalProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg max-h-[88vh] overflow-y-auto border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        <DialogHeader>
          <DialogTitle className="text-base font-semibold text-[#222222]">
            Chi tiết cảnh báo an ninh
          </DialogTitle>
          <DialogDescription className="text-xs text-[#717171]">
            Xem bằng chứng kỹ thuật, cập nhật trạng thái điều tra và ghi nhận kết quả rà soát nội
            bộ.
          </DialogDescription>
        </DialogHeader>

        {open && alert ? (
          <AlertDetailForm
            key={alert.id}
            alert={alert}
            canManageAlerts={canManageAlerts}
            canCreateIncident={canCreateIncident}
            onCreateIncidentFromAlert={onCreateIncidentFromAlert}
            onClose={() => onOpenChange(false)}
            onClearError={onClearError}
            onOptimisticUpdate={onOptimisticUpdate}
            onSuccess={onSuccess}
            onError={onError}
          />
        ) : (
          <div className="space-y-3 py-2 text-xs">
            <p className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-4 text-center text-[#717171]">
              Không tìm thấy dữ liệu cảnh báo hiện tại. Bạn có thể đóng hộp thoại và làm mới danh
              sách.
            </p>
            <DialogFooter className="pt-1">
              <InteractiveHoverButton
                type="button"
                variant="secondary"
                size="sm"
                text="Đóng"
                onClick={() => onOpenChange(false)}
              />
            </DialogFooter>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

interface AlertDetailFormProps {
  alert: SecurityAlertItem;
  canManageAlerts: boolean;
  canCreateIncident: boolean;
  onCreateIncidentFromAlert?: ((prefill: IncidentDraftPrefill) => void) | undefined;
  onClose: () => void;
  onClearError: () => void;
  onOptimisticUpdate?: ((alertId: string, patch: OptimisticAlertPatch) => () => void) | undefined;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

/**
 * Thuật toán: Cập Nhật Nguyên Tử Trạng Thái Cảnh Báo & Ghi Chú Điều Tra Kèm Nạp Bằng Chứng Audit (`AlertDetailForm`)
 * Mục đích:
 *   - Nạp chi tiết `GET /security-alerts/:id` để hiển thị đầy đủ `description`, `notes[]`, `ipAddress` và `linkedAuditLogs` (#01, #02, #03).
 *   - Gửi gộp `investigationNote` trong một lệnh `PATCH /status` nguyên tử khi đổi trạng thái kèm ghi chú (#09).
 */
function AlertDetailForm({
  alert,
  canManageAlerts,
  canCreateIncident,
  onCreateIncidentFromAlert,
  onClose,
  onClearError,
  onOptimisticUpdate,
  onSuccess,
  onError,
}: AlertDetailFormProps) {
  const { user: currentUser } = useAuth();
  const [fullAlert, setFullAlert] = useState<SecurityAlertItem>(alert);
  const [newStatus, setNewStatus] = useState<SecurityAlertItem['status']>(alert.status);
  const [resolutionNote, setResolutionNote] = useState('');
  const [investigationNote, setInvestigationNote] = useState('');
  const [isUpdatingAlert, setIsUpdatingAlert] = useState(false);

  useEffect(() => {
    let cancelled = false;
    apiClient<AlertApiDto>(`/security-alerts/${alert.id}`)
      .then((dto) => {
        if (!cancelled) {
          const mapped = mapAlertDto(dto);
          setFullAlert(mapped);
          setNewStatus(mapped.status);
        }
      })
      .catch(() => {
        // Keep base list item if background detail fetch fails transiently
      });
    return () => {
      cancelled = true;
    };
  }, [alert.id]);

  const allowedStatuses = Array.from(
    new Set<SecurityAlertItem['status']>([
      fullAlert.status,
      ...(VALID_TRANSITIONS[fullAlert.status] ?? []),
    ]),
  );
  const isTerminalStatus = allowedStatuses.length <= 1;
  const statusChanged = newStatus !== fullAlert.status;
  const requiresResolutionNote =
    statusChanged && (newStatus === 'RESOLVED' || newStatus === 'FALSE_POSITIVE');

  async function handleUpdateAlertStatus() {
    if (!canManageAlerts) return;
    const trimmedResNote = resolutionNote.trim();
    const trimmedInvNote = investigationNote.trim();

    if (!statusChanged && !trimmedInvNote) {
      onError('Vui lòng chọn trạng thái xử lý mới hoặc nhập ghi chú điều tra nội bộ.');
      return;
    }
    if (requiresResolutionNote && trimmedResNote.length < 5) {
      onError(
        'Cần nhập ghi chú kết luận xử lý (tối thiểu 5 ký tự) khi hoàn tất hoặc đánh dấu báo động giả.',
      );
      return;
    }
    if (trimmedInvNote && trimmedInvNote.length < 5) {
      onError('Ghi chú điều tra nội bộ cần tối thiểu 5 ký tự.');
      return;
    }

    setIsUpdatingAlert(true);
    onClearError();

    try {
      let updatedDto: AlertApiDto;
      if (statusChanged) {
        // CONFLICT-RESOLVED: Gửi nguyên tử cả status, resolutionNote và investigationNote trong đúng 1 PATCH (#09).
        updatedDto = await apiClient<AlertApiDto>(`/security-alerts/${fullAlert.id}/status`, {
          method: 'PATCH',
          body: JSON.stringify({
            status: newStatus,
            ...(trimmedResNote ? { resolutionNote: trimmedResNote } : {}),
            ...(trimmedInvNote ? { investigationNote: trimmedInvNote } : {}),
          }),
        });
      } else {
        updatedDto = await apiClient<AlertApiDto>(`/security-alerts/${fullAlert.id}/notes`, {
          method: 'POST',
          body: JSON.stringify({ note: trimmedInvNote }),
        });
      }

      const mapped = mapAlertDto(updatedDto);
      setFullAlert(mapped);
      setNewStatus(mapped.status);

      const confirmedNote: AlertNoteItem | undefined = trimmedInvNote
        ? {
            id: `note-${Date.now()}`,
            note: trimmedInvNote,
            authorName:
              currentUser?.fullName || currentUser?.username || 'Cán bộ an ninh thông tin',
            createdAt: new Date().toISOString(),
          }
        : undefined;
      const isReopeningInvestigation =
        statusChanged && (mapped.status === 'INVESTIGATING' || mapped.status === 'OPEN');
      const nextResolutionNote = isReopeningInvestigation
        ? null
        : mapped.resolutionNote !== undefined
          ? mapped.resolutionNote
          : trimmedResNote || undefined;
      onOptimisticUpdate?.(fullAlert.id, {
        status: mapped.status,
        resolutionNote: nextResolutionNote,
        addedNote: confirmedNote,
      });
      setInvestigationNote('');
      if (trimmedResNote) setResolutionNote('');
      await onSuccess(
        statusChanged
          ? `Đã cập nhật trạng thái cảnh báo thành "${formatAlertStatusLabel(mapped.status)}".`
          : 'Đã lưu ghi chú điều tra nội bộ cho cảnh báo.',
      );
      if (statusChanged) onClose();
    } catch (err) {
      onError(err instanceof ApiError ? err.message : 'Đã xảy ra lỗi khi cập nhật cảnh báo.');
    } finally {
      setIsUpdatingAlert(false);
    }
  }

  return (
    <>
      <div className="space-y-3.5 py-2 text-xs">
        <AlertNotesHistory
          ruleCode={fullAlert.ruleCode}
          title={fullAlert.title}
          description={fullAlert.description}
          detectedUserName={fullAlert.detectedUserName}
          ipAddress={fullAlert.ipAddress}
          detectedAt={fullAlert.detectedAt}
          resolutionNote={fullAlert.resolutionNote}
          notes={fullAlert.notes}
          linkedAuditLogs={fullAlert.linkedAuditLogs}
        />

        {canManageAlerts && (
          <>
            <div className="space-y-1">
              <label htmlFor="alert-status-select" className="font-medium text-[#222222]">
                Trạng thái xử lý
              </label>
              <Select
                id="alert-status-select"
                value={newStatus}
                disabled={isTerminalStatus || isUpdatingAlert}
                onChange={(e) => setNewStatus(e.target.value as SecurityAlertItem['status'])}
              >
                {allowedStatuses.map((opt) => (
                  <option key={opt} value={opt}>
                    {STATUS_LABELS[opt]}
                  </option>
                ))}
              </Select>
            </div>

            {requiresResolutionNote && (
              <div className="space-y-1">
                <label htmlFor="res-note" className="font-medium text-[#222222]">
                  Ghi chú kết luận (tối thiểu 5 ký tự) <span className="text-[#C13515]">*</span>
                </label>
                <Textarea
                  id="res-note"
                  rows={2}
                  maxLength={1000}
                  disabled={isUpdatingAlert}
                  value={resolutionNote}
                  onChange={(e) => setResolutionNote(e.target.value)}
                  placeholder="Nêu rõ kết quả xác minh hoặc nguyên nhân báo động giả…"
                  className="text-xs rounded-[20px] bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#717171]"
                />
              </div>
            )}

            <div className="space-y-1">
              <label htmlFor="inv-note" className="font-medium text-[#222222]">
                Thêm ghi chú điều tra nội bộ
              </label>
              <Textarea
                id="inv-note"
                rows={2}
                maxLength={1000}
                disabled={isUpdatingAlert}
                value={investigationNote}
                onChange={(e) => setInvestigationNote(e.target.value)}
                placeholder="Ghi nhận các bước rà soát nhật ký, trao đổi với người dùng…"
                className="text-xs rounded-[20px] bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#717171]"
              />
            </div>
          </>
        )}
      </div>

      <DialogFooter className="pt-2 flex flex-wrap items-center justify-between gap-2">
        {canCreateIncident && onCreateIncidentFromAlert ? (
          <InteractiveHoverButton
            type="button"
            variant="secondary"
            size="sm"
            text="Lập hồ sơ sự cố"
            icon={<FilePlus2 size={16} strokeWidth={1.75} aria-hidden="true" />}
            onClick={() => {
              onClose();
              onCreateIncidentFromAlert({
                alertId: fullAlert.id,
                title: `Điều tra sự cố: ${formatDetectionRuleLabel(fullAlert.ruleCode)}`.slice(
                  0,
                  200,
                ),
                summary:
                  `Khởi tạo từ cảnh báo "${fullAlert.title}" (${fullAlert.detectedUserName || 'Chưa định danh'}, IP ${fullAlert.ipAddress}). ${fullAlert.description}`.trim(),
              });
            }}
          />
        ) : (
          <span />
        )}

        <div className="flex items-center gap-2">
          <InteractiveHoverButton
            type="button"
            variant="ghost"
            size="sm"
            text="Đóng"
            onClick={onClose}
          />
          {canManageAlerts && (
            <InteractiveHoverButton
              type="button"
              variant="primary"
              size="sm"
              text="Cập nhật cảnh báo"
              icon={<Check size={16} strokeWidth={2} aria-hidden="true" />}
              isLoading={isUpdatingAlert}
              disabled={isUpdatingAlert}
              onClick={() => void handleUpdateAlertStatus()}
            />
          )}
        </div>
      </DialogFooter>
    </>
  );
}
