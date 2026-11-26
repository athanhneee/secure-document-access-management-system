'use client';

import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { AlertTriangle, CheckCircle2, FileText, RefreshCw } from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import { formatIncidentStatusLabel } from '@/lib/ui-labels';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { isValidPositiveBigIntId, mapIncidentDto } from '../helpers';
import type { IncidentApiDto, IncidentItem } from '../types';
import { IncidentActionsPanel } from './incident-actions-panel';
import { IncidentAnalysisForm, IncidentLifecycleFooter } from './incident-analysis-form';

function toLocalDayEndIso(dateStr: string): string {
  const parts = dateStr.trim().split('-').map(Number);
  if (parts.length === 3 && parts.every((n) => Number.isInteger(n))) {
    const [year, month, day] = parts as [number, number, number];
    const localEnd = new Date(year, month - 1, day, 23, 59, 59, 999);
    if (!Number.isNaN(localEnd.getTime())) {
      return localEnd.toISOString();
    }
  }
  return new Date(`${dateStr}T23:59:59`).toISOString();
}

interface IncidentDetailModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  incidentId: string | null;
  canManageIncidents?: boolean | undefined;
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

/**
 * Thuật toán: Điều Phối Vòng Đời Hồ Sơ Sự Cố SOC Có Tự Động Lưu Bản Nháp Trước Khi Gửi/Đóng (`IncidentDetailModal`)
 * Mục đích:
 *   - Khi `isDraftDirty === true` và người dùng bấm "Gửi phê duyệt", "Chuyển xem xét" hoặc "Đóng hồ sơ sự cố", tự động gọi `PATCH /incidents/:id` trước và dừng ngay nếu `PATCH` thất bại (không dùng `window.confirm`).
 *   - Kiểm định `submittedToOwner` / `submittedToAdmin` thuộc miền `PositiveBigInt` `[1, 9223372036854775807]`.
 */
export function IncidentDetailModal({
  open,
  onOpenChange,
  incidentId,
  canManageIncidents = true,
  onClearError,
  onSuccess,
  onError,
}: IncidentDetailModalProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[88vh] overflow-y-auto border-[#ebebeb] bg-[#ffffff] text-[#222222]">
        {open && incidentId ? (
          <IncidentDetailBody
            key={incidentId}
            incidentId={incidentId}
            canManageIncidents={canManageIncidents}
            onClose={() => onOpenChange(false)}
            onClearError={onClearError}
            onSuccess={onSuccess}
            onError={onError}
          />
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

function IncidentDetailBody({
  incidentId,
  canManageIncidents,
  onClose,
  onClearError,
  onSuccess,
  onError,
}: {
  incidentId: string;
  canManageIncidents: boolean;
  onClose: () => void;
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}) {
  const [detail, setDetail] = useState<IncidentItem | null>(null);
  const [isLoadingDetail, setIsLoadingDetail] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [title, setTitle] = useState('');
  const [summary, setSummary] = useState('');
  const [findings, setFindings] = useState('');
  const [impactAssessment, setImpactAssessment] = useState('');
  const [isDraftDirty, setIsDraftDirty] = useState(false);

  const [submittedToOwner, setSubmittedToOwner] = useState('');
  const [submittedToAdmin, setSubmittedToAdmin] = useState('');
  const [closingNote, setClosingNote] = useState('');
  const [forceClose, setForceClose] = useState(false);
  const [busyOp, setBusyOp] = useState<'save' | 'submit' | 'review' | 'close' | null>(null);

  const loadDetail = useCallback(
    async (id: string, opts?: { preserveDraft?: boolean }) => {
      setIsLoadingDetail(true);
      setLoadError(null);
      try {
        const mapped = mapIncidentDto(await apiClient<IncidentApiDto>(`/incidents/${id}`));
        setDetail(mapped);
        if (!opts?.preserveDraft) {
          setTitle(mapped.title);
          setSummary(mapped.summary);
          setFindings(mapped.findings || '');
          setImpactAssessment(mapped.impactAssessment || '');
          setIsDraftDirty(false);
        }
      } catch (err) {
        const msg = err instanceof ApiError ? err.message : 'Không thể tải chi tiết hồ sơ sự cố.';
        setLoadError(msg);
        onError(msg);
      } finally {
        setIsLoadingDetail(false);
      }
    },
    [onError],
  );

  useEffect(() => {
    let cancelled = false;
    apiClient<IncidentApiDto>(`/incidents/${incidentId}`)
      .then((dto) => {
        if (cancelled) return;
        const mapped = mapIncidentDto(dto);
        setDetail(mapped);
        setTitle(mapped.title);
        setSummary(mapped.summary);
        setFindings(mapped.findings || '');
        setImpactAssessment(mapped.impactAssessment || '');
        setIsDraftDirty(false);
      })
      .catch((err) => {
        if (!cancelled) {
          const msg = err instanceof ApiError ? err.message : 'Không thể tải chi tiết hồ sơ sự cố.';
          setLoadError(msg);
          onError(msg);
        }
      })
      .finally(() => {
        if (!cancelled) setIsLoadingDetail(false);
      });
    return () => {
      cancelled = true;
    };
  }, [incidentId, onError]);

  const isClosed = detail?.status === 'CLOSED';
  const readOnly = Boolean(isClosed) || !canManageIncidents;
  const canSubmit = canManageIncidents && detail?.status === 'DRAFT';
  const canReview = canManageIncidents && detail?.status === 'SUBMITTED';
  const canClose =
    canManageIncidents && (detail?.status === 'SUBMITTED' || detail?.status === 'IN_REVIEW');
  const incompleteActionsCount = (detail?.actions ?? []).filter(
    (a) => !a.completedAt && !a.isCompleted,
  ).length;

  async function persistAnalysisDraft(targetId: string) {
    await apiClient(`/incidents/${targetId}`, {
      method: 'PATCH',
      body: JSON.stringify({
        title: title.trim(),
        summary: summary.trim(),
        findings: findings.trim(),
        impactAssessment: impactAssessment.trim(),
      }),
    });
    setIsDraftDirty(false);
  }

  async function handleSaveAnalysis(e: FormEvent) {
    e.preventDefault();
    if (!detail || readOnly) return;
    if (title.trim().length < 5 || summary.trim().length < 10) {
      onError('Tiêu đề cần tối thiểu 5 ký tự và tóm tắt sự cố cần tối thiểu 10 ký tự.');
      return;
    }
    setBusyOp('save');
    onClearError();
    try {
      await persistAnalysisDraft(detail.id);
      await loadDetail(detail.id, { preserveDraft: false });
      await onSuccess('Đã lưu cập nhật phân tích nguyên nhân gốc & đánh giá tác động.');
    } catch (err) {
      onError(err instanceof ApiError ? err.message : 'Không thể cập nhật hồ sơ sự cố.');
    } finally {
      setBusyOp(null);
    }
  }

  async function handleAddAction(
    actionType: string,
    recommendation: string,
    dueAt?: string,
    assignedTo?: string,
  ): Promise<boolean> {
    if (!detail || readOnly) return false;
    onClearError();
    try {
      await apiClient(`/incidents/${detail.id}/actions`, {
        method: 'POST',
        body: JSON.stringify({
          actionType,
          recommendation,
          ...(assignedTo ? { assignedTo } : {}),
          ...(dueAt ? { dueAt: toLocalDayEndIso(dueAt) } : {}),
        }),
      });
      await loadDetail(detail.id, { preserveDraft: isDraftDirty });
      await onSuccess('Đã bổ sung hành động khắc phục vào hồ sơ sự cố.');
      return true;
    } catch (err) {
      onError(err instanceof ApiError ? err.message : 'Không thể thêm hành động khắc phục.');
      return false;
    }
  }

  async function handleCompleteAction(actionId: string, completionNote: string): Promise<boolean> {
    if (!detail || readOnly) return false;
    onClearError();
    try {
      await apiClient(`/incidents/${detail.id}/actions/${actionId}/complete`, {
        method: 'PATCH',
        body: JSON.stringify({ completionNote }),
      });
      await loadDetail(detail.id, { preserveDraft: isDraftDirty });
      await onSuccess('Đã đánh dấu hoàn thành hành động khắc phục.');
      return true;
    } catch (err) {
      onError(err instanceof ApiError ? err.message : 'Không thể hoàn thành hành động khắc phục.');
      return false;
    }
  }

  async function handleTransition(mode: 'submit' | 'review' | 'close') {
    if (!detail || !canManageIncidents) return;
    if (isDraftDirty && !readOnly && (title.trim().length < 5 || summary.trim().length < 10)) {
      onError(
        'Nội dung phân tích chưa lưu không hợp lệ: Tiêu đề cần tối thiểu 5 ký tự và tóm tắt sự cố cần tối thiểu 10 ký tự.',
      );
      return;
    }

    const trimmedClose = closingNote.trim();
    if (mode === 'close') {
      if (incompleteActionsCount > 0 && (!forceClose || trimmedClose.length < 5)) {
        onError(
          `Còn ${incompleteActionsCount} hành động khắc phục chưa hoàn tất. Vui lòng hoàn thành trước khi đóng hoặc chọn "Đóng ngoại lệ" kèm ghi chú kết luận tối thiểu 5 ký tự.`,
        );
        return;
      }
      if (trimmedClose.length > 0 && trimmedClose.length < 5) {
        onError('Ghi chú đóng hồ sơ (nếu nhập) cần tối thiểu 5 ký tự.');
        return;
      }
    }
    if (mode === 'submit') {
      if (!submittedToOwner.trim() && !submittedToAdmin.trim()) {
        onError(
          'Vui lòng nhập ít nhất một người nhận báo cáo (ID Chủ sở hữu tài liệu hoặc ID Quản trị viên hệ thống).',
        );
        return;
      }
      if (submittedToOwner.trim() && !isValidPositiveBigIntId(submittedToOwner)) {
        onError(
          'Mã tài khoản Chủ sở hữu tài liệu phải là số nguyên dương hợp lệ (từ 1 đến 9223372036854775807).',
        );
        return;
      }
      if (submittedToAdmin.trim() && !isValidPositiveBigIntId(submittedToAdmin)) {
        onError(
          'Mã tài khoản Quản trị viên hệ thống phải là số nguyên dương hợp lệ (từ 1 đến 9223372036854775807).',
        );
        return;
      }
    }

    setBusyOp(mode);
    onClearError();
    try {
      if (isDraftDirty && !readOnly) {
        await persistAnalysisDraft(detail.id);
      }

      if (mode === 'submit') {
        await apiClient(`/incidents/${detail.id}/submit`, {
          method: 'POST',
          body: JSON.stringify({
            ...(submittedToOwner.trim() ? { submittedToOwner: submittedToOwner.trim() } : {}),
            ...(submittedToAdmin.trim() ? { submittedToAdmin: submittedToAdmin.trim() } : {}),
          }),
        });
        await loadDetail(detail.id, { preserveDraft: false });
        await onSuccess('Đã gửi phê duyệt hồ sơ sự cố thành công.');
      } else if (mode === 'review') {
        await apiClient(`/incidents/${detail.id}/review`, { method: 'POST', body: '{}' });
        await loadDetail(detail.id, { preserveDraft: false });
        await onSuccess('Đã chuyển hồ sơ sự cố sang trạng thái Đang xem xét.');
      } else {
        await apiClient(`/incidents/${detail.id}/close`, {
          method: 'POST',
          body: JSON.stringify({
            ...(trimmedClose ? { closingNote: trimmedClose } : {}),
            ...(forceClose ? { forceClose: true } : {}),
          }),
        });
        onClose();
        await onSuccess('Đã đóng hồ sơ sự cố an ninh thành công.');
      }
    } catch (err) {
      onError(err instanceof ApiError ? err.message : 'Không thể chuyển trạng thái sự cố.');
    } finally {
      setBusyOp(null);
    }
  }

  return (
    <>
      <DialogHeader>
        <div className="flex flex-wrap items-center justify-between gap-2 pr-8">
          <DialogTitle className="flex items-center gap-2 text-base font-semibold text-[#222222]">
            <FileText size={20} strokeWidth={1.75} className="text-[#FF385C]" aria-hidden="true" />
            <span>Hồ sơ sự cố {detail?.incidentCode || ''}</span>
          </DialogTitle>
          {detail && (
            <Badge variant={isClosed ? 'success' : detail.status === 'DRAFT' ? 'warning' : 'info'}>
              {formatIncidentStatusLabel(detail.status)}
            </Badge>
          )}
        </div>
        <DialogDescription className="text-xs text-[#717171]">
          Phân tích nguyên nhân gốc, theo dõi hành động khắc phục và cập nhật tiến độ xử lý sự cố.
        </DialogDescription>
      </DialogHeader>

      {isLoadingDetail && !detail ? (
        <div className="py-8 text-center text-xs text-[#717171]">Đang tải hồ sơ sự cố…</div>
      ) : !detail ? (
        <div className="space-y-4 py-4 text-xs">
          <div className="rounded-[16px] border border-[#dddddd] bg-[#f7f7f7] p-4 text-center space-y-2">
            <div className="flex justify-center text-[#C13515]">
              <AlertTriangle size={20} strokeWidth={1.75} aria-hidden="true" />
            </div>
            <p className="font-semibold text-[#222222]">Không thể tải hồ sơ sự cố</p>
            <p className="text-[#717171]">
              {loadError || 'Vui lòng kiểm tra kết nối và thử tải lại.'}
            </p>
          </div>
          <DialogFooter className="flex flex-wrap gap-2">
            <InteractiveHoverButton
              type="button"
              variant="ghost"
              size="sm"
              text="Đóng"
              onClick={onClose}
            />
            <InteractiveHoverButton
              type="button"
              variant="secondary"
              size="sm"
              text="Thử lại"
              icon={<RefreshCw size={16} strokeWidth={1.75} aria-hidden="true" />}
              onClick={() => {
                onClearError();
                void loadDetail(incidentId);
              }}
            />
          </DialogFooter>
        </div>
      ) : (
        <div className="space-y-4 py-2 text-xs">
          {detail.closingNote && (
            <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1">
              <div className="flex items-center gap-1.5 font-semibold text-[#008A05]">
                <CheckCircle2 size={16} strokeWidth={1.75} aria-hidden="true" />
                <span>Ghi chú nghiệm thu đóng hồ sơ:</span>
              </div>
              <p className="text-xs text-[#222222] leading-relaxed whitespace-pre-wrap">
                {detail.closingNote}
              </p>
            </div>
          )}

          <IncidentAnalysisForm
            title={title}
            summary={summary}
            findings={findings}
            impactAssessment={impactAssessment}
            isClosed={readOnly}
            isSaving={busyOp === 'save'}
            isBusy={busyOp !== null}
            isDraftDirty={isDraftDirty}
            onTitleChange={(v) => {
              setTitle(v);
              setIsDraftDirty(true);
            }}
            onSummaryChange={(v) => {
              setSummary(v);
              setIsDraftDirty(true);
            }}
            onFindingsChange={(v) => {
              setFindings(v);
              setIsDraftDirty(true);
            }}
            onImpactChange={(v) => {
              setImpactAssessment(v);
              setIsDraftDirty(true);
            }}
            onSubmit={handleSaveAnalysis}
          />

          <IncidentActionsPanel
            actions={detail.actions || []}
            isClosed={readOnly}
            onAddAction={handleAddAction}
            onCompleteAction={handleCompleteAction}
            onError={onError}
          />

          <IncidentLifecycleFooter
            canSubmit={Boolean(canSubmit)}
            canReview={Boolean(canReview)}
            canClose={Boolean(canClose)}
            incompleteActionsCount={incompleteActionsCount}
            submittedToOwner={submittedToOwner}
            submittedToAdmin={submittedToAdmin}
            closingNote={closingNote}
            forceClose={forceClose}
            busyOp={busyOp}
            onSubmittedToOwnerChange={setSubmittedToOwner}
            onSubmittedToAdminChange={setSubmittedToAdmin}
            onClosingNoteChange={setClosingNote}
            onForceCloseChange={setForceClose}
            onCloseDialog={onClose}
            onTransition={(mode) => handleTransition(mode)}
          />
        </div>
      )}
    </>
  );
}
