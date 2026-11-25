'use client';

import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { FileText } from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import { formatIncidentStatusLabel } from '@/lib/ui-labels';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { mapIncidentDto } from '../helpers';
import type { IncidentApiDto, IncidentItem } from '../types';
import { IncidentActionsPanel } from './incident-actions-panel';
import { IncidentAnalysisForm, IncidentLifecycleFooter } from './incident-analysis-form';

interface IncidentDetailModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  incidentId: string | null;
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}

/**
 * Thuật toán: Điều Phối Máy Trạng Thái Hồ Sơ Sự Cố SOC (`DRAFT -> SUBMITTED -> CLOSED`) (`IncidentDetailModal`)
 * Mục đích: Khởi tạo phiên xem độc lập theo `incidentId`, nạp `GET /incidents/:id` và điều phối phân tích / khắc phục / đóng hồ sơ.
 */
export function IncidentDetailModal({
  open,
  onOpenChange,
  incidentId,
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
  onClose,
  onClearError,
  onSuccess,
  onError,
}: {
  incidentId: string;
  onClose: () => void;
  onClearError: () => void;
  onSuccess: (message: string) => Promise<void>;
  onError: (errorMessage: string) => void;
}) {
  const [detail, setDetail] = useState<IncidentItem | null>(null);
  const [isLoadingDetail, setIsLoadingDetail] = useState(true);
  const [title, setTitle] = useState('');
  const [summary, setSummary] = useState('');
  const [findings, setFindings] = useState('');
  const [impactAssessment, setImpactAssessment] = useState('');
  const [closingNote, setClosingNote] = useState('');
  const [busyOp, setBusyOp] = useState<'save' | 'submit' | 'close' | null>(null);

  const loadDetail = useCallback(
    async (id: string) => {
      setIsLoadingDetail(true);
      try {
        const mapped = mapIncidentDto(await apiClient<IncidentApiDto>(`/incidents/${id}`));
        setDetail(mapped);
        setTitle(mapped.title);
        setSummary(mapped.summary);
        setFindings(mapped.findings || '');
        setImpactAssessment(mapped.impactAssessment || '');
      } catch (err) {
        onError(err instanceof ApiError ? err.message : 'Không thể tải chi tiết hồ sơ sự cố.');
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
      })
      .catch((err) => {
        if (!cancelled) {
          onError(err instanceof ApiError ? err.message : 'Không thể tải chi tiết hồ sơ sự cố.');
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
  const canSubmit = detail?.status === 'DRAFT';
  const canClose = detail?.status === 'SUBMITTED' || detail?.status === 'IN_REVIEW';

  async function handleSaveAnalysis(e: FormEvent) {
    e.preventDefault();
    if (!detail || isClosed) return;
    if (title.trim().length < 5 || summary.trim().length < 10) {
      onError('Tiêu đề cần tối thiểu 5 ký tự và tóm tắt sự cố cần tối thiểu 10 ký tự.');
      return;
    }
    setBusyOp('save');
    onClearError();
    try {
      await apiClient(`/incidents/${detail.id}`, {
        method: 'PATCH',
        body: JSON.stringify({
          title: title.trim(),
          summary: summary.trim(),
          findings: findings.trim(),
          impactAssessment: impactAssessment.trim(),
        }),
      });
      await loadDetail(detail.id);
      await onSuccess('Đã lưu cập nhật phân tích nguyên nhân gốc & đánh giá tác động.');
    } catch (err) {
      onError(err instanceof ApiError ? err.message : 'Không thể cập nhật hồ sơ sự cố.');
    } finally {
      setBusyOp(null);
    }
  }

  async function handleAddAction(actionType: string, recommendation: string): Promise<boolean> {
    if (!detail) return false;
    onClearError();
    try {
      await apiClient(`/incidents/${detail.id}/actions`, {
        method: 'POST',
        body: JSON.stringify({ actionType, recommendation }),
      });
      await loadDetail(detail.id);
      await onSuccess('Đã bổ sung hành động khắc phục vào hồ sơ sự cố.');
      return true;
    } catch (err) {
      onError(err instanceof ApiError ? err.message : 'Không thể thêm hành động khắc phục.');
      return false;
    }
  }

  async function handleCompleteAction(actionId: string, completionNote: string): Promise<boolean> {
    if (!detail) return false;
    onClearError();
    try {
      await apiClient(`/incidents/${detail.id}/actions/${actionId}/complete`, {
        method: 'PATCH',
        body: JSON.stringify({ completionNote }),
      });
      await loadDetail(detail.id);
      await onSuccess('Đã đánh dấu hoàn thành hành động khắc phục.');
      return true;
    } catch (err) {
      onError(err instanceof ApiError ? err.message : 'Không thể hoàn thành hành động khắc phục.');
      return false;
    }
  }

  async function handleTransition(mode: 'submit' | 'close') {
    if (!detail) return;
    const trimmedClose = closingNote.trim();
    if (mode === 'close' && trimmedClose.length > 0 && trimmedClose.length < 5) {
      onError('Ghi chú đóng hồ sơ (nếu nhập) cần tối thiểu 5 ký tự.');
      return;
    }
    setBusyOp(mode);
    onClearError();
    try {
      if (mode === 'submit') {
        await apiClient(`/incidents/${detail.id}/submit`, { method: 'POST', body: '{}' });
        await loadDetail(detail.id);
        await onSuccess('Đã gửi phê duyệt hồ sơ sự cố thành công.');
      } else {
        await apiClient(`/incidents/${detail.id}/close`, {
          method: 'POST',
          body: JSON.stringify(trimmedClose ? { closingNote: trimmedClose } : {}),
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
        <div className="flex flex-wrap items-center justify-between gap-2">
          <DialogTitle className="flex items-center gap-2 text-base font-semibold text-[#222222]">
            <FileText size={20} strokeWidth={1.75} className="text-[#FF385C]" aria-hidden="true" />
            <span>Hồ sơ sự cố {detail?.incidentCode || ''}</span>
          </DialogTitle>
          {detail && (
            <Badge variant={isClosed ? 'success' : canSubmit ? 'warning' : 'info'}>
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
      ) : (
        detail && (
          <div className="space-y-4 py-2 text-xs">
            <IncidentAnalysisForm
              title={title}
              summary={summary}
              findings={findings}
              impactAssessment={impactAssessment}
              isClosed={Boolean(isClosed)}
              isSaving={busyOp === 'save'}
              isBusy={busyOp !== null}
              onTitleChange={setTitle}
              onSummaryChange={setSummary}
              onFindingsChange={setFindings}
              onImpactChange={setImpactAssessment}
              onSubmit={handleSaveAnalysis}
            />

            <IncidentActionsPanel
              actions={detail.actions || []}
              isClosed={Boolean(isClosed)}
              onAddAction={handleAddAction}
              onCompleteAction={handleCompleteAction}
              onError={onError}
            />

            <IncidentLifecycleFooter
              canSubmit={Boolean(canSubmit)}
              canClose={Boolean(canClose)}
              closingNote={closingNote}
              busyOp={busyOp}
              onClosingNoteChange={setClosingNote}
              onCloseDialog={onClose}
              onTransition={(mode) => void handleTransition(mode)}
            />
          </div>
        )
      )}
    </>
  );
}
