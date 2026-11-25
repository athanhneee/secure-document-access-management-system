'use client';

import { useState, type FormEvent } from 'react';
import { Check, Plus } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { formatIncidentActionTypeLabel } from '@/lib/ui-labels';
import type { IncidentActionItem } from '../types';

interface IncidentActionsPanelProps {
  actions: IncidentActionItem[];
  isClosed: boolean;
  onAddAction: (actionType: string, recommendation: string) => Promise<boolean>;
  onCompleteAction: (actionId: string, completionNote: string) => Promise<boolean>;
  onError: (msg: string) => void;
}

/**
 * Thuật toán: Quản Lý Danh Sách Hành Động Khắc Phục Sự Cố & Ghi Chú Nghiệm Thu (`IncidentActionsPanel`)
 * Mục đích: Cho phép thêm hành động khắc phục mới (`POST /incidents/:id/actions`) và đánh dấu hoàn tất kèm biên bản nghiệm thu tối thiểu 5 ký tự (`PATCH /incidents/:id/actions/:actionId/complete`).
 */
export function IncidentActionsPanel({
  actions,
  isClosed,
  onAddAction,
  onCompleteAction,
  onError,
}: IncidentActionsPanelProps) {
  const [actionType, setActionType] = useState('REVOKE_ACCESS');
  const [recommendation, setRecommendation] = useState('');
  const [isAdding, setIsAdding] = useState(false);

  const [completingActionId, setCompletingActionId] = useState<string | null>(null);
  const [completionNotes, setCompletionNotes] = useState<Record<string, string>>({});

  async function handleCreateAction(e: FormEvent) {
    e.preventDefault();
    if (actionType.trim().length < 3) {
      onError('Loại hành động khắc phục phải có ít nhất 3 ký tự.');
      return;
    }
    if (recommendation.trim().length < 5) {
      onError('Khuyến nghị khắc phục phải có ít nhất 5 ký tự.');
      return;
    }
    setIsAdding(true);
    try {
      const ok = await onAddAction(actionType.trim(), recommendation.trim());
      if (ok) setRecommendation('');
    } finally {
      setIsAdding(false);
    }
  }

  async function handleFinishAction(actionId: string) {
    const note = (completionNotes[actionId] || '').trim();
    if (note.length < 5) {
      onError('Ghi chú nghiệm thu hoàn thành hành động phải có ít nhất 5 ký tự.');
      return;
    }
    setCompletingActionId(actionId);
    try {
      const ok = await onCompleteAction(actionId, note);
      if (ok) {
        setCompletionNotes((prev) => {
          const next = { ...prev };
          delete next[actionId];
          return next;
        });
      }
    } finally {
      setCompletingActionId(null);
    }
  }

  return (
    <div className="space-y-3 rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3.5 text-xs">
      <div className="flex items-center justify-between gap-2">
        <h4 className="font-semibold text-[#222222]">Hành động khắc phục ({actions.length})</h4>
      </div>

      {actions.length === 0 ? (
        <p className="text-[#717171]">Chưa có hành động khắc phục nào được ghi nhận.</p>
      ) : (
        <div className="space-y-2">
          {actions.map((act) => {
            const done = Boolean(act.completedAt) || Boolean(act.isCompleted);
            return (
              <div
                key={act.id}
                className="rounded-[16px] border border-[#ebebeb] bg-[#ffffff] p-3 space-y-2"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-semibold text-[#222222]">
                    {formatIncidentActionTypeLabel(act.actionType)}
                  </span>
                  <Badge variant={done ? 'success' : 'warning'}>
                    {done ? 'Đã hoàn thành' : 'Đang thực hiện'}
                  </Badge>
                </div>
                <p className="text-[#222222]">{act.recommendation}</p>
                {done
                  ? act.completionNote && (
                      <div className="text-[#008A05] text-xs border-t border-[#ebebeb] pt-1.5">
                        Nghiệm thu: {act.completionNote}
                      </div>
                    )
                  : !isClosed && (
                      <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 pt-1">
                        <label htmlFor={`complete-note-${act.id}`} className="sr-only">
                          Ghi chú hoàn thành hành động{' '}
                          {formatIncidentActionTypeLabel(act.actionType)}
                        </label>
                        <Input
                          id={`complete-note-${act.id}`}
                          value={completionNotes[act.id] ?? ''}
                          onChange={(e) =>
                            setCompletionNotes((prev) => ({ ...prev, [act.id]: e.target.value }))
                          }
                          placeholder="Ghi chú kết quả thực hiện (tối thiểu 5 ký tự)…"
                          className="min-h-11 sm:h-9 flex-1 text-xs rounded-full bg-[#ffffff] border-[#dddddd]"
                        />
                        <InteractiveHoverButton
                          type="button"
                          variant="secondary"
                          size="sm"
                          text="Hoàn thành"
                          icon={<Check size={16} strokeWidth={2} aria-hidden="true" />}
                          isLoading={completingActionId === act.id}
                          disabled={completingActionId === act.id}
                          onClick={() => void handleFinishAction(act.id)}
                        />
                      </div>
                    )}
              </div>
            );
          })}
        </div>
      )}

      {!isClosed && (
        <form onSubmit={handleCreateAction} className="space-y-2 border-t border-[#dddddd] pt-3">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
            <div>
              <label
                htmlFor="incident-action-type"
                className="block font-medium text-[#222222] mb-1"
              >
                Loại hành động
              </label>
              <select
                id="incident-action-type"
                value={actionType}
                onChange={(e) => setActionType(e.target.value)}
                className="w-full min-h-11 sm:h-9 rounded-full border border-[#dddddd] bg-[#ffffff] px-3 text-xs text-[#222222] cursor-pointer"
              >
                <option value="REVOKE_ACCESS">Thu hồi quyền truy cập</option>
                <option value="LOCK_ACCOUNT">Tạm khóa tài khoản</option>
                <option value="ROTATE_POLICY">Cập nhật chính sách bảo mật</option>
                <option value="FORENSIC_AUDIT">Kiểm tra chuyên sâu</option>
              </select>
            </div>
            <div className="sm:col-span-2">
              <label
                htmlFor="incident-action-rec"
                className="block font-medium text-[#222222] mb-1"
              >
                Nội dung khắc phục đề xuất
              </label>
              <div className="flex flex-col sm:flex-row gap-2">
                <Input
                  id="incident-action-rec"
                  value={recommendation}
                  onChange={(e) => setRecommendation(e.target.value)}
                  placeholder="Mô tả biện pháp xử lý (tối thiểu 5 ký tự)…"
                  className="min-h-11 sm:h-9 flex-1 text-xs rounded-full bg-[#ffffff] border-[#dddddd]"
                />
                <InteractiveHoverButton
                  type="submit"
                  variant="secondary"
                  size="sm"
                  text="Thêm"
                  icon={<Plus size={16} strokeWidth={2} aria-hidden="true" />}
                  isLoading={isAdding}
                  disabled={isAdding}
                />
              </div>
            </div>
          </div>
        </form>
      )}
    </div>
  );
}
