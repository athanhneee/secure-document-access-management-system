'use client';

import { Plus, Copy, Trash2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ATTRIBUTE_REGISTRY, type VisualCondition, type VisualConditionGroup } from './abac-models';
import { ConditionRow } from './condition-row';

interface ConditionGroupCardProps {
  group: VisualConditionGroup;
  groupIdx: number;
  onAddCondition: (groupId: number, attributeKey?: string) => void;
  onDuplicateGroup: (group: VisualConditionGroup) => void;
  onRemoveGroup: (groupId: number) => void;
  onDropConditionOnGroup: (targetGroupId: number) => void;
  onDragStartCondition: (groupId: number, conditionIndex: number) => void;
  onMoveCondition: (groupId: number, index: number, direction: 'up' | 'down') => void;
  onChangeConditionField: (
    groupId: number,
    conditionId: string,
    field: keyof VisualCondition,
    value: unknown,
  ) => void;
  onDuplicateCondition: (groupId: number, condition: VisualCondition) => void;
  onRemoveCondition: (groupId: number, conditionId: string) => void;
}

export function ConditionGroupCard({
  group,
  groupIdx,
  onAddCondition,
  onDuplicateGroup,
  onRemoveGroup,
  onDropConditionOnGroup,
  onDragStartCondition,
  onMoveCondition,
  onChangeConditionField,
  onDuplicateCondition,
  onRemoveCondition,
}: ConditionGroupCardProps) {
  return (
    <div className="space-y-2">
      {groupIdx > 0 && (
        <div className="flex items-center justify-center my-2">
          <Badge variant="warning">HOẶC (OR) - Chỉ cần 1 nhóm điều kiện thỏa mãn</Badge>
        </div>
      )}

      <div
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => {
          e.preventDefault();
          const droppedAttrKey = e.dataTransfer.getData('text/plain');
          if (droppedAttrKey && ATTRIBUTE_REGISTRY[droppedAttrKey]) {
            onAddCondition(group.id, droppedAttrKey);
          } else {
            onDropConditionOnGroup(group.id);
          }
        }}
        className="p-4 rounded-[16px] border border-[#ebebeb] bg-[#ffffff] space-y-3 shadow-xs hover:border-[#dddddd] transition-all"
      >
        <div className="flex items-center justify-between border-b border-[#ebebeb] pb-2.5">
          <div className="flex items-center gap-2.5">
            {/* // CONFLICT-RESOLVED: Phẳng hóa nhãn chỉ số nhóm theo chuẩn staff-001 (không bọc hộp tròn màu nền) tại rules/ui-design-system.md. */}
            <span className="staff-badge inline-flex items-center gap-1.5 text-xs font-extrabold text-[#FF385C]">
              <span className="dot dot-primary" aria-hidden="true" />
              <span>#{groupIdx + 1}</span>
            </span>
            <div>
              <h3 className="font-bold text-xs text-[#222222]">
                Nhóm Điều Kiện #{group.id} (Mệnh đề liên hội AND)
              </h3>
              <p className="text-[11px] text-[#717171]">
                Tất cả {group.conditions.length} điều kiện dưới đây phải ĐỒNG THỜI đúng.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-1.5">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => onAddCondition(group.id)}
              className="h-7 text-xs rounded-full border-[#dddddd] hover:border-[#FF385C] flex items-center gap-1"
            >
              <Plus size={16} strokeWidth={1.75} className="text-[#FF385C]" aria-hidden="true" />
              <span>Thêm AND</span>
            </Button>

            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => onDuplicateGroup(group)}
              title="Nhân bản nhóm điều kiện"
              aria-label={`Nhân bản nhóm điều kiện ${group.id}`}
              className="h-7 w-7 p-0 rounded-full hover:bg-[#f7f7f7] text-[#717171]"
            >
              <Copy size={16} strokeWidth={1.75} aria-hidden="true" />
            </Button>

            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => onRemoveGroup(group.id)}
              title="Xóa nhóm"
              aria-label={`Xóa nhóm điều kiện ${group.id}`}
              className="h-7 w-7 p-0 rounded-full hover:bg-[#C13515]/10 text-[#C13515]"
            >
              <Trash2 size={16} strokeWidth={1.75} aria-hidden="true" />
            </Button>
          </div>
        </div>

        <div className="space-y-2">
          {group.conditions.length === 0 ? (
            <div className="p-6 text-center text-xs text-[#717171] border border-dashed border-[#dddddd] rounded-[12px]">
              Chưa có điều kiện nào trong nhóm này. Hãy kéo thuộc tính từ cột trái hoặc bấm
              &quot;Thêm AND&quot;.
            </div>
          ) : (
            group.conditions.map((cond, condIdx) => (
              <ConditionRow
                key={cond.id}
                groupId={group.id}
                condition={cond}
                conditionIndex={condIdx}
                totalConditions={group.conditions.length}
                onDragStart={onDragStartCondition}
                onMove={onMoveCondition}
                onChangeField={onChangeConditionField}
                onDuplicate={onDuplicateCondition}
                onRemove={onRemoveCondition}
              />
            ))
          )}
        </div>
      </div>
    </div>
  );
}
