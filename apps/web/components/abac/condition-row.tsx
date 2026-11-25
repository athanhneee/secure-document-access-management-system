'use client';

import { ArrowDown, ArrowUp, Copy, GripVertical, Trash2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  ATTRIBUTE_REGISTRY,
  OPERATOR_LABELS,
  type AttributeMetadata,
  type PolicyOperator,
  type VisualCondition,
} from './abac-models';
import { ExpectedValueWidget } from './expected-value-widget';

interface ConditionRowProps {
  groupId: number;
  condition: VisualCondition;
  conditionIndex: number;
  totalConditions: number;
  attributeRegistry?: Readonly<Record<string, AttributeMetadata>> | undefined;
  onDragStart: (groupId: number, conditionIndex: number) => void;
  onMove: (groupId: number, index: number, direction: 'up' | 'down') => void;
  onChangeField: (
    groupId: number,
    conditionId: string,
    field: keyof VisualCondition,
    value: unknown,
  ) => void;
  onDuplicate: (groupId: number, condition: VisualCondition) => void;
  onRemove: (groupId: number, conditionId: string) => void;
}

export function ConditionRow({
  groupId,
  condition,
  conditionIndex,
  totalConditions,
  attributeRegistry = ATTRIBUTE_REGISTRY,
  onDragStart,
  onMove,
  onChangeField,
  onDuplicate,
  onRemove,
}: ConditionRowProps) {
  const meta = attributeRegistry[condition.attribute] ?? ATTRIBUTE_REGISTRY[condition.attribute];

  return (
    <div
      draggable
      onDragStart={() => onDragStart(groupId, conditionIndex)}
      className="group flex flex-col md:flex-row items-stretch md:items-center gap-2 p-2.5 rounded-[12px] bg-[#f7f7f7] border border-[#ebebeb] hover:border-[#dddddd] transition-all text-xs"
    >
      <div className="flex items-center gap-1 text-[#717171]">
        <GripVertical size={16} strokeWidth={1.75} className="cursor-grab" aria-hidden="true" />
        <div className="flex flex-row md:flex-col gap-1">
          <button
            type="button"
            aria-label="Di chuyển điều kiện lên"
            onClick={() => onMove(groupId, conditionIndex, 'up')}
            disabled={conditionIndex === 0}
            className="flex min-h-11 min-w-11 sm:min-h-9 sm:min-w-9 items-center justify-center rounded-full hover:bg-[#ffffff] hover:text-[#222222] disabled:opacity-30 cursor-pointer"
          >
            <ArrowUp size={16} strokeWidth={1.75} aria-hidden="true" />
          </button>
          <button
            type="button"
            aria-label="Di chuyển điều kiện xuống"
            onClick={() => onMove(groupId, conditionIndex, 'down')}
            disabled={conditionIndex === totalConditions - 1}
            className="flex min-h-11 min-w-11 sm:min-h-9 sm:min-w-9 items-center justify-center rounded-full hover:bg-[#ffffff] hover:text-[#222222] disabled:opacity-30 cursor-pointer"
          >
            <ArrowDown size={16} strokeWidth={1.75} aria-hidden="true" />
          </button>
        </div>
      </div>

      <div className="flex-1 min-w-0 sm:min-w-[180px]">
        <select
          aria-label="Thuộc tính điều kiện"
          value={condition.attribute}
          onChange={(e) => onChangeField(groupId, condition.id, 'attribute', e.target.value)}
          className="w-full min-h-11 sm:h-9 text-xs font-medium rounded-full border border-[#dddddd] px-3 bg-[#ffffff] text-[#222222]"
        >
          {Object.values(attributeRegistry).map((a) => (
            <option key={a.key} value={a.key}>
              {a.label}
            </option>
          ))}
        </select>
      </div>

      <div className="w-full md:w-[170px]">
        <select
          aria-label="Toán tử so sánh"
          value={condition.operator}
          onChange={(e) =>
            onChangeField(groupId, condition.id, 'operator', e.target.value as PolicyOperator)
          }
          className="w-full min-h-11 sm:h-9 text-xs font-semibold rounded-full border border-[#dddddd] px-3 bg-[#ffffff] text-[#E31C5F]"
        >
          {(meta?.supportedOperators || ['EQ']).map((op) => (
            <option key={op} value={op}>
              {OPERATOR_LABELS[op] || op}
            </option>
          ))}
        </select>
      </div>

      <div className="flex-1 min-w-0 sm:min-w-[180px]">
        <ExpectedValueWidget
          attributeMeta={meta}
          operator={condition.operator}
          value={condition.expected}
          onChange={(newVal) => onChangeField(groupId, condition.id, 'expected', newVal)}
        />
      </div>

      <div className="flex items-center gap-1 justify-end">
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={() => onDuplicate(groupId, condition)}
          title="Nhân bản điều kiện"
          aria-label="Nhân bản điều kiện"
          className="min-h-11 min-w-11 sm:h-9 sm:w-9 p-0 rounded-full hover:bg-white text-[#717171]"
        >
          <Copy size={16} strokeWidth={1.75} aria-hidden="true" />
        </Button>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={() => onRemove(groupId, condition.id)}
          title="Xóa điều kiện"
          aria-label="Xóa điều kiện"
          className="min-h-11 min-w-11 sm:h-9 sm:w-9 p-0 rounded-full hover:bg-[#C13515]/10 text-[#C13515]"
        >
          <Trash2 size={16} strokeWidth={1.75} aria-hidden="true" />
        </Button>
      </div>
    </div>
  );
}
