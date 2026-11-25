'use client';

import { useState } from 'react';
import { Tag, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import type { PolicyOperator } from './abac-models';
import { BetweenBoundsInput, TimeBetweenInput } from './expected-range-widgets';

export interface ExpectedValueWidgetProps {
  attributeMeta?:
    | {
        type?: string | undefined;
        valueType?: string | undefined;
        options?: Array<{ label: string; value: string | number | boolean }> | undefined;
      }
    | undefined;
  operator: PolicyOperator;
  value: unknown;
  onChange: (value: unknown) => void;
}

/**
 * Thuật toán: Điều Khiển Nhập Liệu Giá Trị Kỳ Vọng Đa Hình (`ExpectedValueWidget`)
 * Mục đích:
 *   - Tự động chọn giao diện nhập chuẩn kiểu cho `(attributeMeta, operator)` bao gồm `EXISTS` (Boolean nghiêm ngặt), `TIME_BETWEEN`, `BETWEEN`, `IN`/`NOT_IN` (hỗ trợ chọn trực tiếp từ danh mục động CSDL), và `EQ`/`NEQ`.
 *   - Hiển thị tập hợp giá trị `IN` / `NOT_IN` theo mẫu phẳng `staff-001` (nền trong suốt, không đóng khung viên thuốc).
 */
export function ExpectedValueWidget({
  attributeMeta,
  operator,
  value,
  onChange,
}: ExpectedValueWidgetProps) {
  const [tagInput, setTagInput] = useState('');
  const resolvedType = attributeMeta?.valueType ?? attributeMeta?.type ?? 'STRING';
  const isNumeric = resolvedType === 'NUMBER';

  if (operator === 'TIME_BETWEEN') {
    return <TimeBetweenInput value={value} onChange={onChange} />;
  }

  if (operator === 'BETWEEN') {
    return (
      <BetweenBoundsInput
        isNumeric={isNumeric}
        options={attributeMeta?.options}
        value={value}
        onChange={onChange}
      />
    );
  }

  if (operator === 'EXISTS') {
    const boolVal = value === false || value === 'false' ? 'false' : 'true';
    return (
      <select
        aria-label="Điều kiện tồn tại thuộc tính"
        value={boolVal}
        onChange={(e) => onChange(e.target.value === 'true')}
        className="w-full min-h-11 sm:h-9 text-xs rounded-full border border-[#dddddd] px-3 bg-[#ffffff] text-[#222222]"
      >
        <option value="true">Phải có giá trị (Tồn tại)</option>
        <option value="false">Không có giá trị (Rỗng)</option>
      </select>
    );
  }

  if (resolvedType === 'BOOLEAN') {
    const booleanOptions =
      attributeMeta?.options && attributeMeta.options.length > 0
        ? attributeMeta.options
        : [
            { label: 'Đúng (Có)', value: true },
            { label: 'Sai (Không)', value: false },
          ];
    return (
      <select
        aria-label="Giá trị đúng hoặc sai kỳ vọng"
        value={String(value)}
        onChange={(e) => onChange(e.target.value === 'true')}
        className="w-full min-h-11 sm:h-9 text-xs rounded-full border border-[#dddddd] px-3 bg-[#ffffff] text-[#222222]"
      >
        {booleanOptions.map((opt) => (
          <option key={String(opt.value)} value={String(opt.value)}>
            {opt.label}
          </option>
        ))}
      </select>
    );
  }

  if (operator === 'IN' || operator === 'NOT_IN') {
    const arr = Array.isArray(value) ? (value as Array<string | number | boolean>) : [];
    const options = attributeMeta?.options ?? [];
    const optionLabelMap = new Map(options.map((opt) => [String(opt.value), opt.label]));

    const addValue = (rawVal: string | number | boolean) => {
      let nextItem: string | number | boolean = rawVal;
      if (isNumeric && typeof rawVal !== 'number') {
        const parsed = Number(rawVal);
        if (!Number.isFinite(parsed)) return;
        nextItem = parsed;
      }
      const alreadyExists = arr.some(
        (existing) => existing === nextItem || (isNumeric && Number(existing) === Number(nextItem)),
      );
      if (!alreadyExists) {
        onChange([...arr, nextItem]);
      }
    };

    const handleAddTag = () => {
      const trimmed = tagInput.trim();
      if (!trimmed) return;
      addValue(trimmed);
      setTagInput('');
    };

    return (
      <div className="space-y-2">
        {options.length > 0 ? (
          <select
            aria-label="Chọn giá trị thêm vào danh sách"
            value=""
            onChange={(e) => {
              if (!e.target.value) return;
              addValue(isNumeric ? Number(e.target.value) : e.target.value);
            }}
            className="w-full min-h-11 sm:h-9 text-xs rounded-full border border-[#dddddd] px-3 bg-[#ffffff] text-[#222222]"
          >
            <option value="">Chọn để thêm vào danh sách…</option>
            {options.map((opt) => (
              <option key={String(opt.value)} value={String(opt.value)}>
                {opt.label}
              </option>
            ))}
          </select>
        ) : (
          <div className="flex items-center gap-1.5">
            <Input
              type={isNumeric ? 'number' : 'text'}
              aria-label="Nhập giá trị thêm vào danh sách"
              value={tagInput}
              onChange={(e) => setTagInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  handleAddTag();
                }
              }}
              placeholder={isNumeric ? 'Nhập số rồi nhấn Enter…' : 'Thêm giá trị rồi nhấn Enter…'}
              className="min-h-11 sm:h-9 text-xs rounded-full border-[#dddddd] bg-[#ffffff]"
            />
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={handleAddTag}
              className="rounded-full border-[#dddddd] px-3 text-xs shrink-0"
            >
              Thêm
            </Button>
          </div>
        )}
        {arr.length > 0 && (
          <div className="flex flex-wrap items-center gap-3 pt-0.5">
            {arr.map((item, idx) => (
              <span
                key={`${String(item)}-${idx}`}
                className="staff-badge inline-flex items-center gap-1 bg-transparent border-0 p-0 text-xs font-semibold text-[#008489]"
              >
                <Tag
                  size={16}
                  strokeWidth={1.75}
                  className="text-[#008489] shrink-0"
                  aria-hidden="true"
                />
                <span>{optionLabelMap.get(String(item)) ?? String(item)}</span>
                <button
                  type="button"
                  aria-label={`Xóa giá trị ${String(item)}`}
                  onClick={() => onChange(arr.filter((_, i) => i !== idx))}
                  className="inline-flex min-h-11 min-w-11 sm:min-h-7 sm:min-w-7 items-center justify-center rounded-full text-[#717171] hover:bg-[#C13515]/10 hover:text-[#C13515] cursor-pointer"
                >
                  <X size={16} strokeWidth={1.75} aria-hidden="true" />
                </button>
              </span>
            ))}
          </div>
        )}
      </div>
    );
  }

  if (attributeMeta?.options && attributeMeta.options.length > 0) {
    const stringVal = value !== undefined && value !== null ? String(value) : '';
    const hasMatch = attributeMeta.options.some((opt) => String(opt.value) === stringVal);
    return (
      <select
        aria-label="Giá trị kỳ vọng"
        value={stringVal}
        onChange={(e) => onChange(isNumeric ? Number(e.target.value) : e.target.value)}
        className="w-full min-h-11 sm:h-9 text-xs rounded-full border border-[#dddddd] px-3 bg-[#ffffff] text-[#222222]"
      >
        {!hasMatch && stringVal && (
          <option value={stringVal}>{stringVal} (Giá trị hiện lưu)</option>
        )}
        {attributeMeta.options.map((opt) => (
          <option key={String(opt.value)} value={String(opt.value)}>
            {opt.label}
          </option>
        ))}
      </select>
    );
  }

  return (
    <Input
      aria-label="Giá trị kỳ vọng"
      type={isNumeric ? 'number' : 'text'}
      value={value !== undefined && value !== null ? String(value) : ''}
      onChange={(e) => onChange(isNumeric ? Number(e.target.value) : e.target.value)}
      placeholder="Nhập giá trị kỳ vọng…"
      className="min-h-11 sm:h-9 text-xs rounded-full border-[#dddddd] bg-[#ffffff] text-[#222222]"
    />
  );
}
