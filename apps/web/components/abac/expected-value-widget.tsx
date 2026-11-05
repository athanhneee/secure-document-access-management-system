'use client';

import { useId, useState } from 'react';
import { Clock, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import type { PolicyOperator, TimeWindow } from './abac-models';

export interface ExpectedValueWidgetProps {
  attributeMeta?:
    | {
        type: string;
        options?: Array<{ label: string; value: string | number | boolean }> | undefined;
      }
    | undefined;
  operator: PolicyOperator;
  value: unknown;
  onChange: (value: unknown) => void;
}

/**
 * Thuật toán: Điều Khiển Nhập Liệu Giá Trị Kỳ Vọng Đa Hình (Polymorphic Expected-Value Input Dispatch)
 * Mục đích: Tự động chọn giao diện nhập và ép kiểu chuẩn xác cho `expected` dựa trên tổ hợp `(attributeMeta.type, operator)`.
 * Cơ chế hoạt động:
 *   - Phân nhánh theo thứ tự ưu tiên: Khung thời gian `TIME_BETWEEN` (`TimeWindow` HH:mm) -> Khoảng hai cận `BETWEEN` (`[min, max]` cho cả tùy chọn ENUM lẫn số/chuỗi vô hướng) -> Kiểu logic `BOOLEAN` -> Tập hợp thẻ khử trùng lặp cho `IN` / `NOT_IN` -> Danh sách chọn định sẵn (`options`) -> Ô nhập văn bản/số mặc định.
 */
export function ExpectedValueWidget({
  attributeMeta,
  operator,
  value,
  onChange,
}: ExpectedValueWidgetProps) {
  const [tagInput, setTagInput] = useState('');
  const boundIdPrefix = useId();

  if (operator === 'TIME_BETWEEN') {
    const tw = (typeof value === 'object' && value !== null ? value : {}) as Partial<TimeWindow>;
    return (
      <div className="flex items-center gap-1.5">
        <Clock
          size={16}
          strokeWidth={1.75}
          className="text-[#717171] shrink-0"
          aria-hidden="true"
        />
        <Input
          type="time"
          aria-label="Giờ bắt đầu cho phép"
          value={tw.start || '08:00'}
          onChange={(e) =>
            onChange({
              start: e.target.value,
              end: tw.end || '17:30',
              timeZone: 'Asia/Ho_Chi_Minh',
            })
          }
          className="h-8 text-xs rounded-full border-[#dddddd] bg-[#ffffff] w-24 px-2"
        />
        <span className="text-[#717171] text-xs">đến</span>
        <Input
          type="time"
          aria-label="Giờ kết thúc cho phép"
          value={tw.end || '17:30'}
          onChange={(e) =>
            onChange({
              start: tw.start || '08:00',
              end: e.target.value,
              timeZone: 'Asia/Ho_Chi_Minh',
            })
          }
          className="h-8 text-xs rounded-full border-[#dddddd] bg-[#ffffff] w-24 px-2"
        />
      </div>
    );
  }

  if (operator === 'BETWEEN') {
    const fallbackBounds: [string | number | boolean, string | number | boolean] =
      attributeMeta?.options && attributeMeta.options.length > 0
        ? [
            attributeMeta.options[0]!.value,
            attributeMeta.options[attributeMeta.options.length - 1]!.value,
          ]
        : attributeMeta?.type === 'NUMBER'
          ? [0, 100]
          : ['', ''];

    const minVal =
      Array.isArray(value) && value.length >= 1 && value[0] !== undefined
        ? (value[0] as string | number | boolean)
        : fallbackBounds[0];
    const maxVal =
      Array.isArray(value) && value.length >= 2 && value[1] !== undefined
        ? (value[1] as string | number | boolean)
        : fallbackBounds[1];

    const minId = `${boundIdPrefix}-between-min`;
    const maxId = `${boundIdPrefix}-between-max`;
    const coerceBound = (raw: string) =>
      attributeMeta?.type === 'NUMBER' ? (raw === '' ? 0 : Number(raw)) : raw;

    if (attributeMeta?.options && attributeMeta.options.length > 0) {
      return (
        <div className="flex items-center gap-1.5">
          <label htmlFor={minId} className="sr-only">
            Giá trị cận dưới
          </label>
          <select
            id={minId}
            aria-label="Giá trị cận dưới"
            value={String(minVal)}
            onChange={(e) => onChange([coerceBound(e.target.value), maxVal])}
            className="flex-1 h-8 text-xs rounded-full border border-[#dddddd] px-2.5 bg-[#ffffff] text-[#222222]"
          >
            {attributeMeta.options.map((opt) => (
              <option key={`min-${String(opt.value)}`} value={String(opt.value)}>
                {opt.label}
              </option>
            ))}
          </select>
          <span className="text-[#717171] text-xs shrink-0">đến</span>
          <label htmlFor={maxId} className="sr-only">
            Giá trị cận trên
          </label>
          <select
            id={maxId}
            aria-label="Giá trị cận trên"
            value={String(maxVal)}
            onChange={(e) => onChange([minVal, coerceBound(e.target.value)])}
            className="flex-1 h-8 text-xs rounded-full border border-[#dddddd] px-2.5 bg-[#ffffff] text-[#222222]"
          >
            {attributeMeta.options.map((opt) => (
              <option key={`max-${String(opt.value)}`} value={String(opt.value)}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>
      );
    }

    return (
      <div className="flex items-center gap-1.5">
        <label htmlFor={minId} className="sr-only">
          Giá trị cận dưới
        </label>
        <Input
          id={minId}
          aria-label="Giá trị cận dưới"
          type={attributeMeta?.type === 'NUMBER' ? 'number' : 'text'}
          value={String(minVal)}
          onChange={(e) => onChange([coerceBound(e.target.value), maxVal])}
          placeholder="Cận dưới"
          className="h-8 text-xs rounded-full border-[#dddddd] bg-[#ffffff] text-[#222222]"
        />
        <span className="text-[#717171] text-xs shrink-0">đến</span>
        <label htmlFor={maxId} className="sr-only">
          Giá trị cận trên
        </label>
        <Input
          id={maxId}
          aria-label="Giá trị cận trên"
          type={attributeMeta?.type === 'NUMBER' ? 'number' : 'text'}
          value={String(maxVal)}
          onChange={(e) => onChange([minVal, coerceBound(e.target.value)])}
          placeholder="Cận trên"
          className="h-8 text-xs rounded-full border-[#dddddd] bg-[#ffffff] text-[#222222]"
        />
      </div>
    );
  }

  if (attributeMeta?.type === 'BOOLEAN') {
    return (
      <select
        aria-label="Giá trị logic mong đợi"
        value={String(value)}
        onChange={(e) => onChange(e.target.value === 'true')}
        className="w-full h-8 text-xs rounded-full border border-[#dddddd] px-2.5 bg-[#ffffff] text-[#222222]"
      >
        <option value="true">ĐÚNG (true / Tin cậy / Kích hoạt)</option>
        <option value="false">SAI (false / Ngoài mạng / Chưa bật)</option>
      </select>
    );
  }

  if (operator === 'IN' || operator === 'NOT_IN') {
    const arr = Array.isArray(value) ? (value as string[]) : [];
    const handleAddTag = () => {
      const trimmed = tagInput.trim();
      if (trimmed && !arr.includes(trimmed)) {
        onChange([...arr, trimmed]);
        setTagInput('');
      }
    };
    return (
      <div className="space-y-1.5">
        <div className="flex items-center gap-1.5">
          <Input
            aria-label="Nhập giá trị thêm vào danh sách"
            value={tagInput}
            onChange={(e) => setTagInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                handleAddTag();
              }
            }}
            placeholder="Thêm giá trị + Enter..."
            className="h-7 text-xs rounded-full border-[#dddddd] bg-[#ffffff]"
          />
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={handleAddTag}
            className="h-7 px-2.5 text-xs rounded-full border-[#dddddd]"
          >
            Thêm
          </Button>
        </div>
        {arr.length > 0 && (
          <div className="flex flex-wrap gap-2.5 pt-0.5">
            {arr.map((item, idx) => (
              // CONFLICT-RESOLVED: Phẳng hóa nhãn giá trị tập hợp sang chuẩn staff-001 (không bọc viền/nền trắng capsule) và bo tròn nút xóa chuẩn pill.
              <span
                key={idx}
                className="staff-badge inline-flex items-center gap-1 text-[11px] font-mono text-[#008489]"
              >
                <span className="dot dot-info" aria-hidden="true" />
                <span>{item}</span>
                <button
                  type="button"
                  aria-label={`Xóa giá trị ${item}`}
                  onClick={() => onChange(arr.filter((i) => i !== item))}
                  className="inline-flex h-5 w-5 items-center justify-center rounded-full text-[#717171] hover:bg-[#C13515]/10 hover:text-[#C13515] cursor-pointer"
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
    return (
      <select
        aria-label="Giá trị kỳ vọng"
        value={String(value)}
        onChange={(e) =>
          onChange(attributeMeta.type === 'NUMBER' ? Number(e.target.value) : e.target.value)
        }
        className="w-full h-8 text-xs rounded-full border border-[#dddddd] px-2.5 bg-[#ffffff] text-[#222222]"
      >
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
      type={attributeMeta?.type === 'NUMBER' ? 'number' : 'text'}
      value={value !== undefined && value !== null ? String(value) : ''}
      onChange={(e) =>
        onChange(attributeMeta?.type === 'NUMBER' ? Number(e.target.value) : e.target.value)
      }
      placeholder="Nhập giá trị mong đợi..."
      className="h-8 text-xs rounded-full border-[#dddddd] bg-[#ffffff] text-[#222222]"
    />
  );
}
