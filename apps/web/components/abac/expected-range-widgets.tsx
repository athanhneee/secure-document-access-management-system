'use client';

import { useId } from 'react';
import { Clock } from 'lucide-react';
import { Input } from '@/components/ui/input';
import type { TimeWindow } from './abac-models';

interface TimeBetweenInputProps {
  value: unknown;
  onChange: (value: TimeWindow) => void;
}

export function TimeBetweenInput({ value, onChange }: TimeBetweenInputProps) {
  const tw = (typeof value === 'object' && value !== null ? value : {}) as Partial<TimeWindow>;

  return (
    <div className="flex flex-wrap items-center gap-1.5">
      <Clock size={16} strokeWidth={1.75} className="text-[#717171] shrink-0" aria-hidden="true" />
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
        className="min-h-11 sm:h-9 text-xs rounded-full border-[#dddddd] bg-[#ffffff] w-28 px-3"
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
        className="min-h-11 sm:h-9 text-xs rounded-full border-[#dddddd] bg-[#ffffff] w-28 px-3"
      />
    </div>
  );
}

interface BetweenBoundsInputProps {
  isNumeric: boolean;
  options?: Array<{ label: string; value: string | number | boolean }> | undefined;
  value: unknown;
  onChange: (value: [string | number | boolean, string | number | boolean]) => void;
}

/**
 * Thuật toán: Chuẩn Hóa Cặp Cận `[min, max]` Cho Toán Tử Khoảng `BETWEEN` (`BetweenBoundsInput`)
 * Mục đích: Bảo toàn kiểu dữ liệu số học hoặc giá trị tùy chọn định sẵn cho cả hai biên cận dưới và cận trên.
 */
export function BetweenBoundsInput({
  isNumeric,
  options,
  value,
  onChange,
}: BetweenBoundsInputProps) {
  const boundIdPrefix = useId();
  const fallbackBounds: [string | number | boolean, string | number | boolean] =
    options && options.length > 0
      ? [options[0]!.value, options[options.length - 1]!.value]
      : isNumeric
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
  const coerceBound = (raw: string) => (isNumeric ? (raw === '' ? 0 : Number(raw)) : raw);

  if (options && options.length > 0) {
    return (
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-1.5">
        <label htmlFor={minId} className="sr-only">
          Giá trị tối thiểu
        </label>
        <select
          id={minId}
          aria-label="Giá trị tối thiểu"
          value={String(minVal)}
          onChange={(e) => onChange([coerceBound(e.target.value), maxVal])}
          className="flex-1 min-h-11 sm:h-9 text-xs rounded-full border border-[#dddddd] px-3 bg-[#ffffff] text-[#222222]"
        >
          {options.map((opt) => (
            <option key={`min-${String(opt.value)}`} value={String(opt.value)}>
              {opt.label}
            </option>
          ))}
        </select>
        <span className="text-[#717171] text-xs shrink-0 text-center">đến</span>
        <label htmlFor={maxId} className="sr-only">
          Giá trị tối đa
        </label>
        <select
          id={maxId}
          aria-label="Giá trị tối đa"
          value={String(maxVal)}
          onChange={(e) => onChange([minVal, coerceBound(e.target.value)])}
          className="flex-1 min-h-11 sm:h-9 text-xs rounded-full border border-[#dddddd] px-3 bg-[#ffffff] text-[#222222]"
        >
          {options.map((opt) => (
            <option key={`max-${String(opt.value)}`} value={String(opt.value)}>
              {opt.label}
            </option>
          ))}
        </select>
      </div>
    );
  }

  return (
    <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-1.5">
      <label htmlFor={minId} className="sr-only">
        Giá trị tối thiểu
      </label>
      <Input
        id={minId}
        aria-label="Giá trị tối thiểu"
        type={isNumeric ? 'number' : 'text'}
        value={String(minVal)}
        onChange={(e) => onChange([coerceBound(e.target.value), maxVal])}
        placeholder="Từ"
        className="min-h-11 sm:h-9 text-xs rounded-full border-[#dddddd] bg-[#ffffff] text-[#222222]"
      />
      <span className="text-[#717171] text-xs shrink-0 text-center">đến</span>
      <label htmlFor={maxId} className="sr-only">
        Giá trị tối đa
      </label>
      <Input
        id={maxId}
        aria-label="Giá trị tối đa"
        type={isNumeric ? 'number' : 'text'}
        value={String(maxVal)}
        onChange={(e) => onChange([minVal, coerceBound(e.target.value)])}
        placeholder="Đến"
        className="min-h-11 sm:h-9 text-xs rounded-full border-[#dddddd] bg-[#ffffff] text-[#222222]"
      />
    </div>
  );
}
