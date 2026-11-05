'use client';

import { Input } from '@/components/ui/input';
import type { VisualPolicyRule, TargetAction } from './abac-models';

interface PolicyMetaCardProps {
  rule: VisualPolicyRule;
  onUpdateRule: (newRule: VisualPolicyRule) => void;
}

export function PolicyMetaCard({ rule, onUpdateRule }: PolicyMetaCardProps) {
  return (
    <div className="p-4 rounded-[16px] border border-[#ebebeb] bg-[#ffffff] space-y-4 shadow-xs">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
        <div>
          <label
            htmlFor="abac-rule-code"
            className="block text-xs font-semibold text-[#717171] mb-1"
          >
            Mã Chính sách (Rule Code):
          </label>
          <Input
            id="abac-rule-code"
            value={rule.code}
            onChange={(e) => onUpdateRule({ ...rule, code: e.target.value.toUpperCase() })}
            placeholder="VD: POL_SECRET_RESTRICTED"
            className="h-8 text-xs font-mono font-semibold rounded-full bg-[#f7f7f7] border-[#dddddd] text-[#222222]"
          />
        </div>

        <div className="md:col-span-2">
          <label
            htmlFor="abac-rule-name"
            className="block text-xs font-semibold text-[#717171] mb-1"
          >
            Tên Chính sách:
          </label>
          <Input
            id="abac-rule-name"
            value={rule.name}
            onChange={(e) => onUpdateRule({ ...rule, name: e.target.value })}
            placeholder="Tên gợi nhớ quy tắc..."
            className="h-8 text-xs rounded-full border-[#dddddd] text-[#222222]"
          />
        </div>

        <fieldset className="border-0 p-0 m-0 min-w-0">
          <legend className="block text-xs font-semibold text-[#717171] mb-1">
            Hiệu lực Thực thi (Effect):
          </legend>
          <div className="flex gap-2">
            <button
              type="button"
              aria-pressed={rule.effect === 'PERMIT'}
              onClick={() => onUpdateRule({ ...rule, effect: 'PERMIT' })}
              className={`flex-1 h-8 rounded-full text-xs font-bold transition-all border cursor-pointer ${
                rule.effect === 'PERMIT'
                  ? 'bg-[#008A05]/10 border-[#008A05] text-[#008A05]'
                  : 'border-[#dddddd] text-[#717171] hover:bg-[#f7f7f7]'
              }`}
            >
              CHO PHÉP (PERMIT)
            </button>
            <button
              type="button"
              aria-pressed={rule.effect === 'DENY'}
              onClick={() => onUpdateRule({ ...rule, effect: 'DENY' })}
              className={`flex-1 h-8 rounded-full text-xs font-bold transition-all border cursor-pointer ${
                rule.effect === 'DENY'
                  ? 'bg-[#C13515]/10 border-[#C13515] text-[#C13515]'
                  : 'border-[#dddddd] text-[#717171] hover:bg-[#f7f7f7]'
              }`}
            >
              TỪ CHỐI (DENY)
            </button>
          </div>
        </fieldset>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
        <div>
          <label
            htmlFor="abac-target-action"
            className="block text-xs font-semibold text-[#717171] mb-1"
          >
            Hành động áp dụng (Target Action):
          </label>
          <select
            id="abac-target-action"
            value={rule.targetAction}
            onChange={(e) =>
              onUpdateRule({ ...rule, targetAction: e.target.value as TargetAction })
            }
            className="w-full h-8 text-xs rounded-full border border-[#dddddd] px-2.5 bg-[#ffffff] font-semibold text-[#222222]"
          >
            <option value="ALL">TẤT CẢ HÀNH ĐỘNG (ALL ACTIONS)</option>
            <option value="VIEW">XEM TRỰC TUYẾN (VIEW)</option>
            <option value="DOWNLOAD">TẢI BẢN SAO (DOWNLOAD)</option>
            <option value="SHARE">CHIA SẺ (SHARE)</option>
            <option value="MANAGE">QUẢN TRỊ (MANAGE)</option>
            <option value="DISCOVER">TÌM KIẾM (DISCOVER)</option>
          </select>
        </div>

        <div>
          <label
            htmlFor="abac-rule-priority"
            className="block text-xs font-semibold text-[#717171] mb-1"
          >
            Mức độ Ưu tiên (Priority: 1 - 100):
          </label>
          <Input
            id="abac-rule-priority"
            type="number"
            min="1"
            max="100"
            value={rule.priority}
            onChange={(e) => onUpdateRule({ ...rule, priority: Number(e.target.value) })}
            className="h-8 text-xs rounded-full border-[#dddddd] text-[#222222]"
          />
        </div>

        <div className="md:col-span-2">
          <label
            htmlFor="abac-rule-description"
            className="block text-xs font-semibold text-[#717171] mb-1"
          >
            Mô tả mục đích an ninh:
          </label>
          <Input
            id="abac-rule-description"
            value={rule.description}
            onChange={(e) => onUpdateRule({ ...rule, description: e.target.value })}
            placeholder="Giải thích ngắn gọn nghiệp vụ của chính sách..."
            className="h-8 text-xs rounded-full border-[#dddddd] text-[#222222]"
          />
        </div>
      </div>
    </div>
  );
}
