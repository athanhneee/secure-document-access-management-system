'use client';

import { Shield, Sparkles, Play, Layers, Code2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';
import type { VisualPolicyRule } from './abac-models';
import { PRESET_POLICY_TEMPLATES, type PolicyTemplate } from './policy-templates';
import { PolicyMetaCard } from './policy-meta-card';

interface PolicyPresetsBarProps {
  rule: VisualPolicyRule;
  viewMode: 'visual' | 'json';
  onSetViewMode: (mode: 'visual' | 'json') => void;
  onUpdateRule: (newRule: VisualPolicyRule) => void;
  onOpenSimulator: () => void;
  templateDialogOpen: boolean;
  onTemplateDialogChange: (open: boolean) => void;
  onSelectTemplate: (tpl: PolicyTemplate) => void;
  onSaveRule?: ((rule: VisualPolicyRule) => void) | undefined;
  onCancel?: (() => void) | undefined;
}

export function PolicyPresetsBar({
  rule,
  viewMode,
  onSetViewMode,
  onUpdateRule,
  onOpenSimulator,
  templateDialogOpen,
  onTemplateDialogChange,
  onSelectTemplate,
  onSaveRule,
  onCancel,
}: PolicyPresetsBarProps) {
  return (
    <>
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 rounded-[16px] border border-[#ebebeb] bg-[#ffffff] shadow-xs">
        <div className="flex items-center gap-3">
          {/* // CONFLICT-RESOLVED: Loại bỏ hộp tròn nền màu nhạt bg-[#FF385C]/10 bọc quanh icon Shield theo rules/ui-design-system.md. */}
          <Shield
            size={24}
            strokeWidth={1.75}
            className="text-[#FF385C] shrink-0"
            aria-hidden="true"
          />
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold text-[#222222]">
                Trình Biên Tập Chính Sách ABAC Trực Quan (Visual Policy Builder)
              </h2>
              <Badge variant="info">No-Code DNF Engine</Badge>
            </div>
            <p className="text-xs text-[#717171]">
              Kéo thả khối điều kiện logic phân cấp (Disjunctive Normal Form: OR groups → AND
              conditions).
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => onTemplateDialogChange(true)}
            className="rounded-full text-xs h-8 border-[#dddddd] hover:border-[#FF385C] flex items-center gap-1.5"
          >
            <Sparkles size={16} strokeWidth={1.75} className="text-[#FF385C]" aria-hidden="true" />
            <span>Mẫu dựng sẵn (Presets)</span>
          </Button>

          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={onOpenSimulator}
            className="rounded-full text-xs h-8 border-[#dddddd] hover:border-[#008A05] text-[#222222] flex items-center gap-1.5"
          >
            <Play
              size={16}
              strokeWidth={1.75}
              className="text-[#008A05] fill-current"
              aria-hidden="true"
            />
            <span>Kiểm thử PDP (Simulator)</span>
          </Button>

          <div className="flex items-center bg-[#f7f7f7] border border-[#ebebeb] p-0.5 rounded-full">
            <button
              type="button"
              onClick={() => onSetViewMode('visual')}
              className={`px-3 py-1 text-xs font-semibold rounded-full transition-all flex items-center gap-1.5 cursor-pointer ${
                viewMode === 'visual'
                  ? 'bg-white text-[#222222] shadow-xs'
                  : 'text-[#717171] hover:text-[#222222]'
              }`}
            >
              <Layers size={16} strokeWidth={1.75} aria-hidden="true" />
              <span>Khối Kéo Thả</span>
            </button>
            <button
              type="button"
              onClick={() => onSetViewMode('json')}
              className={`px-3 py-1 text-xs font-semibold rounded-full transition-all flex items-center gap-1.5 cursor-pointer ${
                viewMode === 'json'
                  ? 'bg-white text-[#222222] shadow-xs'
                  : 'text-[#717171] hover:text-[#222222]'
              }`}
            >
              <Code2 size={16} strokeWidth={1.75} aria-hidden="true" />
              <span>JSON AST</span>
            </button>
          </div>

          {onSaveRule && (
            <Button
              type="button"
              size="sm"
              onClick={() => onSaveRule(rule)}
              className="rounded-full bg-[#FF385C] hover:bg-[#E31C5F] text-white text-xs h-8 px-4 font-semibold"
            >
              Lưu Chính Sách
            </Button>
          )}

          {onCancel && (
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={onCancel}
              className="rounded-full text-xs h-8 border-[#dddddd]"
            >
              Đóng
            </Button>
          )}
        </div>
      </div>

      <PolicyMetaCard rule={rule} onUpdateRule={onUpdateRule} />

      <Dialog open={templateDialogOpen} onOpenChange={onTemplateDialogChange}>
        <DialogContent className="max-w-3xl bg-[#ffffff] border-[#ebebeb] p-6 text-[#222222]">
          <DialogHeader>
            <div className="flex items-center gap-2">
              <Sparkles
                size={20}
                strokeWidth={1.75}
                className="text-[#FF385C]"
                aria-hidden="true"
              />
              <DialogTitle className="text-base font-bold text-[#222222]">
                Thư Viện Mẫu Chính Sách Dựng Sẵn (Policy Presets)
              </DialogTitle>
            </div>
            <DialogDescription className="text-xs text-[#717171]">
              Chọn nhanh cấu hình chính sách mẫu tiêu chuẩn để bắt đầu chỉnh sửa kéo thả.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-3 max-h-[60vh] overflow-y-auto pr-1">
            {PRESET_POLICY_TEMPLATES.map((tpl) => (
              <div
                key={tpl.id}
                className="p-3.5 rounded-[16px] border border-[#ebebeb] hover:border-[#FF385C] bg-[#ffffff] transition-all space-y-2"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-xs text-[#222222]">{tpl.name}</span>
                    <Badge variant="primary">{tpl.badge}</Badge>
                  </div>
                  <Button
                    type="button"
                    size="sm"
                    onClick={() => onSelectTemplate(tpl)}
                    className="rounded-full bg-[#FF385C] hover:bg-[#E31C5F] text-white text-xs h-7 px-3.5 font-semibold"
                  >
                    Áp dụng mẫu này
                  </Button>
                </div>
                <p className="text-xs text-[#717171]">{tpl.summary}</p>
                <div className="flex flex-wrap gap-2 text-[11px] text-[#717171] font-mono">
                  <span>Mã: {tpl.rule.code}</span>
                  <span>•</span>
                  <span>
                    Hiệu lực:{' '}
                    <strong
                      className={tpl.rule.effect === 'PERMIT' ? 'text-[#008A05]' : 'text-[#C13515]'}
                    >
                      {tpl.rule.effect}
                    </strong>
                  </span>
                  <span>•</span>
                  <span>Ưu tiên: {tpl.rule.priority}</span>
                </div>
              </div>
            ))}
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
