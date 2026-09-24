'use client';

import { useState } from 'react';
import {
  Shield,
  Layers,
  Code2,
  Play,
  Plus,
  Trash2,
  Copy,
  GripVertical,
  Check,
  Search,
  Sparkles,
  ArrowDown,
  ArrowUp,
  SlidersHorizontal,
  Clock,
  Network,
  KeyRound,
  FileCheck2,
  AlertTriangle,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';
import type {
  VisualPolicyRule,
  VisualCondition,
  VisualConditionGroup,
  VisualObligation,
  PolicyOperator,
  TargetAction,
  TimeWindow,
} from './abac-models';
import { ATTRIBUTE_REGISTRY, OPERATOR_LABELS } from './abac-models';
import { PRESET_POLICY_TEMPLATES, type PolicyTemplate } from './policy-templates';
import { PolicySimulatorDialog } from './policy-simulator-dialog';

export interface VisualPolicyBuilderProps {
  initialRule?: VisualPolicyRule | undefined;
  onSaveRule?: ((rule: VisualPolicyRule) => void) | undefined;
  onCancel?: (() => void) | undefined;
}

let conditionCounter = 0;
function createConditionId(): string {
  conditionCounter += 1;
  return `cond-${conditionCounter}`;
}

const DEFAULT_INITIAL_RULE: VisualPolicyRule = {
  id: 'rule-new-001',
  code: 'POL_DOCUMENT_ACCESS_RESTRICTED',
  name: 'Chính sách Truy cập Tài liệu Mật Tiêu chuẩn',
  description:
    'Yêu cầu nhân viên kết nối từ mạng nội bộ cơ quan và có cấp bậc an ninh phù hợp với cấp độ mật của tài liệu.',
  effect: 'PERMIT',
  priority: 10,
  targetResource: 'DOCUMENT',
  targetAction: 'VIEW',
  combiningAlgorithm: 'DENY_OVERRIDES',
  groups: [
    {
      id: 1,
      conditions: [
        {
          id: 'c-1',
          attribute: 'environment.trustedNetwork',
          operator: 'EQ',
          expected: true,
        },
        {
          id: 'c-2',
          attribute: 'subject.clearanceRank',
          operator: 'GTE',
          expected: 2,
        },
      ],
    },
  ],
  obligations: [{ type: 'REQUIRE_WATERMARK' }],
};

export function VisualPolicyBuilder({
  initialRule = DEFAULT_INITIAL_RULE,
  onSaveRule,
  onCancel,
}: VisualPolicyBuilderProps) {
  const [rule, setRule] = useState<VisualPolicyRule>(initialRule);
  const [viewMode, setViewMode] = useState<'visual' | 'json'>('visual');
  const [jsonText, setJsonText] = useState(() => JSON.stringify(initialRule, null, 2));
  const [jsonError, setJsonError] = useState<string | null>(null);

  // Search in attribute palette
  const [searchPalette, setSearchPalette] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<
    'ALL' | 'SUBJECT' | 'RESOURCE' | 'ENVIRONMENT'
  >('ALL');

  // Templates Dialog state
  const [templateDialogOpen, setTemplateDialogOpen] = useState(false);

  // Simulator Dialog state
  const [simulatorOpen, setSimulatorOpen] = useState(false);

  // Drag and drop state
  const [draggedCondition, setDraggedCondition] = useState<{
    groupId: number;
    conditionIndex: number;
  } | null>(null);

  // Copy JSON feedback
  const [copied, setCopied] = useState(false);

  // Sync to JSON text whenever rule changes
  const updateRule = (newRule: VisualPolicyRule) => {
    setRule(newRule);
    setJsonText(JSON.stringify(newRule, null, 2));
    setJsonError(null);
  };

  // Sync from JSON editor back to rule
  const handleJsonApply = () => {
    try {
      const parsed = JSON.parse(jsonText) as VisualPolicyRule;
      if (!parsed.code || !parsed.effect || !Array.isArray(parsed.groups)) {
        throw new Error('Cấu trúc JSON không hợp lệ: Thiếu các trường code, effect hoặc groups.');
      }
      setRule(parsed);
      setJsonError(null);
      setViewMode('visual');
    } catch (err) {
      setJsonError((err as Error).message);
    }
  };

  // Handle template selection
  const handleSelectTemplate = (tpl: PolicyTemplate) => {
    updateRule(JSON.parse(JSON.stringify(tpl.rule)));
    setTemplateDialogOpen(false);
  };

  // Condition manipulations
  const handleAddCondition = (groupId: number, attributeKey?: string) => {
    const attrKey = attributeKey || 'subject.clearanceRank';
    const meta = ATTRIBUTE_REGISTRY[attrKey];
    const newCondition: VisualCondition = {
      id: createConditionId(),
      attribute: attrKey,
      operator: meta ? meta.supportedOperators[0]! : 'EQ',
      expected: meta ? meta.defaultValue : '',
    };

    const newGroups = rule.groups.map((group) => {
      if (group.id === groupId) {
        return {
          ...group,
          conditions: [...group.conditions, newCondition],
        };
      }
      return group;
    });

    updateRule({ ...rule, groups: newGroups });
  };

  const handleRemoveCondition = (groupId: number, conditionId: string) => {
    const newGroups = rule.groups.map((group) => {
      if (group.id === groupId) {
        return {
          ...group,
          conditions: group.conditions.filter((c) => c.id !== conditionId),
        };
      }
      return group;
    });
    updateRule({ ...rule, groups: newGroups });
  };

  const handleDuplicateCondition = (groupId: number, condition: VisualCondition) => {
    const cloned: VisualCondition = {
      ...condition,
      id: createConditionId(),
    };
    const newGroups = rule.groups.map((group) => {
      if (group.id === groupId) {
        return {
          ...group,
          conditions: [...group.conditions, cloned],
        };
      }
      return group;
    });
    updateRule({ ...rule, groups: newGroups });
  };

  const handleMoveCondition = (groupId: number, index: number, direction: 'up' | 'down') => {
    const targetGroup = rule.groups.find((g) => g.id === groupId);
    if (!targetGroup) return;

    const newConditions = [...targetGroup.conditions];
    const targetIndex = direction === 'up' ? index - 1 : index + 1;
    if (targetIndex < 0 || targetIndex >= newConditions.length) return;

    const temp = newConditions[index]!;
    newConditions[index] = newConditions[targetIndex]!;
    newConditions[targetIndex] = temp;

    const newGroups = rule.groups.map((g) =>
      g.id === groupId ? { ...g, conditions: newConditions } : g,
    );
    updateRule({ ...rule, groups: newGroups });
  };

  const handleConditionChange = (
    groupId: number,
    conditionId: string,
    field: keyof VisualCondition,
    value: unknown,
  ) => {
    const newGroups = rule.groups.map((group) => {
      if (group.id === groupId) {
        const newConditions = group.conditions.map((cond) => {
          if (cond.id === conditionId) {
            if (field === 'attribute') {
              const meta = ATTRIBUTE_REGISTRY[value as string];
              return {
                ...cond,
                attribute: value as string,
                operator: meta ? meta.supportedOperators[0]! : 'EQ',
                expected: meta ? meta.defaultValue : '',
              };
            }
            return { ...cond, [field]: value };
          }
          return cond;
        });
        return { ...group, conditions: newConditions };
      }
      return group;
    });
    updateRule({ ...rule, groups: newGroups });
  };

  // Group manipulations (OR logic)
  const handleAddGroup = () => {
    const nextId = rule.groups.length > 0 ? Math.max(...rule.groups.map((g) => g.id)) + 1 : 1;
    const newGroup: VisualConditionGroup = {
      id: nextId,
      conditions: [
        {
          id: createConditionId(),
          attribute: 'environment.trustedNetwork',
          operator: 'EQ',
          expected: true,
        },
      ],
    };
    updateRule({ ...rule, groups: [...rule.groups, newGroup] });
  };

  const handleRemoveGroup = (groupId: number) => {
    if (rule.groups.length <= 1) {
      alert('Chính sách phải có ít nhất một nhóm điều kiện!');
      return;
    }
    const newGroups = rule.groups.filter((g) => g.id !== groupId);
    updateRule({ ...rule, groups: newGroups });
  };

  const handleDuplicateGroup = (group: VisualConditionGroup) => {
    const nextId = Math.max(...rule.groups.map((g) => g.id)) + 1;
    const clonedConditions: VisualCondition[] = group.conditions.map((c) => ({
      ...c,
      id: createConditionId(),
    }));
    const clonedGroup: VisualConditionGroup = {
      id: nextId,
      conditions: clonedConditions,
    };
    updateRule({ ...rule, groups: [...rule.groups, clonedGroup] });
  };

  // Obligations manipulations
  const hasObligation = (type: string) => {
    return rule.obligations.some((o) => o.type === type);
  };

  const toggleObligation = (type: string) => {
    let newObs: VisualObligation[];
    if (hasObligation(type)) {
      newObs = rule.obligations.filter((o) => o.type !== type);
    } else {
      if (type === 'MAX_SESSION_MINUTES') {
        newObs = [...rule.obligations, { type: 'MAX_SESSION_MINUTES', minutes: 30 }];
      } else if (type === 'REQUIRE_WATERMARK') {
        newObs = [...rule.obligations, { type: 'REQUIRE_WATERMARK' }];
      } else if (type === 'REQUIRE_MFA') {
        newObs = [...rule.obligations, { type: 'REQUIRE_MFA' }];
      } else if (type === 'FORBID_DOWNLOAD') {
        newObs = [...rule.obligations, { type: 'FORBID_DOWNLOAD' }];
      } else {
        newObs = [...rule.obligations, { type: 'NO_CACHE' }];
      }
    }
    updateRule({ ...rule, obligations: newObs });
  };

  const setSessionMinutes = (minutes: number) => {
    const newObs = rule.obligations.map((o) =>
      o.type === 'MAX_SESSION_MINUTES' ? { ...o, minutes } : o,
    );
    updateRule({ ...rule, obligations: newObs });
  };

  // Filtered attribute palette
  const filteredAttributes = Object.values(ATTRIBUTE_REGISTRY).filter((attr) => {
    const matchesCategory = selectedCategory === 'ALL' || attr.category === selectedCategory;
    const query = searchPalette.toLowerCase();
    const matchesSearch =
      attr.label.toLowerCase().includes(query) ||
      attr.key.toLowerCase().includes(query) ||
      attr.description.toLowerCase().includes(query);
    return matchesCategory && matchesSearch;
  });

  // Handle Drag & Drop between conditions
  const handleDropOnGroup = (targetGroupId: number) => {
    if (!draggedCondition) return;
    const { groupId: srcGroupId, conditionIndex: srcIndex } = draggedCondition;

    const srcGroup = rule.groups.find((g) => g.id === srcGroupId);
    if (!srcGroup) return;

    const condToMove = srcGroup.conditions[srcIndex];
    if (!condToMove) return;

    if (srcGroupId === targetGroupId) {
      // Same group, do nothing here (handled by index if needed)
      setDraggedCondition(null);
      return;
    }

    // Remove from source group, add to target group
    const newGroups = rule.groups.map((group) => {
      if (group.id === srcGroupId) {
        return {
          ...group,
          conditions: group.conditions.filter((_, idx) => idx !== srcIndex),
        };
      }
      if (group.id === targetGroupId) {
        return {
          ...group,
          conditions: [...group.conditions, condToMove],
        };
      }
      return group;
    });

    updateRule({ ...rule, groups: newGroups });
    setDraggedCondition(null);
  };

  return (
    <div className="flex flex-col h-full space-y-4">
      {/* Top Action Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 rounded-[16px] border border-[#ebebeb] bg-[#ffffff] shadow-xs">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-full bg-[#FF385C]/10 flex items-center justify-center text-[#FF385C]">
            <Shield className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold text-[#222222]">
                Trình Biên Tập Chính Sách ABAC Trực Quan (Visual Policy Builder)
              </h2>
              <Badge variant="info">No-Code DNF Engine</Badge>
            </div>
            <p className="text-xs text-[#717171]">
              Kéo thả khối điều kiện logic phân cấp (Disjunctive Normal Form: OR groups
              $\rightarrow$ AND conditions).
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Preset Templates */}
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => setTemplateDialogOpen(true)}
            className="rounded-full text-xs h-8 border-[#dddddd] hover:border-[#FF385C] flex items-center gap-1.5"
          >
            <Sparkles className="h-3.5 w-3.5 text-[#FF385C]" />
            <span>Mẫu dựng sẵn (Presets)</span>
          </Button>

          {/* Live Simulator */}
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => setSimulatorOpen(true)}
            className="rounded-full text-xs h-8 border-[#dddddd] hover:border-[#008A05] text-[#222222] flex items-center gap-1.5"
          >
            <Play className="h-3.5 w-3.5 text-[#008A05] fill-current" />
            <span>Kiểm thử PDP (Simulator)</span>
          </Button>

          {/* Toggle View Mode */}
          <div className="flex items-center bg-[#f7f7f7] border border-[#ebebeb] p-0.5 rounded-full">
            <button
              type="button"
              onClick={() => setViewMode('visual')}
              className={`px-3 py-1 text-xs font-semibold rounded-full transition-all flex items-center gap-1.5 ${
                viewMode === 'visual'
                  ? 'bg-white text-[#222222] shadow-xs'
                  : 'text-[#717171] hover:text-[#222222]'
              }`}
            >
              <Layers className="h-3.5 w-3.5" />
              <span>Khối Kéo Thả</span>
            </button>
            <button
              type="button"
              onClick={() => {
                setJsonText(JSON.stringify(rule, null, 2));
                setViewMode('json');
              }}
              className={`px-3 py-1 text-xs font-semibold rounded-full transition-all flex items-center gap-1.5 ${
                viewMode === 'json'
                  ? 'bg-white text-[#222222] shadow-xs'
                  : 'text-[#717171] hover:text-[#222222]'
              }`}
            >
              <Code2 className="h-3.5 w-3.5" />
              <span>JSON AST</span>
            </button>
          </div>

          {/* Save Rule */}
          {onSaveRule && (
            <Button
              type="button"
              size="sm"
              onClick={() => onSaveRule(rule)}
              className="rounded-full bg-[#FF385C] hover:bg-[#E03150] text-white text-xs h-8 px-4 font-semibold"
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

      {/* Meta Configuration Card */}
      <div className="p-4 rounded-[16px] border border-[#ebebeb] bg-[#ffffff] space-y-4 shadow-xs">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
          {/* Rule Code */}
          <div>
            <div className="text-[11px] font-semibold text-[#717171] mb-1">
              Mã Chính sách (Rule Code):
            </div>
            <Input
              value={rule.code}
              onChange={(e) => updateRule({ ...rule, code: e.target.value.toUpperCase() })}
              placeholder="VD: POL_SECRET_RESTRICTED"
              className="h-8 text-xs font-mono font-semibold rounded-full bg-[#f7f7f7] border-[#dddddd] text-[#222222]"
            />
          </div>

          {/* Rule Name */}
          <div className="md:col-span-2">
            <div className="text-[11px] font-semibold text-[#717171] mb-1">Tên Chính sách:</div>
            <Input
              value={rule.name}
              onChange={(e) => updateRule({ ...rule, name: e.target.value })}
              placeholder="Tên gợi nhớ quy tắc..."
              className="h-8 text-xs rounded-full border-[#dddddd] text-[#222222]"
            />
          </div>

          {/* Effect (PERMIT / DENY) */}
          <div>
            <div className="text-[11px] font-semibold text-[#717171] mb-1">
              Hiệu lực Thực thi (Effect):
            </div>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => updateRule({ ...rule, effect: 'PERMIT' })}
                className={`flex-1 h-8 rounded-full text-xs font-bold transition-all border ${
                  rule.effect === 'PERMIT'
                    ? 'bg-[#008A05]/10 border-[#008A05] text-[#008A05]'
                    : 'border-[#dddddd] text-[#717171] hover:bg-[#f7f7f7]'
                }`}
              >
                CHO PHÉP (PERMIT)
              </button>
              <button
                type="button"
                onClick={() => updateRule({ ...rule, effect: 'DENY' })}
                className={`flex-1 h-8 rounded-full text-xs font-bold transition-all border ${
                  rule.effect === 'DENY'
                    ? 'bg-[#C13515]/10 border-[#C13515] text-[#C13515]'
                    : 'border-[#dddddd] text-[#717171] hover:bg-[#f7f7f7]'
                }`}
              >
                TỪ CHỐI (DENY)
              </button>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
          {/* Target Action */}
          <div>
            <div className="text-[11px] font-semibold text-[#717171] mb-1">
              Hành động áp dụng (Target Action):
            </div>
            <select
              value={rule.targetAction}
              onChange={(e) =>
                updateRule({ ...rule, targetAction: e.target.value as TargetAction })
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

          {/* Priority */}
          <div>
            <div className="text-[11px] font-semibold text-[#717171] mb-1">
              Mức độ Ưu tiên (Priority: 1 - 100):
            </div>
            <Input
              type="number"
              min="1"
              max="100"
              value={rule.priority}
              onChange={(e) => updateRule({ ...rule, priority: Number(e.target.value) })}
              className="h-8 text-xs rounded-full border-[#dddddd] text-[#222222]"
            />
          </div>

          {/* Description */}
          <div className="md:col-span-2">
            <div className="text-[11px] font-semibold text-[#717171] mb-1">
              Mô tả mục đích an ninh:
            </div>
            <Input
              value={rule.description}
              onChange={(e) => updateRule({ ...rule, description: e.target.value })}
              placeholder="Giải thích ngắn gọn nghiệp vụ của chính sách..."
              className="h-8 text-xs rounded-full border-[#dddddd] text-[#222222]"
            />
          </div>
        </div>
      </div>

      {/* Main Workspace: Visual vs JSON Mode */}
      {viewMode === 'json' ? (
        <Card className="border-[#ebebeb] bg-[#ffffff] shadow-xs flex-1">
          <CardHeader className="pb-3 flex flex-row items-center justify-between">
            <div>
              <CardTitle className="text-base text-[#222222] flex items-center gap-2">
                <Code2 className="h-4 w-4 text-[#FF385C]" />
                <span>Trình Soạn Thảo JSON AST Trực Tiếp</span>
              </CardTitle>
              <CardDescription className="text-xs text-[#717171]">
                Xem hoặc chỉnh sửa trực tiếp biểu diễn trừu tượng (Abstract Syntax Tree) của quy
                tắc.
              </CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => {
                  navigator.clipboard.writeText(jsonText);
                  setCopied(true);
                  setTimeout(() => setCopied(false), 2000);
                }}
                className="rounded-full text-xs h-8 border-[#dddddd] flex items-center gap-1.5"
              >
                {copied ? (
                  <Check className="h-3.5 w-3.5 text-[#008A05]" />
                ) : (
                  <Copy className="h-3.5 w-3.5" />
                )}
                <span>{copied ? 'Đã sao chép!' : 'Sao chép JSON'}</span>
              </Button>
              <Button
                type="button"
                size="sm"
                onClick={handleJsonApply}
                className="rounded-full bg-[#FF385C] hover:bg-[#E03150] text-white text-xs h-8 font-semibold"
              >
                Cập nhật vào Trình Kéo Thả
              </Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            {jsonError && (
              <div className="p-3 rounded-[12px] bg-[#C13515]/10 border border-[#C13515]/30 text-xs text-[#C13515] flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 shrink-0" />
                <span>{jsonError}</span>
              </div>
            )}
            <textarea
              value={jsonText}
              onChange={(e) => setJsonText(e.target.value)}
              rows={20}
              className="w-full font-mono text-xs p-4 rounded-[16px] bg-[#222222] text-[#f7f7f7] border border-[#dddddd] focus:outline-none focus:border-[#FF385C]"
              spellCheck={false}
            />
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 flex-1 items-start">
          {/* LEFT: Attribute Palette (4 cols) */}
          <div className="lg:col-span-4 p-4 rounded-[16px] border border-[#ebebeb] bg-[#ffffff] space-y-3 shadow-xs">
            <div className="flex items-center justify-between border-b border-[#ebebeb] pb-2">
              <div className="flex items-center gap-1.5 font-bold text-xs text-[#222222]">
                <SlidersHorizontal className="h-4 w-4 text-[#FF385C]" />
                <span>Bảng Khối Thuộc Tính (Palette)</span>
              </div>
              <span className="text-[11px] text-[#717171]">
                {filteredAttributes.length} thuộc tính
              </span>
            </div>

            {/* Category Filter Pills */}
            <div className="flex flex-wrap gap-1 text-[11px]">
              {(['ALL', 'SUBJECT', 'RESOURCE', 'ENVIRONMENT'] as const).map((cat) => (
                <button
                  key={cat}
                  type="button"
                  onClick={() => setSelectedCategory(cat)}
                  className={`px-2.5 py-0.5 rounded-full font-medium transition-all ${
                    selectedCategory === cat
                      ? 'bg-[#222222] text-white'
                      : 'bg-[#f7f7f7] text-[#717171] hover:text-[#222222]'
                  }`}
                >
                  {cat === 'ALL'
                    ? 'Tất cả'
                    : cat === 'SUBJECT'
                      ? 'Chủ thể'
                      : cat === 'RESOURCE'
                        ? 'Tài nguyên'
                        : 'Môi trường'}
                </button>
              ))}
            </div>

            {/* Search Box */}
            <div className="relative">
              <Search className="h-3.5 w-3.5 absolute left-3 top-2.5 text-[#717171]" />
              <Input
                value={searchPalette}
                onChange={(e) => setSearchPalette(e.target.value)}
                placeholder="Tìm thuộc tính..."
                className="pl-8 h-8 text-xs rounded-full border-[#dddddd] bg-[#ffffff]"
              />
            </div>

            {/* Palette Items List */}
            <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
              {filteredAttributes.map((attr) => {
                const isSubject = attr.category === 'SUBJECT';
                const isResource = attr.category === 'RESOURCE';
                const isEnv = attr.category === 'ENVIRONMENT';

                return (
                  <div
                    key={attr.key}
                    draggable
                    onDragStart={(e) => {
                      e.dataTransfer.setData('text/plain', attr.key);
                    }}
                    className="group p-2.5 rounded-[12px] border border-[#ebebeb] bg-[#ffffff] hover:border-[#FF385C] hover:shadow-xs transition-all text-xs cursor-grab active:cursor-grabbing"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-center gap-1.5 font-semibold text-[#222222]">
                        {isSubject && <KeyRound className="h-3.5 w-3.5 text-[#008489]" />}
                        {isResource && <FileCheck2 className="h-3.5 w-3.5 text-[#FF385C]" />}
                        {isEnv && <Network className="h-3.5 w-3.5 text-[#008A05]" />}
                        <span>{attr.label}</span>
                      </div>
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        onClick={() => handleAddCondition(rule.groups[0]?.id ?? 1, attr.key)}
                        title="Thêm vào nhóm đầu tiên"
                        className="h-6 w-6 p-0 rounded-full hover:bg-[#FF385C]/10 hover:text-[#FF385C]"
                      >
                        <Plus className="h-3.5 w-3.5" />
                      </Button>
                    </div>

                    <div className="mt-1 flex items-center justify-between text-[11px] text-[#717171]">
                      <span className="font-mono text-[10px] text-[#717171]">{attr.key}</span>
                      <span className="text-[10px] uppercase font-bold text-[#b0b0b0]">
                        {attr.type}
                      </span>
                    </div>

                    <p className="mt-1 text-[11px] text-[#717171] line-clamp-2">
                      {attr.description}
                    </p>
                  </div>
                );
              })}
            </div>
          </div>

          {/* RIGHT: DNF Logic Canvas (8 cols) */}
          <div className="lg:col-span-8 space-y-4">
            {/* Condition Groups (OR Logic) */}
            <div className="space-y-4">
              {rule.groups.map((group, groupIdx) => (
                <div key={group.id} className="space-y-2">
                  {/* OR Connector between groups */}
                  {groupIdx > 0 && (
                    <div className="flex items-center justify-center my-2">
                      <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-[#E07912]/10 border border-[#E07912]/30 text-[#E07912] text-xs font-bold shadow-xs">
                        <span>HOẶC (OR) - Chỉ cần 1 nhóm điều kiện thỏa mãn</span>
                      </div>
                    </div>
                  )}

                  {/* Group Container */}
                  <div
                    onDragOver={(e) => e.preventDefault()}
                    onDrop={(e) => {
                      e.preventDefault();
                      const droppedAttrKey = e.dataTransfer.getData('text/plain');
                      if (droppedAttrKey && ATTRIBUTE_REGISTRY[droppedAttrKey]) {
                        handleAddCondition(group.id, droppedAttrKey);
                      } else {
                        handleDropOnGroup(group.id);
                      }
                    }}
                    className="p-4 rounded-[16px] border border-[#ebebeb] bg-[#ffffff] space-y-3 shadow-xs hover:border-[#dddddd] transition-all"
                  >
                    {/* Group Header */}
                    <div className="flex items-center justify-between border-b border-[#ebebeb] pb-2.5">
                      <div className="flex items-center gap-2">
                        <span className="h-6 w-6 rounded-full bg-[#222222] text-white flex items-center justify-center text-xs font-bold">
                          {groupIdx + 1}
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
                          onClick={() => handleAddCondition(group.id)}
                          className="h-7 text-xs rounded-full border-[#dddddd] hover:border-[#FF385C] flex items-center gap-1"
                        >
                          <Plus className="h-3 w-3 text-[#FF385C]" />
                          <span>Thêm AND</span>
                        </Button>

                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          onClick={() => handleDuplicateGroup(group)}
                          title="Nhân bản nhóm điều kiện"
                          className="h-7 w-7 p-0 rounded-full hover:bg-[#f7f7f7] text-[#717171]"
                        >
                          <Copy className="h-3.5 w-3.5" />
                        </Button>

                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          onClick={() => handleRemoveGroup(group.id)}
                          title="Xóa nhóm"
                          className="h-7 w-7 p-0 rounded-full hover:bg-[#C13515]/10 text-[#C13515]"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </div>

                    {/* Condition Blocks in Group */}
                    <div className="space-y-2">
                      {group.conditions.length === 0 ? (
                        <div className="p-6 text-center text-xs text-[#717171] border border-dashed border-[#dddddd] rounded-[12px]">
                          Chưa có điều kiện nào trong nhóm này. Hãy kéo thuộc tính từ cột trái hoặc
                          bấm &quot;Thêm AND&quot;.
                        </div>
                      ) : (
                        group.conditions.map((cond, condIdx) => {
                          const meta = ATTRIBUTE_REGISTRY[cond.attribute];

                          return (
                            <div
                              key={cond.id}
                              draggable
                              onDragStart={() => {
                                setDraggedCondition({
                                  groupId: group.id,
                                  conditionIndex: condIdx,
                                });
                              }}
                              className="group flex flex-col md:flex-row items-stretch md:items-center gap-2 p-2.5 rounded-[12px] bg-[#f7f7f7] border border-[#ebebeb] hover:border-[#dddddd] transition-all text-xs"
                            >
                              {/* Drag Handle & Order Controls */}
                              <div className="flex items-center gap-1 text-[#b0b0b0]">
                                <GripVertical className="h-4 w-4 cursor-grab" />
                                <div className="flex flex-col">
                                  <button
                                    type="button"
                                    onClick={() => handleMoveCondition(group.id, condIdx, 'up')}
                                    disabled={condIdx === 0}
                                    className="p-0.5 hover:text-[#222222] disabled:opacity-30"
                                  >
                                    <ArrowUp className="h-3 w-3" />
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => handleMoveCondition(group.id, condIdx, 'down')}
                                    disabled={condIdx === group.conditions.length - 1}
                                    className="p-0.5 hover:text-[#222222] disabled:opacity-30"
                                  >
                                    <ArrowDown className="h-3 w-3" />
                                  </button>
                                </div>
                              </div>

                              {/* Attribute Selector */}
                              <div className="flex-1 min-w-[200px]">
                                <select
                                  value={cond.attribute}
                                  onChange={(e) =>
                                    handleConditionChange(
                                      group.id,
                                      cond.id,
                                      'attribute',
                                      e.target.value,
                                    )
                                  }
                                  className="w-full h-8 text-xs font-medium rounded-full border border-[#dddddd] px-2.5 bg-[#ffffff] text-[#222222]"
                                >
                                  {Object.values(ATTRIBUTE_REGISTRY).map((a) => (
                                    <option key={a.key} value={a.key}>
                                      {a.label}
                                    </option>
                                  ))}
                                </select>
                              </div>

                              {/* Operator Selector */}
                              <div className="w-full md:w-[170px]">
                                <select
                                  value={cond.operator}
                                  onChange={(e) =>
                                    handleConditionChange(
                                      group.id,
                                      cond.id,
                                      'operator',
                                      e.target.value as PolicyOperator,
                                    )
                                  }
                                  className="w-full h-8 text-xs font-semibold rounded-full border border-[#dddddd] px-2.5 bg-[#ffffff] text-[#FF385C]"
                                >
                                  {(meta?.supportedOperators || ['EQ']).map((op) => (
                                    <option key={op} value={op}>
                                      {OPERATOR_LABELS[op] || op}
                                    </option>
                                  ))}
                                </select>
                              </div>

                              {/* Expected Value Input Widget */}
                              <div className="flex-1 min-w-[200px]">
                                <ExpectedValueWidget
                                  attributeMeta={meta}
                                  operator={cond.operator}
                                  value={cond.expected}
                                  onChange={(newVal) =>
                                    handleConditionChange(group.id, cond.id, 'expected', newVal)
                                  }
                                />
                              </div>

                              {/* Action Buttons: Duplicate & Delete */}
                              <div className="flex items-center gap-1 justify-end">
                                <Button
                                  type="button"
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => handleDuplicateCondition(group.id, cond)}
                                  title="Nhân bản điều kiện"
                                  className="h-7 w-7 p-0 rounded-full hover:bg-white text-[#717171]"
                                >
                                  <Copy className="h-3 w-3" />
                                </Button>
                                <Button
                                  type="button"
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => handleRemoveCondition(group.id, cond.id)}
                                  title="Xóa điều kiện"
                                  className="h-7 w-7 p-0 rounded-full hover:bg-[#C13515]/10 text-[#C13515]"
                                >
                                  <Trash2 className="h-3 w-3" />
                                </Button>
                              </div>
                            </div>
                          );
                        })
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Add Group Button (OR) */}
            <div className="flex justify-center pt-2">
              <Button
                type="button"
                variant="outline"
                onClick={handleAddGroup}
                className="rounded-full border-dashed border-[#dddddd] hover:border-[#FF385C] bg-[#ffffff] text-[#222222] text-xs h-9 px-6 flex items-center gap-2 shadow-xs"
              >
                <Plus className="h-4 w-4 text-[#FF385C]" />
                <span className="font-semibold">+ Thêm Nhóm Điều Kiện Mới (OR Clause)</span>
              </Button>
            </div>

            {/* Policy Obligations Card */}
            <div className="p-4 rounded-[16px] border border-[#ebebeb] bg-[#ffffff] space-y-3 shadow-xs">
              <div className="flex items-center justify-between border-b border-[#ebebeb] pb-2">
                <div className="flex items-center gap-2">
                  <FileCheck2 className="h-4 w-4 text-[#008A05]" />
                  <h3 className="font-bold text-xs text-[#222222]">
                    Nghĩa Vụ & Ràng Buộc Bắt Buộc Đi Kèm (Policy Obligations)
                  </h3>
                </div>
                <Badge variant="success">PDP Enforcement</Badge>
              </div>

              <p className="text-[11px] text-[#717171]">
                Các hành động bảo mật mà hệ thống và giao diện bắt buộc phải thực thi ngay khi quy
                tắc cho phép (PERMIT) hoặc từ chối (DENY).
              </p>

              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 text-xs">
                {/* Watermark */}
                <label
                  aria-label="Đóng Thủy Ấn (Watermark)"
                  className="flex items-start gap-2.5 p-3 rounded-[12px] border border-[#ebebeb] hover:bg-[#f7f7f7] cursor-pointer"
                >
                  <input
                    type="checkbox"
                    checked={hasObligation('REQUIRE_WATERMARK')}
                    onChange={() => toggleObligation('REQUIRE_WATERMARK')}
                    className="h-4 w-4 mt-0.5 rounded border-[#dddddd] accent-[#FF385C]"
                  />
                  <div>
                    <span className="font-bold text-[#222222] block">Đóng Thủy Ấn (Watermark)</span>
                    <span className="text-[11px] text-[#717171]">
                      Nhúng tên, IP, thời gian & mã token lên bản xem tài liệu.
                    </span>
                  </div>
                </label>

                {/* Require MFA */}
                <label
                  aria-label="Yêu Cầu MFA (FIDO2 / TOTP)"
                  className="flex items-start gap-2.5 p-3 rounded-[12px] border border-[#ebebeb] hover:bg-[#f7f7f7] cursor-pointer"
                >
                  <input
                    type="checkbox"
                    checked={hasObligation('REQUIRE_MFA')}
                    onChange={() => toggleObligation('REQUIRE_MFA')}
                    className="h-4 w-4 mt-0.5 rounded border-[#dddddd] accent-[#FF385C]"
                  />
                  <div>
                    <span className="font-bold text-[#222222] block">
                      Yêu Cầu MFA (FIDO2 / TOTP)
                    </span>
                    <span className="text-[11px] text-[#717171]">
                      Bắt buộc xác thực đa yếu tố cấp cao trước khi mở.
                    </span>
                  </div>
                </label>

                {/* Forbid Download */}
                <label
                  aria-label="Cấm Tải File (No Download)"
                  className="flex items-start gap-2.5 p-3 rounded-[12px] border border-[#ebebeb] hover:bg-[#f7f7f7] cursor-pointer"
                >
                  <input
                    type="checkbox"
                    checked={hasObligation('FORBID_DOWNLOAD')}
                    onChange={() => toggleObligation('FORBID_DOWNLOAD')}
                    className="h-4 w-4 mt-0.5 rounded border-[#dddddd] accent-[#FF385C]"
                  />
                  <div>
                    <span className="font-bold text-[#222222] block">
                      Cấm Tải File (No Download)
                    </span>
                    <span className="text-[11px] text-[#717171]">
                      Chỉ cho phép xem trực tuyến, vô hiệu hóa nút tải xuống.
                    </span>
                  </div>
                </label>

                {/* No Cache */}
                <label
                  aria-label="Không Lưu Bộ Đệm (No-Cache)"
                  className="flex items-start gap-2.5 p-3 rounded-[12px] border border-[#ebebeb] hover:bg-[#f7f7f7] cursor-pointer"
                >
                  <input
                    type="checkbox"
                    checked={hasObligation('NO_CACHE')}
                    onChange={() => toggleObligation('NO_CACHE')}
                    className="h-4 w-4 mt-0.5 rounded border-[#dddddd] accent-[#FF385C]"
                  />
                  <div>
                    <span className="font-bold text-[#222222] block">
                      Không Lưu Bộ Đệm (No-Cache)
                    </span>
                    <span className="text-[11px] text-[#717171]">
                      Gửi header cấm proxy và browser lưu trữ bộ đệm file.
                    </span>
                  </div>
                </label>

                {/* Max Session Minutes */}
                <div className="flex items-start gap-2.5 p-3 rounded-[12px] border border-[#ebebeb] sm:col-span-2">
                  <input
                    type="checkbox"
                    checked={hasObligation('MAX_SESSION_MINUTES')}
                    onChange={() => toggleObligation('MAX_SESSION_MINUTES')}
                    className="h-4 w-4 mt-1 rounded border-[#dddddd] accent-[#FF385C]"
                  />
                  <div className="flex-1 space-y-1">
                    <span className="font-bold text-[#222222] block">
                      Giới Hạn Thời Gian Phiên (Max Session Time)
                    </span>
                    <span className="text-[11px] text-[#717171] block">
                      Tự động thu hồi quyền xem sau số phút chỉ định:
                    </span>
                    {hasObligation('MAX_SESSION_MINUTES') && (
                      <div className="flex items-center gap-2 pt-1">
                        <Input
                          type="number"
                          min="5"
                          max="240"
                          value={
                            (
                              rule.obligations.find((o) => o.type === 'MAX_SESSION_MINUTES') as
                                { minutes: number } | undefined
                            )?.minutes || 30
                          }
                          onChange={(e) => setSessionMinutes(Number(e.target.value))}
                          className="w-24 h-7 text-xs rounded-full border-[#dddddd]"
                        />
                        <span className="text-[11px] text-[#717171]">phút</span>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Preset Templates Dialog */}
      <Dialog open={templateDialogOpen} onOpenChange={setTemplateDialogOpen}>
        <DialogContent className="max-w-3xl bg-[#ffffff] border-[#ebebeb] p-6 text-[#222222]">
          <DialogHeader>
            <div className="flex items-center gap-2">
              <Sparkles className="h-5 w-5 text-[#FF385C]" />
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
                    onClick={() => handleSelectTemplate(tpl)}
                    className="rounded-full bg-[#FF385C] hover:bg-[#E03150] text-white text-xs h-7 px-3.5 font-semibold"
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

      {/* Simulator Dialog */}
      <PolicySimulatorDialog
        open={simulatorOpen}
        onOpenChange={setSimulatorOpen}
        activeRule={rule}
      />
    </div>
  );
}

// Widget for rendering appropriate input based on attribute type and operator
interface ExpectedValueWidgetProps {
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

function ExpectedValueWidget({
  attributeMeta,
  operator,
  value,
  onChange,
}: ExpectedValueWidgetProps) {
  const [tagInput, setTagInput] = useState('');

  // 1. Time Between Window
  if (operator === 'TIME_BETWEEN') {
    const tw = (typeof value === 'object' && value !== null ? value : {}) as Partial<TimeWindow>;
    return (
      <div className="flex items-center gap-1.5">
        <Clock className="h-3.5 w-3.5 text-[#717171] shrink-0" />
        <Input
          type="time"
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

  // 2. Boolean attributes
  if (attributeMeta?.type === 'BOOLEAN') {
    return (
      <select
        value={String(value)}
        onChange={(e) => onChange(e.target.value === 'true')}
        className="w-full h-8 text-xs rounded-full border border-[#dddddd] px-2.5 bg-[#ffffff] text-[#222222]"
      >
        <option value="true">ĐÚNG (true / Tin cậy / Kích hoạt)</option>
        <option value="false">SAI (false / Ngoài mạng / Chưa bật)</option>
      </select>
    );
  }

  // 3. IN / NOT_IN array values
  if (operator === 'IN' || operator === 'NOT_IN') {
    const arr = Array.isArray(value) ? (value as string[]) : [];

    const handleAddTag = () => {
      const trimmed = tagInput.trim();
      if (trimmed && !arr.includes(trimmed)) {
        onChange([...arr, trimmed]);
        setTagInput('');
      }
    };

    const handleRemoveTag = (item: string) => {
      onChange(arr.filter((i) => i !== item));
    };

    return (
      <div className="space-y-1.5">
        <div className="flex items-center gap-1.5">
          <Input
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
          <div className="flex flex-wrap gap-1">
            {arr.map((item, idx) => (
              <span
                key={idx}
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-white border border-[#ebebeb] text-[11px] font-mono text-[#222222]"
              >
                <span>{item}</span>
                <button
                  type="button"
                  onClick={() => handleRemoveTag(item)}
                  className="hover:text-[#C13515]"
                >
                  ×
                </button>
              </span>
            ))}
          </div>
        )}
      </div>
    );
  }

  // 4. Predefined Select Options (Clearance rank, Department, Category)
  if (attributeMeta?.options && attributeMeta.options.length > 0) {
    return (
      <select
        value={String(value)}
        onChange={(e) => {
          const val = attributeMeta.type === 'NUMBER' ? Number(e.target.value) : e.target.value;
          onChange(val);
        }}
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

  // 5. Default Text / Number / IP input
  return (
    <Input
      type={attributeMeta?.type === 'NUMBER' ? 'number' : 'text'}
      value={value !== undefined && value !== null ? String(value) : ''}
      onChange={(e) => {
        const val = attributeMeta?.type === 'NUMBER' ? Number(e.target.value) : e.target.value;
        onChange(val);
      }}
      placeholder="Nhập giá trị mong đợi..."
      className="h-8 text-xs rounded-full border-[#dddddd] bg-[#ffffff] text-[#222222]"
    />
  );
}
