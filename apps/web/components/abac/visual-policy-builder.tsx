'use client';

import { useState } from 'react';
import { AlertTriangle, Plus } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import type { VisualPolicyRule, VisualCondition, VisualConditionGroup } from './abac-models';
import type { PolicyTemplate } from './policy-templates';
import { PolicySimulatorDialog } from './policy-simulator-dialog';
import {
  DEFAULT_INITIAL_RULE,
  serializePolicyAst,
  deserializePolicyAst,
  clonePolicyTemplate,
  addConditionToGroup,
  removeConditionFromGroup,
  duplicateConditionInGroup,
  moveConditionInGroup,
  updateConditionField,
  addDisjunctiveGroup,
  duplicateDisjunctiveGroup,
  relocateConditionAcrossGroups,
  toggleRuleObligation,
  filterAttributePalette,
} from './policy-ast-helpers';
import { PolicyPresetsBar } from './policy-presets-bar';
import { PolicyJsonPreview } from './policy-json-preview';
import { AttributePalettePanel } from './attribute-palette-panel';
import { ConditionGroupCard } from './condition-group-card';
import { ObligationsPanel } from './obligations-panel';

export interface VisualPolicyBuilderProps {
  initialRule?: VisualPolicyRule | undefined;
  onSaveRule?: ((rule: VisualPolicyRule) => void) | undefined;
  onCancel?: (() => void) | undefined;
}

/**
 * Algorithm / Thuật toán: Trình Biên Tập Trực Quan & Chuyển Đổi Hai Chiều AST <-> DNF (Bidirectional DNF/AST Policy Builder)
 * Mục đích: Cung cấp môi trường kéo-thả No-Code xây dựng quy tắc ABAC dưới dạng Chuẩn Tuyển (DNF: OR của các nhóm liên hội AND) đồng bộ tức thời với JSON AST.
 * Cơ chế hoạt động:
 *   - Duy trì bất biến kiểu dữ liệu trên từng nút điều kiện dựa vào `ATTRIBUTE_REGISTRY`.
 *   - Điều phối đồng bộ hai chiều giữa cây giao diện kéo-thả, bộ soạn thảo JSON AST và trình giả lập PDP trực tiếp.
 */
export function VisualPolicyBuilder({
  initialRule = DEFAULT_INITIAL_RULE,
  onSaveRule,
  onCancel,
}: VisualPolicyBuilderProps) {
  const [rule, setRule] = useState<VisualPolicyRule>(initialRule);
  const [viewMode, setViewMode] = useState<'visual' | 'json'>('visual');
  const [jsonText, setJsonText] = useState(() => serializePolicyAst(initialRule));
  const [jsonError, setJsonError] = useState<string | null>(null);
  const [builderWarning, setBuilderWarning] = useState<string | null>(null);
  const [searchPalette, setSearchPalette] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<
    'ALL' | 'SUBJECT' | 'RESOURCE' | 'ENVIRONMENT'
  >('ALL');
  const [templateDialogOpen, setTemplateDialogOpen] = useState(false);
  const [simulatorOpen, setSimulatorOpen] = useState(false);
  const [draggedCondition, setDraggedCondition] = useState<{
    groupId: number;
    conditionIndex: number;
  } | null>(null);

  const updateRule = (newRule: VisualPolicyRule) => {
    setRule(newRule);
    setJsonText(serializePolicyAst(newRule));
    setJsonError(null);
    setBuilderWarning(null);
  };

  const handleSetViewMode = (mode: 'visual' | 'json') => {
    if (mode === 'json') setJsonText(serializePolicyAst(rule));
    setViewMode(mode);
  };

  const handleJsonApply = () => {
    try {
      const parsed = deserializePolicyAst(jsonText);
      setRule(parsed);
      setJsonError(null);
      setBuilderWarning(null);
      setViewMode('visual');
    } catch (err) {
      setJsonError((err as Error).message);
    }
  };

  const handleSelectTemplate = (tpl: PolicyTemplate) => {
    updateRule(clonePolicyTemplate(tpl));
    setTemplateDialogOpen(false);
  };

  const handleMoveCondition = (groupId: number, index: number, direction: 'up' | 'down') => {
    const moved = moveConditionInGroup(rule, groupId, index, direction);
    if (moved) updateRule(moved);
  };

  const handleConditionChange = (
    groupId: number,
    conditionId: string,
    field: keyof VisualCondition,
    value: unknown,
  ) => {
    updateRule(updateConditionField(rule, groupId, conditionId, field, value));
  };

  const handleRemoveGroup = (groupId: number) => {
    if (rule.groups.length <= 1) {
      // CONFLICT-RESOLVED: Thay thế hộp thoại trình duyệt thô window.alert bằng cảnh báo nội dòng Alert chuẩn WCAG.
      setBuilderWarning('Chính sách ABAC bắt buộc phải duy trì ít nhất một nhóm điều kiện (AND).');
      return;
    }
    updateRule({ ...rule, groups: rule.groups.filter((g) => g.id !== groupId) });
  };

  const handleDropOnGroup = (targetGroupId: number) => {
    if (!draggedCondition) return;
    const relocated = relocateConditionAcrossGroups(
      rule,
      draggedCondition.groupId,
      draggedCondition.conditionIndex,
      targetGroupId,
    );
    if (relocated) updateRule(relocated);
    setDraggedCondition(null);
  };

  const filteredAttributes = filterAttributePalette(selectedCategory, searchPalette);

  return (
    <div className="flex flex-col h-full space-y-4">
      <PolicyPresetsBar
        rule={rule}
        viewMode={viewMode}
        onSetViewMode={handleSetViewMode}
        onUpdateRule={updateRule}
        onOpenSimulator={() => setSimulatorOpen(true)}
        templateDialogOpen={templateDialogOpen}
        onTemplateDialogChange={setTemplateDialogOpen}
        onSelectTemplate={handleSelectTemplate}
        onSaveRule={onSaveRule}
        onCancel={onCancel}
      />

      {builderWarning && (
        <Alert variant="warning" className="text-xs">
          <AlertTriangle
            size={16}
            strokeWidth={1.75}
            className="shrink-0 text-[#E07912]"
            aria-hidden="true"
          />
          <AlertDescription className="ml-2">{builderWarning}</AlertDescription>
        </Alert>
      )}

      {viewMode === 'json' ? (
        <PolicyJsonPreview
          jsonText={jsonText}
          jsonError={jsonError}
          onChangeJsonText={setJsonText}
          onApplyJson={handleJsonApply}
        />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 flex-1 items-start">
          <AttributePalettePanel
            filteredAttributes={filteredAttributes}
            selectedCategory={selectedCategory}
            onSelectCategory={setSelectedCategory}
            searchPalette={searchPalette}
            onSearchChange={setSearchPalette}
            firstGroupId={rule.groups[0]?.id ?? 1}
            onAddAttributeToFirstGroup={(gid, key) =>
              updateRule(addConditionToGroup(rule, gid, key))
            }
          />

          <div className="lg:col-span-8 space-y-4">
            <div className="space-y-4">
              {rule.groups.map((group: VisualConditionGroup, groupIdx: number) => (
                <ConditionGroupCard
                  key={group.id}
                  group={group}
                  groupIdx={groupIdx}
                  onAddCondition={(gid, key) => updateRule(addConditionToGroup(rule, gid, key))}
                  onDuplicateGroup={(g) => updateRule(duplicateDisjunctiveGroup(rule, g))}
                  onRemoveGroup={handleRemoveGroup}
                  onDropConditionOnGroup={handleDropOnGroup}
                  onDragStartCondition={(groupId, conditionIndex) =>
                    setDraggedCondition({ groupId, conditionIndex })
                  }
                  onMoveCondition={handleMoveCondition}
                  onChangeConditionField={handleConditionChange}
                  onDuplicateCondition={(gid, cond) =>
                    updateRule(duplicateConditionInGroup(rule, gid, cond))
                  }
                  onRemoveCondition={(gid, cid) =>
                    updateRule(removeConditionFromGroup(rule, gid, cid))
                  }
                />
              ))}
            </div>

            <div className="flex justify-center pt-2">
              <Button
                type="button"
                variant="outline"
                onClick={() => updateRule(addDisjunctiveGroup(rule))}
                className="rounded-full border-dashed border-[#dddddd] hover:border-[#FF385C] bg-[#ffffff] text-[#222222] text-xs h-9 px-6 flex items-center gap-2 shadow-xs"
              >
                <Plus size={16} strokeWidth={2} className="text-[#FF385C]" aria-hidden="true" />
                <span className="font-semibold">Thêm Nhóm Điều Kiện Mới (OR Clause)</span>
              </Button>
            </div>

            <ObligationsPanel
              obligations={rule.obligations}
              onToggleObligation={(type) =>
                updateRule({ ...rule, obligations: toggleRuleObligation(rule.obligations, type) })
              }
              onSetSessionMinutes={(minutes) =>
                updateRule({
                  ...rule,
                  obligations: rule.obligations.map((o) =>
                    o.type === 'MAX_SESSION_MINUTES' ? { ...o, minutes } : o,
                  ),
                })
              }
            />
          </div>
        </div>
      )}

      <PolicySimulatorDialog
        open={simulatorOpen}
        onOpenChange={setSimulatorOpen}
        activeRule={rule}
      />
    </div>
  );
}
