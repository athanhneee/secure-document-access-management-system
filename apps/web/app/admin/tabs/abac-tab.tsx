'use client';

import { useState } from 'react';
import { Check, Play, Plus, ShieldCheck } from 'lucide-react';
import type { VisualPolicyRule } from '@/components/abac/abac-models';
import { PolicySimulatorDialog } from '@/components/abac/policy-simulator-dialog';
import { PRESET_POLICY_TEMPLATES } from '@/components/abac/policy-templates';
import { VisualPolicyBuilder } from '@/components/abac/visual-policy-builder';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { resolveVisualRuleForPolicy } from '../helpers';
import type { AbacPolicyRow, AttributeDefinitionRow } from '../types';
import { AbacAttributesPanel } from './abac-attributes-panel';

interface AbacTabProps {
  policies: AbacPolicyRow[];
  attributes: AttributeDefinitionRow[];
  onActivatePolicy: (policyId: string) => Promise<boolean>;
  onSaveDraftPolicy: (savedRule: VisualPolicyRule) => Promise<boolean>;
  onClearError: () => void;
}

/**
 * Thuật toán: Điều Phối Danh Sách Chính Sách ABAC, Trình Dựng DNF & Bộ Mô Phỏng PDP (`AbacTab`)
 */
export function AbacTab({
  policies,
  attributes,
  onActivatePolicy,
  onSaveDraftPolicy,
  onClearError,
}: AbacTabProps) {
  const [abacSubTab, setAbacSubTab] = useState<'policies' | 'attributes'>('policies');
  const [builderOpen, setBuilderOpen] = useState(false);
  const [selectedRuleForBuilder, setSelectedRuleForBuilder] = useState<
    VisualPolicyRule | undefined
  >(undefined);
  const [simulatorOpen, setSimulatorOpen] = useState(false);
  const [activatingId, setActivatingId] = useState<string | null>(null);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2 border-b border-[#ebebeb] pb-2">
        <button
          type="button"
          onClick={() => setAbacSubTab('policies')}
          className={`min-h-11 sm:min-h-9 px-3.5 py-1.5 rounded-full text-xs font-semibold cursor-pointer ${
            abacSubTab === 'policies'
              ? 'bg-[#FF385C] text-white shadow-xs'
              : 'bg-[#f7f7f7] text-[#717171] hover:bg-[#ebebeb]'
          }`}
        >
          Quy tắc chính sách (Policies)
        </button>
        <button
          type="button"
          onClick={() => setAbacSubTab('attributes')}
          className={`min-h-11 sm:min-h-9 px-3.5 py-1.5 rounded-full text-xs font-semibold cursor-pointer ${
            abacSubTab === 'attributes'
              ? 'bg-[#FF385C] text-white shadow-xs'
              : 'bg-[#f7f7f7] text-[#717171] hover:bg-[#ebebeb]'
          }`}
        >
          Định nghĩa Thuộc tính (Attributes)
        </button>
      </div>

      {abacSubTab === 'policies' ? (
        builderOpen ? (
          <VisualPolicyBuilder
            initialRule={selectedRuleForBuilder}
            onClearError={onClearError}
            onSaveRule={async (savedRule) => {
              const ok = await onSaveDraftPolicy(savedRule);
              if (ok) setBuilderOpen(false);
            }}
            onCancel={() => {
              onClearError();
              setBuilderOpen(false);
            }}
          />
        ) : (
          <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
            <CardHeader className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
              <div>
                <CardTitle className="text-base text-[#222222]">
                  Chính sách kiểm soát thuộc tính (ABAC Policies)
                </CardTitle>
                <CardDescription className="text-xs text-[#717171]">
                  Quy tắc đánh giá ngữ cảnh tại Policy Decision Point (PDP) gồm Clearance,
                  Department và Obligations
                </CardDescription>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    onClearError();
                    setSimulatorOpen(true);
                  }}
                  className="rounded-full text-xs border-[#dddddd] hover:border-[#008A05] flex items-center gap-1.5"
                >
                  <Play
                    size={16}
                    strokeWidth={1.75}
                    className="text-[#008A05] fill-current"
                    aria-hidden="true"
                  />
                  <span>Mô phỏng PDP</span>
                </Button>
                <Button
                  type="button"
                  size="sm"
                  onClick={() => {
                    onClearError();
                    setSelectedRuleForBuilder(undefined);
                    setBuilderOpen(true);
                  }}
                  className="rounded-full bg-[#FF385C] hover:bg-[#E31C5F] text-white text-xs px-4 font-semibold flex items-center gap-1.5"
                >
                  <Plus size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Soạn thảo Trực quan</span>
                </Button>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                    <TableRow>
                      <TableHead className="text-xs text-[#717171]">Tên quy tắc</TableHead>
                      <TableHead className="text-xs text-[#717171]">Mô tả hành vi</TableHead>
                      <TableHead className="text-xs text-[#717171]">Hiệu lực (Effect)</TableHead>
                      <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
                      <TableHead className="text-xs text-[#717171] text-right">Thao tác</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {policies.map((p) => (
                      <TableRow
                        key={p.id}
                        className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60"
                      >
                        <TableCell className="font-semibold text-xs text-[#222222]">
                          {p.name}
                        </TableCell>
                        <TableCell className="text-xs text-[#222222] max-w-md">
                          {p.description}
                        </TableCell>
                        <TableCell>
                          <Badge variant={p.effect === 'PERMIT' ? 'success' : 'destructive'}>
                            {p.effect}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          {p.isActive ? (
                            <span className="flex items-center gap-1 text-xs text-[#008A05]">
                              <Check size={16} strokeWidth={1.75} aria-hidden="true" />
                              <span>Đang thực thi</span>
                            </span>
                          ) : (
                            <Badge variant="secondary" className="text-[13px]">
                              Chờ kích hoạt
                            </Badge>
                          )}
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex items-center justify-end gap-1">
                            {!p.isActive && (
                              <InteractiveHoverButton
                                variant="primary"
                                size="sm"
                                text="Kích hoạt"
                                icon={
                                  <ShieldCheck size={16} strokeWidth={1.75} aria-hidden="true" />
                                }
                                isLoading={activatingId === p.id}
                                disabled={activatingId === p.id}
                                onClick={async () => {
                                  setActivatingId(p.id);
                                  try {
                                    await onActivatePolicy(p.id);
                                  } finally {
                                    setActivatingId(null);
                                  }
                                }}
                              />
                            )}
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              onClick={() => {
                                onClearError();
                                setSelectedRuleForBuilder(resolveVisualRuleForPolicy(p));
                                setBuilderOpen(true);
                              }}
                              className="text-xs rounded-full hover:bg-[#f7f7f7] text-[#E31C5F] font-semibold"
                            >
                              Sửa Trực quan
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        )
      ) : (
        <AbacAttributesPanel attributes={attributes} />
      )}

      <PolicySimulatorDialog
        open={simulatorOpen}
        onOpenChange={setSimulatorOpen}
        activeRule={selectedRuleForBuilder || PRESET_POLICY_TEMPLATES[0]!.rule}
      />
    </div>
  );
}
