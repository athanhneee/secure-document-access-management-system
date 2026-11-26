'use client';

import { useMemo, useState } from 'react';
import { Check, PauseCircle, Play, Plus, ShieldCheck, Trash2 } from 'lucide-react';
import type { VisualPolicyRule } from '@/components/abac/abac-models';
import { PolicySimulatorDialog } from '@/components/abac/policy-simulator-dialog';
import { VisualPolicyBuilder } from '@/components/abac/visual-policy-builder';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { formatPolicyEffectLabel } from '@/lib/ui-labels';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { resolveVisualRuleForPolicy } from '../helpers';
import type {
  AbacPolicyRow,
  AttributeDefinitionRow,
  BusinessCategoryOptionRow,
  DepartmentLookupRow,
} from '../types';
import { AbacAttributesPanel } from './abac-attributes-panel';

interface AbacTabProps {
  policies: AbacPolicyRow[];
  attributes: AttributeDefinitionRow[];
  departments?: readonly DepartmentLookupRow[] | undefined;
  businessCategories?: readonly BusinessCategoryOptionRow[] | undefined;
  canManagePolicies?: boolean | undefined;
  canManageAttributes?: boolean | undefined;
  canSimulatePolicy?: boolean | undefined;
  onActivatePolicy: (policyId: string) => Promise<boolean>;
  onDeactivatePolicy: (policyId: string) => Promise<boolean>;
  onDeletePolicy: (policy: AbacPolicyRow) => Promise<boolean>;
  onSaveDraftPolicy: (savedRule: VisualPolicyRule) => Promise<boolean>;
  onClearError: () => void;
}

/**
 * Thuật toán: Điều Phối Danh Sách Chính Sách ABAC Lọc Quyền Hạt Mịn, Tạm Tắt/Xóa & Dữ Liệu CSDL Động (`AbacTab`)
 * Mục đích: Tách riêng hiển thị thao tác theo từng quyền (`POLICY:MANAGE`, `ATTRIBUTE:MANAGE`, `POLICY:SIMULATE`), truyền phòng ban & danh mục thực tế xuống Trình dựng và Bộ mô phỏng.
 */
export function AbacTab({
  policies,
  attributes,
  departments,
  businessCategories,
  canManagePolicies = true,
  canManageAttributes = true,
  canSimulatePolicy = true,
  onActivatePolicy,
  onDeactivatePolicy,
  onDeletePolicy,
  onSaveDraftPolicy,
  onClearError,
}: AbacTabProps) {
  const showPoliciesSubTab = canManagePolicies || canSimulatePolicy;
  const [selectedSubTab, setSelectedSubTab] = useState<'policies' | 'attributes'>(() =>
    showPoliciesSubTab ? 'policies' : 'attributes',
  );
  const abacSubTab: 'policies' | 'attributes' =
    selectedSubTab === 'policies' && !showPoliciesSubTab
      ? 'attributes'
      : selectedSubTab === 'attributes' && !canManageAttributes
        ? 'policies'
        : selectedSubTab;

  const [builderOpen, setBuilderOpen] = useState(false);
  const [selectedRuleForBuilder, setSelectedRuleForBuilder] = useState<
    VisualPolicyRule | undefined
  >(undefined);
  const [simulatorOpen, setSimulatorOpen] = useState(false);
  const [activatingId, setActivatingId] = useState<string | null>(null);
  const [pendingPolicyAction, setPendingPolicyAction] = useState<{
    policy: AbacPolicyRow;
    action: 'deactivate' | 'delete';
  } | null>(null);
  const [isMutatingPolicy, setIsMutatingPolicy] = useState(false);

  const allDbVisualRules = useMemo(
    () => policies.map((policy) => resolveVisualRuleForPolicy(policy)),
    [policies],
  );
  const activeDbVisualRules = useMemo(
    () => policies.filter((policy) => policy.isActive).map((p) => resolveVisualRuleForPolicy(p)),
    [policies],
  );

  return (
    <div className="space-y-3.5">
      <div className="flex flex-wrap items-center gap-2">
        {showPoliciesSubTab && (
          <button
            type="button"
            onClick={() => setSelectedSubTab('policies')}
            className={`min-h-11 sm:min-h-8 px-3.5 py-1 rounded-full text-xs font-semibold cursor-pointer ${
              abacSubTab === 'policies'
                ? 'bg-[#FF385C] text-white shadow-xs'
                : 'bg-[#f7f7f7] text-[#717171] hover:bg-[#ebebeb]'
            }`}
          >
            Quy tắc chính sách ({policies.length})
          </button>
        )}
        {canManageAttributes && (
          <button
            type="button"
            onClick={() => setSelectedSubTab('attributes')}
            className={`min-h-11 sm:min-h-8 px-3.5 py-1 rounded-full text-xs font-semibold cursor-pointer ${
              abacSubTab === 'attributes'
                ? 'bg-[#FF385C] text-white shadow-xs'
                : 'bg-[#f7f7f7] text-[#717171] hover:bg-[#ebebeb]'
            }`}
          >
            Thuộc tính ({attributes.length})
          </button>
        )}
      </div>

      {abacSubTab === 'policies' && showPoliciesSubTab ? (
        builderOpen && canManagePolicies ? (
          <VisualPolicyBuilder
            initialRule={selectedRuleForBuilder}
            departments={departments}
            businessCategories={businessCategories}
            canSimulateOnServer={canSimulatePolicy}
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
          <Card>
            <CardHeader className="pb-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
              <CardTitle className="text-sm sm:text-base text-[#222222]">
                Chính sách kiểm soát truy cập
              </CardTitle>
              <div className="flex flex-wrap sm:flex-nowrap items-center gap-2 shrink-0">
                {canSimulatePolicy && (
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
                    <span>Mô phỏng chính sách</span>
                  </Button>
                )}
                {canManagePolicies && (
                  <Button
                    type="button"
                    size="sm"
                    onClick={() => {
                      onClearError();
                      setSelectedRuleForBuilder(undefined);
                      setBuilderOpen(true);
                    }}
                    className="rounded-full bg-[#FF385C] hover:bg-[#E31C5F] text-white text-xs px-3.5 font-semibold flex items-center gap-1.5"
                  >
                    <Plus size={16} strokeWidth={1.75} aria-hidden="true" />
                    <span>Soạn thảo trực quan</span>
                  </Button>
                )}
              </div>
            </CardHeader>
            <CardContent className="p-0">
              {/* Bố cục thẻ di động tối ưu 375px */}
              <div className="md:hidden divide-y divide-[#ebebeb]">
                {policies.length === 0 ? (
                  <div className="py-8 px-4 text-center text-xs text-[#717171]">
                    {canManagePolicies
                      ? 'Chưa có quy tắc chính sách truy cập nào.'
                      : 'Bạn có quyền mô phỏng chính sách — hãy nhấn "Mô phỏng chính sách" ở góc trên để kiểm thử.'}
                  </div>
                ) : (
                  policies.map((p) => (
                    <article key={p.id} className="px-4 py-4 space-y-2.5 bg-[#ffffff]">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <Badge variant={p.effect === 'PERMIT' ? 'success' : 'destructive'}>
                          {formatPolicyEffectLabel(p.effect)}
                        </Badge>
                        {p.isActive ? (
                          <span className="inline-flex items-center gap-1 text-xs font-semibold text-[#008A05]">
                            <Check size={16} strokeWidth={1.75} aria-hidden="true" />
                            <span>Đang thực thi</span>
                          </span>
                        ) : (
                          <Badge variant="secondary">Tạm tắt</Badge>
                        )}
                      </div>
                      <h3 className="text-sm font-semibold text-[#222222] break-words">{p.name}</h3>
                      {p.description && (
                        <p className="text-xs text-[#717171] leading-relaxed break-words">
                          {p.description}
                        </p>
                      )}
                      {canManagePolicies && (
                        <div className="flex flex-wrap gap-2 pt-1">
                          {p.isActive ? (
                            <InteractiveHoverButton
                              variant="secondary"
                              size="sm"
                              text="Tạm tắt"
                              icon={
                                <PauseCircle
                                  size={16}
                                  strokeWidth={1.75}
                                  className="text-[#E07912]"
                                  aria-hidden="true"
                                />
                              }
                              onClick={() => {
                                onClearError();
                                setPendingPolicyAction({ policy: p, action: 'deactivate' });
                              }}
                              className="flex-1"
                            />
                          ) : (
                            <InteractiveHoverButton
                              variant="primary"
                              size="sm"
                              text="Kích hoạt"
                              icon={<ShieldCheck size={16} strokeWidth={1.75} aria-hidden="true" />}
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
                              className="flex-1"
                            />
                          )}
                          <Button
                            type="button"
                            variant="outline"
                            size="sm"
                            onClick={() => {
                              onClearError();
                              setSelectedRuleForBuilder(resolveVisualRuleForPolicy(p));
                              setBuilderOpen(true);
                            }}
                            className="flex-1 min-h-11 text-xs rounded-full border-[#dddddd] text-[#E31C5F] font-semibold"
                          >
                            Sửa trực quan
                          </Button>
                          <InteractiveHoverButton
                            variant="danger"
                            size="sm"
                            text="Xóa"
                            icon={<Trash2 size={16} strokeWidth={1.75} aria-hidden="true" />}
                            onClick={() => {
                              onClearError();
                              setPendingPolicyAction({ policy: p, action: 'delete' });
                            }}
                            className="w-full"
                          />
                        </div>
                      )}
                    </article>
                  ))
                )}
              </div>

              <div className="hidden md:block">
                <Table>
                  <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                    <TableRow>
                      <TableHead className="text-xs text-[#717171]">Tên quy tắc</TableHead>
                      <TableHead className="text-xs text-[#717171]">Mô tả hành vi</TableHead>
                      <TableHead className="text-xs text-[#717171]">Hiệu lực</TableHead>
                      <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
                      {canManagePolicies && (
                        <TableHead className="text-xs text-[#717171] text-right">
                          Thao tác
                        </TableHead>
                      )}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {policies.length === 0 ? (
                      <TableRow>
                        <TableCell
                          colSpan={canManagePolicies ? 5 : 4}
                          className="text-center py-8 text-xs text-[#717171]"
                        >
                          {canManagePolicies
                            ? 'Chưa có quy tắc chính sách truy cập nào.'
                            : 'Bạn có quyền mô phỏng chính sách — hãy nhấn "Mô phỏng chính sách" ở góc trên để kiểm thử.'}
                        </TableCell>
                      </TableRow>
                    ) : (
                      policies.map((p) => (
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
                              {formatPolicyEffectLabel(p.effect)}
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
                                Tạm tắt
                              </Badge>
                            )}
                          </TableCell>
                          {canManagePolicies && (
                            <TableCell className="text-right">
                              <div className="flex flex-wrap items-center justify-end gap-1.5">
                                {p.isActive ? (
                                  <InteractiveHoverButton
                                    variant="ghost"
                                    size="sm"
                                    text="Tạm tắt"
                                    icon={
                                      <PauseCircle
                                        size={16}
                                        strokeWidth={1.75}
                                        className="text-[#E07912]"
                                        aria-hidden="true"
                                      />
                                    }
                                    onClick={() => {
                                      onClearError();
                                      setPendingPolicyAction({ policy: p, action: 'deactivate' });
                                    }}
                                  />
                                ) : (
                                  <InteractiveHoverButton
                                    variant="primary"
                                    size="sm"
                                    text="Kích hoạt"
                                    icon={
                                      <ShieldCheck
                                        size={16}
                                        strokeWidth={1.75}
                                        aria-hidden="true"
                                      />
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
                                  Sửa trực quan
                                </Button>
                                <InteractiveHoverButton
                                  variant="ghost"
                                  size="sm"
                                  text="Xóa"
                                  icon={
                                    <Trash2
                                      size={16}
                                      strokeWidth={1.75}
                                      className="text-[#C13515]"
                                      aria-hidden="true"
                                    />
                                  }
                                  onClick={() => {
                                    onClearError();
                                    setPendingPolicyAction({ policy: p, action: 'delete' });
                                  }}
                                />
                              </div>
                            </TableCell>
                          )}
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        )
      ) : (
        <AbacAttributesPanel attributes={attributes} />
      )}

      {canSimulatePolicy && (
        <PolicySimulatorDialog
          open={simulatorOpen}
          onOpenChange={setSimulatorOpen}
          policySet={activeDbVisualRules}
          selectableRules={allDbVisualRules}
          departments={departments}
          businessCategories={businessCategories}
          canSimulateOnServer={canSimulatePolicy}
        />
      )}

      <ConfirmDialog
        open={Boolean(pendingPolicyAction)}
        onOpenChange={(open) => {
          if (!open && !isMutatingPolicy) setPendingPolicyAction(null);
        }}
        title={
          pendingPolicyAction?.action === 'delete'
            ? 'Xác nhận xóa chính sách truy cập'
            : 'Xác nhận tạm tắt chính sách truy cập'
        }
        description={
          pendingPolicyAction?.action === 'delete'
            ? `Quy tắc "${pendingPolicyAction.policy.name}" sẽ bị xóa vĩnh viễn khỏi bộ đánh giá PDP. Nếu tắt hoặc xóa toàn bộ luật Cho phép (PERMIT), hệ thống sẽ tự động áp dụng Mặc định từ chối (DEFAULT_DENY).`
            : `Quy tắc "${pendingPolicyAction?.policy.name ?? ''}" sẽ ngừng thực thi ngay trên hệ thống PDP và có thể kích hoạt lại bất cứ lúc nào.`
        }
        confirmLabel={
          pendingPolicyAction?.action === 'delete' ? 'Xác nhận xóa' : 'Xác nhận tạm tắt'
        }
        variant="danger"
        isLoading={isMutatingPolicy}
        onConfirm={async () => {
          if (!pendingPolicyAction) return;
          setIsMutatingPolicy(true);
          try {
            const ok =
              pendingPolicyAction.action === 'delete'
                ? await onDeletePolicy(pendingPolicyAction.policy)
                : await onDeactivatePolicy(pendingPolicyAction.policy.id);
            if (ok) setPendingPolicyAction(null);
          } finally {
            setIsMutatingPolicy(false);
          }
        }}
      />
    </div>
  );
}
