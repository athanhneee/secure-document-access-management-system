/**
 * @module AbacPolicyDtoHelper
 * Algorithm: Zod Input Validation, DNF Condition Attribute Mapping & BigInt-Safe Policy Serialization.
 */
import { BadRequestException } from '@nestjs/common';
import type { Prisma } from '@sda/database';
import { z } from 'zod';
import { ATTRIBUTE_CODE_TO_KEY, CONTEXT_ATTRIBUTES } from './attribute-registry.js';

export const UpsertAbacPolicySchema = z.object({
  code: z.string().trim().min(2).max(80),
  name: z.string().trim().min(2).max(180),
  description: z.string().max(2000).nullable().optional(),
  effect: z.enum(['PERMIT', 'DENY']),
  priority: z.coerce.number().int().min(1).max(100_000).default(100),
  targetResource: z.literal('DOCUMENT').default('DOCUMENT'),
  targetAction: z
    .enum(['ALL', 'DISCOVER', 'VIEW', 'DOWNLOAD', 'SHARE', 'MANAGE'])
    .nullable()
    .optional(),
  obligations: z.array(z.record(z.string(), z.unknown())).optional().default([]),
  isActive: z.boolean().optional(),
  groups: z
    .array(
      z.object({
        id: z.coerce.number().int().min(1).optional(),
        conditions: z.array(
          z.object({
            id: z.string().optional(),
            attribute: z.string().trim().min(1).max(100),
            operator: z.string().trim().min(1).max(30),
            expected: z.unknown(),
          }),
        ),
      }),
    )
    .optional()
    .default([]),
});

export type UpsertAbacPolicyInput = z.infer<typeof UpsertAbacPolicySchema>;

interface RawConditionForSerialize {
  id: bigint;
  policy_rule_id: bigint;
  attribute_definition_id: bigint | null;
  context_key: string | null;
  operator: string;
  expected_value: unknown;
  condition_group: number;
  sequence_no: number;
  attribute_definitions?: {
    code: string;
    scope: string;
    value_type: string;
  } | null;
}

export interface RawPolicyForSerialize {
  id: bigint;
  code: string;
  name: string;
  description: string | null;
  effect: 'PERMIT' | 'DENY';
  priority: number;
  target_resource: string;
  target_action: 'DISCOVER' | 'VIEW' | 'DOWNLOAD' | 'SHARE' | 'MANAGE' | null;
  combining_algorithm: string;
  obligations: unknown;
  is_active: boolean;
  valid_from: Date;
  valid_to: Date | null;
  version: bigint;
  policy_rule_conditions?: RawConditionForSerialize[];
}

/**
 * Thuật toán: Chuẩn hóa bản ghi `policy_rules` sang DTO JSON không chứa `bigint`, đồng thời cung cấp cả `is_active` và `isActive` cùng cây nhóm DNF `groups`.
 */
export function serializeAbacPolicyRow(policy: RawPolicyForSerialize): Record<string, unknown> {
  const rawConditions = policy.policy_rule_conditions ?? [];
  const serializedConditions = rawConditions.map((c) => ({
    id: c.id.toString(),
    policy_rule_id: c.policy_rule_id.toString(),
    attribute_definition_id: c.attribute_definition_id?.toString() ?? null,
    context_key: c.context_key,
    operator: c.operator,
    expected_value: c.expected_value,
    condition_group: c.condition_group,
    sequence_no: c.sequence_no,
    attribute_definitions: c.attribute_definitions ?? null,
  }));

  const grouped = new Map<number, Array<Record<string, unknown>>>();
  for (const c of rawConditions) {
    const attrKey =
      c.context_key ?? ATTRIBUTE_CODE_TO_KEY[c.attribute_definitions?.code ?? ''] ?? '';
    const bucket = grouped.get(c.condition_group) ?? [];
    bucket.push({
      id: c.id.toString(),
      attribute: attrKey,
      operator: c.operator,
      expected: c.expected_value,
    });
    grouped.set(c.condition_group, bucket);
  }

  // CONFLICT-RESOLVED: Trả song song cả trường snake_case và camelCase kèm policy_rule_conditions & groups cho UI và caller hiện hữu (HIGH-04)
  return {
    id: policy.id.toString(),
    code: policy.code,
    name: policy.name,
    description: policy.description ?? '',
    effect: policy.effect,
    priority: policy.priority,
    target_resource: policy.target_resource,
    targetResource: policy.target_resource,
    target_action: policy.target_action,
    targetAction: policy.target_action ?? 'ALL',
    combining_algorithm: policy.combining_algorithm,
    combiningAlgorithm: policy.combining_algorithm,
    obligations: Array.isArray(policy.obligations) ? policy.obligations : [],
    is_active: policy.is_active,
    isActive: policy.is_active,
    valid_from: policy.valid_from,
    valid_to: policy.valid_to,
    version: policy.version.toString(),
    policy_rule_conditions: serializedConditions,
    groups: [...grouped.entries()]
      .sort(([a], [b]) => a - b)
      .map(([id, conditions]) => ({ id, conditions })),
  };
}

/**
 * Thuật toán: Ánh xạ danh sách nhóm điều kiện DNF sang hàng phẳng `policy_rule_conditions` thỏa mãn ràng buộc XOR `(attribute_definition_id IS NOT NULL) <> (context_key IS NOT NULL)`.
 */
export async function buildPolicyConditionRows(
  tx: Prisma.TransactionClient,
  groups: UpsertAbacPolicyInput['groups'],
): Promise<
  Array<{
    attribute_definition_id: bigint | null;
    context_key: string | null;
    operator: string;
    expected_value: Prisma.InputJsonValue;
    condition_group: number;
    sequence_no: number;
  }>
> {
  const activeDefs =
    typeof tx.attributeDefinition?.findMany === 'function'
      ? await tx.attributeDefinition.findMany({
          where: { is_active: true },
          select: { id: true, code: true },
        })
      : [];
  const defByCode = new Map(activeDefs.map((d) => [d.code, d.id]));

  const rows: Array<{
    attribute_definition_id: bigint | null;
    context_key: string | null;
    operator: string;
    expected_value: Prisma.InputJsonValue;
    condition_group: number;
    sequence_no: number;
  }> = [];

  groups.forEach((group, groupIdx) => {
    const conditionGroup = group.id && group.id >= 1 ? group.id : groupIdx + 1;
    group.conditions.forEach((cond, condIdx) => {
      const attr = cond.attribute.trim();
      let attributeDefinitionId: bigint | null = null;
      let contextKey: string | null = null;

      if (attr in CONTEXT_ATTRIBUTES) {
        contextKey = attr;
      } else if (defByCode.has(attr)) {
        attributeDefinitionId = defByCode.get(attr)!;
      } else if (ATTRIBUTE_CODE_TO_KEY[attr]) {
        contextKey = ATTRIBUTE_CODE_TO_KEY[attr]!;
      } else {
        throw new BadRequestException({
          errorCode: 'INVALID_POLICY',
          message: `Unknown ABAC condition attribute: ${attr}`,
        });
      }

      rows.push({
        attribute_definition_id: attributeDefinitionId,
        context_key: contextKey,
        operator: cond.operator.trim().toUpperCase(),
        expected_value: (cond.expected ?? null) as Prisma.InputJsonValue,
        condition_group: conditionGroup,
        sequence_no: condIdx + 1,
      });
    });
  });

  return rows;
}
