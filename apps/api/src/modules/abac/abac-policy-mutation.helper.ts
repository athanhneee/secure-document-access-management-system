/**
 * @module AbacPolicyMutationHelper
 * Algorithm: Validated SERIALIZABLE ABAC Policy Rule Creation, Update & DNF Condition Persistence.
 */
import { BadRequestException, ConflictException, NotFoundException } from '@nestjs/common';
import { Prisma, withSerializableTransaction, type getDatabaseClient } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { AbacAuditService } from './abac-audit.service.js';
import {
  buildPolicyConditionRows,
  serializeAbacPolicyRow,
  type RawPolicyForSerialize,
  type UpsertAbacPolicyInput,
} from './abac-policy-dto.helper.js';
import type { AbacRepository } from './abac.repository.js';
import type { PolicyCache } from './policy-cache.js';
import { compilePolicy, PolicyCompilationError } from './policy-compiler.js';

export {
  UpsertAbacPolicySchema,
  serializeAbacPolicyRow,
  type RawPolicyForSerialize,
  type UpsertAbacPolicyInput,
} from './abac-policy-dto.helper.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Thuật toán: Tạo mới hoặc cập nhật nguyên tử quy tắc chính sách ABAC trong giao dịch `SERIALIZABLE`, kiểm định trình biên dịch AST DNF, tăng epoch bộ nhớ đệm và ghi nhật ký kiểm toán.
 */
export async function executeUpsertAbacPolicy(params: {
  ruleId?: bigint;
  input: UpsertAbacPolicyInput;
  principal: AuthPrincipal;
  context: RequestContext;
  database: PrismaClient;
  repository: AbacRepository;
  cache: PolicyCache;
  audit: AbacAuditService;
}): Promise<Record<string, unknown>> {
  const { ruleId, input, principal, context, database, repository, cache, audit } = params;
  const oldVersion = await repository.currentPolicyVersion();
  const normalizedAction =
    !input.targetAction || input.targetAction === 'ALL' ? null : input.targetAction;

  let savedPolicy!: RawPolicyForSerialize;

  await withSerializableTransaction(
    async (tx) => {
      const existingByCode = await tx.policyRule.findFirst({
        where: ruleId ? { code: input.code, id: { not: ruleId } } : { code: input.code },
        select: { id: true },
      });
      if (existingByCode) {
        throw new ConflictException({
          errorCode: AppErrorCode.RESOURCE_CONFLICT,
          message: `Policy rule with code "${input.code}" already exists.`,
        });
      }

      const conditionRows = await buildPolicyConditionRows(tx, input.groups);
      let targetId: bigint;

      if (ruleId === undefined) {
        const created = await tx.policyRule.create({
          data: {
            code: input.code,
            name: input.name,
            description: input.description ?? null,
            effect: input.effect,
            priority: input.priority,
            target_resource: 'DOCUMENT',
            target_action: normalizedAction,
            combining_algorithm: 'DENY_OVERRIDES',
            obligations: input.obligations as Prisma.InputJsonValue,
            is_active: input.isActive ?? true,
            created_by: principal.userId,
            ...(conditionRows.length > 0
              ? { policy_rule_conditions: { createMany: { data: conditionRows } } }
              : {}),
          },
          select: { id: true },
        });
        targetId = created.id;
      } else {
        const before = await tx.policyRule.findUnique({
          where: { id: ruleId },
          select: { id: true, is_active: true, version: true },
        });
        if (!before) throw new NotFoundException('Policy rule was not found.');

        let nextVersion = before.version + 1n;
        if (typeof tx.$queryRawUnsafe === 'function') {
          const seqRows = await tx.$queryRawUnsafe<Array<{ v: bigint | number | string }>>(
            "SELECT nextval('abac_policy_version_seq') AS v",
          );
          if (seqRows[0]?.v !== undefined) nextVersion = BigInt(seqRows[0].v);
        }

        await tx.policyRuleCondition.deleteMany({ where: { policy_rule_id: ruleId } });
        await tx.policyRule.update({
          where: { id: ruleId },
          data: {
            code: input.code,
            name: input.name,
            description: input.description ?? null,
            effect: input.effect,
            priority: input.priority,
            target_resource: 'DOCUMENT',
            target_action: normalizedAction,
            obligations: input.obligations as Prisma.InputJsonValue,
            is_active: input.isActive ?? before.is_active,
            updated_at: new Date(),
            version: nextVersion,
            ...(conditionRows.length > 0
              ? { policy_rule_conditions: { createMany: { data: conditionRows } } }
              : {}),
          },
        });
        targetId = ruleId;
      }

      if (
        typeof tx.attributeDefinition?.findMany === 'function' &&
        typeof tx.policyRule?.findMany === 'function'
      ) {
        const source = await repository.loadPolicySource({
          includeInactiveRuleId: targetId,
          client: tx,
        });
        try {
          compilePolicy(oldVersion + 1n, source.definitions, source.rules);
        } catch (err) {
          if (err instanceof PolicyCompilationError) {
            throw new BadRequestException({
              errorCode: 'INVALID_POLICY',
              message: 'Policy failed compilation validation.',
              issues: err.issueCodes,
            });
          }
          throw err;
        }
      }

      const reloaded = await tx.policyRule.findUnique({
        where: { id: targetId },
        include: {
          policy_rule_conditions: {
            orderBy: [{ condition_group: 'asc' }, { sequence_no: 'asc' }, { id: 'asc' }],
            include: {
              attribute_definitions: { select: { code: true, scope: true, value_type: true } },
            },
          },
        },
      });
      if (!reloaded) throw new NotFoundException('Saved policy rule could not be reloaded.');
      savedPolicy = reloaded;

      await audit.record(
        tx,
        {
          action: ruleId === undefined ? 'POLICY_CREATED' : 'POLICY_UPDATED',
          objectType: 'POLICY',
          objectId: targetId.toString(),
          outcome: 'SUCCESS',
          details: {
            code: savedPolicy.code,
            effect: savedPolicy.effect,
            priority: savedPolicy.priority,
            active: savedPolicy.is_active,
            conditionCount: conditionRows.length,
            version: savedPolicy.version.toString(),
          },
        },
        principal,
        context,
      );
    },
    { client: database },
  );

  await cache.bumpPolicyEpoch(oldVersion.toString());
  return serializeAbacPolicyRow(savedPolicy);
}
