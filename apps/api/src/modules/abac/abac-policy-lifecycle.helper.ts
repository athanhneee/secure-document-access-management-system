/**
 * @module AbacPolicyLifecycleHelper
 * Thuật toán: Tạm tắt (`executeDeactivateAbacRule`) và xóa (`executeDeleteAbacRule`) quy tắc chính sách ABAC
 * trong giao dịch `SERIALIZABLE`, để trigger DB (`trg_policy_rules_version`) tự động tăng `abac_policy_version_seq`,
 * ghi nhật ký kiểm toán bất biến và đẩy Epoch làm mới tức thì bộ đệm PDP trên mọi nút dịch vụ.
 */
import { NotFoundException } from '@nestjs/common';
import { withSerializableTransaction, type getDatabaseClient } from '@sda/database';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import type { AbacAuditService } from './abac-audit.service.js';
import type { AbacRepository } from './abac.repository.js';
import type { PolicyCache } from './policy-cache.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

/**
 * Thuật toán: Tạm tắt quy tắc chính sách ABAC trong giao dịch `SERIALIZABLE`, dựa vào trigger `trg_policy_rules_version` cập nhật phiên bản đơn điệu và vô hiệu hóa bộ đệm PDP.
 */
export async function executeDeactivateAbacRule(params: {
  ruleId: bigint;
  principal: AuthPrincipal;
  context: RequestContext;
  database: PrismaClient;
  repository: AbacRepository;
  cache: PolicyCache;
  audit: AbacAuditService;
}): Promise<{ id: string; policyVersion: string }> {
  const { ruleId, principal, context, database, repository, cache, audit } = params;
  const oldVersion = await repository.currentPolicyVersion();

  await withSerializableTransaction(
    async (transaction) => {
      const before = await transaction.policyRule.findUnique({
        where: { id: ruleId },
        select: { id: true, code: true, is_active: true, version: true },
      });
      if (!before) throw new NotFoundException('Policy rule was not found.');

      // CONFLICT-RESOLVED: Không gọi nextval('abac_policy_version_seq') thủ công vì trigger BEFORE UPDATE trg_policy_rules_version đã tự tăng version khi is_active đổi, tránh nhảy đúp sequence.
      const after = await transaction.policyRule.update({
        where: { id: ruleId },
        data: { is_active: false },
        select: { is_active: true, version: true },
      });

      await audit.record(
        transaction,
        {
          action: 'POLICY_DEACTIVATED',
          objectType: 'POLICY',
          objectId: ruleId.toString(),
          outcome: 'SUCCESS',
          details: {
            code: before.code,
            priorActive: before.is_active,
            active: after.is_active,
            priorVersion: before.version.toString(),
            version: after.version.toString(),
          },
        },
        principal,
        context,
      );
    },
    { client: database },
  );

  await cache.bumpPolicyEpoch(oldVersion.toString());
  const policyVersion = await repository.currentPolicyVersion();
  return { id: ruleId.toString(), policyVersion: policyVersion.toString() };
}

/**
 * Thuật toán: Xóa quy tắc chính sách ABAC cùng toàn bộ điều kiện DNF liên kết trong giao dịch `SERIALIZABLE` và làm mới Epoch PDP (dựa vào trigger `trg_policy_rules_version` tăng sequence khi DELETE).
 */
export async function executeDeleteAbacRule(params: {
  ruleId: bigint;
  principal: AuthPrincipal;
  context: RequestContext;
  database: PrismaClient;
  repository: AbacRepository;
  cache: PolicyCache;
  audit: AbacAuditService;
}): Promise<void> {
  const { ruleId, principal, context, database, repository, cache, audit } = params;
  const oldVersion = await repository.currentPolicyVersion();

  await withSerializableTransaction(
    async (transaction) => {
      const before = await transaction.policyRule.findUnique({
        where: { id: ruleId },
        select: {
          id: true,
          code: true,
          name: true,
          effect: true,
          priority: true,
          is_active: true,
          version: true,
        },
      });
      if (!before) throw new NotFoundException('Policy rule was not found.');

      // CONFLICT-RESOLVED: Không gọi nextval('abac_policy_version_seq') thủ công vì trigger BEFORE DELETE trg_policy_rules_version đã tự tăng sequence, tránh nhảy đúp sequence.
      await transaction.policyRuleCondition.deleteMany({ where: { policy_rule_id: ruleId } });
      await transaction.policyRule.delete({ where: { id: ruleId } });

      await audit.record(
        transaction,
        {
          action: 'POLICY_DELETED',
          objectType: 'POLICY',
          objectId: ruleId.toString(),
          outcome: 'SUCCESS',
          details: {
            code: before.code,
            name: before.name,
            effect: before.effect,
            priority: before.priority,
            priorActive: before.is_active,
            priorVersion: before.version.toString(),
          },
        },
        principal,
        context,
      );
    },
    { client: database },
  );

  await cache.bumpPolicyEpoch(oldVersion.toString());
}
