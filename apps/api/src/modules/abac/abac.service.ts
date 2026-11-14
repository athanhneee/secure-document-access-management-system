/**
 * @module AbacService
 * Thuật toán: Dịch vụ Quyết định Chính sách ABAC (PDP) có bộ đệm phiên bản + bộ đệm Epoch `2_000ms`,
 * bỏ qua kiểm định tĩnh dư thừa khi đánh giá cây AST đã biên dịch, hỗ trợ mô phỏng điểm thời gian và kích hoạt hai pha `SERIALIZABLE`.
 */
import { ForbiddenException, Injectable } from '@nestjs/common';
import { getDatabaseClient, withSerializableTransaction } from '@sda/database';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { canSimulatePolicy } from '../rbac/permission-matrix.js';
import { AbacAuditService } from './abac-audit.service.js';
import {
  executeActivateAbacRule,
  executeUpsertAbacPolicy,
  serializeAbacPolicyRow,
  type RawPolicyForSerialize,
  type UpsertAbacPolicyInput,
} from './abac-policy-mutation.helper.js';
import { AbacRepository } from './abac.repository.js';
import type { PdpResult, PolicyEvaluationInput } from './abac.types.js';
import { PolicyCache } from './policy-cache.js';
import { compilePolicy, PolicyCompilationError } from './policy-compiler.js';
import { evaluatePolicy } from './policy-engine.js';

@Injectable()
export class AbacService {
  private readonly database = getDatabaseClient();

  constructor(
    private readonly repository: AbacRepository,
    private readonly cache: PolicyCache,
    private readonly audit: AbacAuditService,
  ) {}

  /**
   * Thuật toán: Truy vấn và tuần tự hóa danh sách quy tắc chính sách ABAC sang DTO JSON an toàn `bigint`.
   */
  async listPolicies(): Promise<{ data: Array<Record<string, unknown>> }> {
    const policies = await this.repository.listPolicies();
    return {
      data: policies.map((policy) => serializeAbacPolicyRow(policy as RawPolicyForSerialize)),
    };
  }

  /**
   * Thuật toán: Khởi tạo quy tắc chính sách ABAC mới kèm các nhóm điều kiện DNF và kiểm định trình biên dịch.
   */
  async createPolicy(
    principal: AuthPrincipal,
    input: UpsertAbacPolicyInput,
    context: RequestContext,
  ): Promise<Record<string, unknown>> {
    return executeUpsertAbacPolicy({
      input,
      principal,
      context,
      database: this.database,
      repository: this.repository,
      cache: this.cache,
      audit: this.audit,
    });
  }

  /**
   * Thuật toán: Cập nhật quy tắc chính sách ABAC hiện hữu kèm thay thế tập điều kiện DNF và làm mới epoch bộ nhớ đệm.
   */
  async updatePolicy(
    principal: AuthPrincipal,
    ruleId: bigint,
    input: UpsertAbacPolicyInput,
    context: RequestContext,
  ): Promise<Record<string, unknown>> {
    return executeUpsertAbacPolicy({
      ruleId,
      input,
      principal,
      context,
      database: this.database,
      repository: this.repository,
      cache: this.cache,
      audit: this.audit,
    });
  }

  async listAttributes(): Promise<{ data: Array<Record<string, unknown>> }> {
    const attributes = await this.repository.listAttributes();
    return {
      data: attributes.map((attribute) => ({
        ...attribute,
        id: attribute.id.toString(),
        version: attribute.version.toString(),
        attribute_options: attribute.attribute_options.map((option) => ({
          ...option,
          id: option.id.toString(),
        })),
      })),
    };
  }

  /**
   * Thuật toán: Đánh giá chính sách ABAC có bộ đệm Epoch `2_000ms` và bỏ qua `validatePolicy` dư thừa trên cây AST đã biên dịch.
   */
  async evaluate(input: PolicyEvaluationInput): Promise<PdpResult> {
    const start = performance.now();
    let isCached = false;
    let result: PdpResult | undefined;

    let version =
      typeof this.cache.getCachedPolicyEpoch === 'function'
        ? await this.cache.getCachedPolicyEpoch()
        : null;
    if (version === null) {
      version = await this.repository.currentPolicyVersion();
      if (typeof this.cache.setCachedPolicyEpoch === 'function') {
        await this.cache.setCachedPolicyEpoch(version);
      }
    }

    const versionText = version.toString();
    const cached = await this.cache.get(versionText);
    if (cached) {
      try {
        result = evaluatePolicy(cached, input, { skipValidation: true });
        isCached = true;
      } catch {
        await this.cache.invalidate(versionText);
      }
    }

    if (!result) {
      try {
        const source = await this.repository.loadPolicySource();
        const compiled = compilePolicy(version, source.definitions, source.rules);
        await this.cache.put(compiled);
        result = evaluatePolicy(compiled, input, { skipValidation: true });
      } catch (error) {
        if (!(error instanceof PolicyCompilationError)) throw error;
        result = {
          decision: 'DENY',
          reasonCode: 'INVALID_POLICY',
          matchedRuleIds: [],
          obligations: [],
          policyVersion: versionText,
        };
      }
    }

    const durationSeconds = (performance.now() - start) / 1000;
    try {
      const { MetricsService } = await import('../system-health/metrics.service.js');
      MetricsService.getInstance().recordPdpEvaluation(result.decision, durationSeconds, isCached);
    } catch {
      // Ignore if metrics service unavailable in lightweight test runner
    }

    return result;
  }

  /**
   * Thuật toán: Mô phỏng quyết định chính sách thời điểm bất kỳ có ghi vết kiểm toán tuần tự hóa.
   */
  async simulate(
    principal: AuthPrincipal,
    input: {
      subjectUserId: bigint;
      resourceDocumentId: string;
      action: PolicyEvaluationInput['action'];
      time: Date;
      ip: string;
      deviceTrust: boolean;
      mfa: boolean;
      riskScore: number;
    },
    context: RequestContext,
  ): Promise<PdpResult> {
    if (!canSimulatePolicy(principal.roles)) {
      throw new ForbiddenException('Policy simulation is restricted to approved security roles.');
    }
    const evaluationInput = await this.repository.simulationInput(input);
    const result = await this.evaluate(evaluationInput);
    await withSerializableTransaction(async (transaction) => {
      await this.audit.record(
        transaction,
        {
          action: 'POLICY_SIMULATED',
          objectType: 'POLICY_SIMULATION',
          objectId: context.correlationId,
          documentId: input.resourceDocumentId,
          outcome: result.decision === 'PERMIT' ? 'SUCCESS' : 'DENIED',
          details: {
            subjectUserId: input.subjectUserId.toString(),
            resourceDocumentId: input.resourceDocumentId,
            requestedAction: input.action,
            decision: result.decision,
            reasonCode: result.reasonCode,
            policyVersion: result.policyVersion,
          },
        },
        principal,
        context,
      );
    });
    return result;
  }

  /**
   * Thuật toán: Kích hoạt luật chính sách kiểm chứng hai pha `SERIALIZABLE` và làm mới Epoch bộ nhớ đệm.
   */
  async activateRule(
    principal: AuthPrincipal,
    ruleId: bigint,
    context: RequestContext,
  ): Promise<{ id: string; policyVersion: string }> {
    return executeActivateAbacRule({
      ruleId,
      principal,
      context,
      database: this.database,
      repository: this.repository,
      cache: this.cache,
      audit: this.audit,
    });
  }
}
