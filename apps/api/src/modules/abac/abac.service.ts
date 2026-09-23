import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { getDatabaseClient, withSerializableTransaction } from '@sda/database';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { canSimulatePolicy } from '../rbac/permission-matrix.js';
import { AbacAuditService } from './abac-audit.service.js';
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

  async listPolicies(): Promise<{ data: Array<Record<string, unknown>> }> {
    const policies = await this.repository.listPolicies();
    return {
      data: policies.map((policy) => ({
        ...policy,
        id: policy.id.toString(),
        version: policy.version.toString(),
      })),
    };
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

  async evaluate(input: PolicyEvaluationInput): Promise<PdpResult> {
    const start = performance.now();
    let isCached = false;
    let result: PdpResult;

    const version = await this.repository.currentPolicyVersion();
    const versionText = version.toString();
    const cached = await this.cache.get(versionText);
    if (cached) {
      try {
        result = evaluatePolicy(cached, input);
        isCached = true;
      } catch {
        await this.cache.invalidate(versionText);
      }
    }

    if (!result!) {
      try {
        const source = await this.repository.loadPolicySource();
        const compiled = compilePolicy(version, source.definitions, source.rules);
        await this.cache.put(compiled);
        result = evaluatePolicy(compiled, input);
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

  async activateRule(
    principal: AuthPrincipal,
    ruleId: bigint,
    context: RequestContext,
  ): Promise<{ id: string; policyVersion: string }> {
    const oldVersion = await this.repository.currentPolicyVersion();
    const source = await this.repository.loadPolicySource({ includeInactiveRuleId: ruleId });
    if (!source.rules.some((rule) => rule.id === ruleId)) {
      throw new NotFoundException('Policy rule was not found.');
    }
    try {
      compilePolicy(oldVersion, source.definitions, source.rules);
    } catch (error) {
      if (error instanceof PolicyCompilationError) {
        throw new BadRequestException({
          errorCode: 'INVALID_POLICY',
          message: 'Policy cannot be activated.',
          issues: error.issueCodes,
        });
      }
      throw error;
    }
    await withSerializableTransaction(
      async (transaction) => {
        const before = await transaction.policyRule.findUnique({
          where: { id: ruleId },
          select: { is_active: true, version: true },
        });
        if (!before) throw new NotFoundException('Policy rule was not found.');
        const after = await transaction.policyRule.update({
          where: { id: ruleId },
          data: { is_active: true },
          select: { is_active: true, version: true },
        });
        await this.audit.record(
          transaction,
          {
            action: 'POLICY_ACTIVATED',
            objectType: 'POLICY',
            objectId: ruleId.toString(),
            outcome: 'SUCCESS',
            details: {
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
      { client: this.database },
    );
    await this.cache.invalidate(oldVersion.toString());
    const policyVersion = await this.repository.currentPolicyVersion();
    return { id: ruleId.toString(), policyVersion: policyVersion.toString() };
  }
}
