import { Injectable, NotFoundException } from '@nestjs/common';
import { getDatabaseClient } from '@sda/database';
import { cidrMatch } from './policy-engine.js';
import type { PolicyEvaluationInput } from './abac.types.js';
import type { StoredDefinition, StoredRule } from './policy-compiler.js';
import { AppConfigService } from '../../config/config.service.js';
import { isAssignmentActive } from './assignment-validity.js';

@Injectable()
export class AbacRepository {
  private readonly database = getDatabaseClient();
  private readonly trustedCidrs: string[];

  constructor(config: AppConfigService) {
    this.trustedCidrs = config
      .get('ABAC_TRUSTED_NETWORK_CIDRS')
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean);
  }

  async currentPolicyVersion(): Promise<bigint> {
    const rows = await this.database.$queryRawUnsafe<Array<{ version: bigint }>>(
      'SELECT last_value AS version FROM abac_policy_version_seq',
    );
    return rows[0]?.version ?? 0n;
  }

  async loadPolicySource(options: { includeInactiveRuleId?: bigint } = {}): Promise<{
    definitions: StoredDefinition[];
    rules: StoredRule[];
  }> {
    const [definitions, rules] = await Promise.all([
      this.database.attributeDefinition.findMany({
        where: { is_active: true },
        orderBy: { code: 'asc' },
        select: {
          code: true,
          is_required: true,
          scope: true,
          value_type: true,
          attribute_options: {
            where: { is_active: true },
            orderBy: [{ sort_order: 'asc' }, { id: 'asc' }],
            select: { value_code: true, numeric_rank: true },
          },
        },
      }),
      this.database.policyRule.findMany({
        where:
          options.includeInactiveRuleId === undefined
            ? { is_active: true }
            : { OR: [{ is_active: true }, { id: options.includeInactiveRuleId }] },
        orderBy: [{ priority: 'asc' }, { id: 'asc' }],
        include: {
          policy_rule_conditions: {
            orderBy: [{ condition_group: 'asc' }, { sequence_no: 'asc' }, { id: 'asc' }],
            include: { attribute_definitions: { select: { code: true } } },
          },
        },
      }),
    ]);
    return {
      definitions: definitions.map((item) => ({
        code: item.code,
        required: item.is_required,
        scope: item.scope,
        valueType: item.value_type,
        options: item.attribute_options.map((option) => ({
          valueCode: option.value_code,
          numericRank: option.numeric_rank,
        })),
      })),
      rules: rules.map((rule) => ({
        id: rule.id,
        code: rule.code,
        effect: rule.effect,
        priority: rule.priority,
        targetResource: rule.target_resource,
        targetAction: rule.target_action,
        combiningAlgorithm: rule.combining_algorithm,
        validFrom: rule.valid_from,
        validTo: rule.valid_to,
        obligations: rule.obligations,
        conditions: rule.policy_rule_conditions.map((condition) => ({
          id: condition.id,
          definitionCode: condition.attribute_definitions?.code ?? null,
          contextKey: condition.context_key,
          operator: condition.operator,
          expectedValue: condition.expected_value,
          group: condition.condition_group,
          sequence: condition.sequence_no,
        })),
      })),
    };
  }

  async listPolicies() {
    return this.database.policyRule.findMany({
      orderBy: [{ priority: 'asc' }, { id: 'asc' }],
      select: {
        id: true,
        code: true,
        name: true,
        effect: true,
        priority: true,
        target_resource: true,
        target_action: true,
        combining_algorithm: true,
        is_active: true,
        valid_from: true,
        valid_to: true,
        version: true,
      },
    });
  }

  async listAttributes() {
    return this.database.attributeDefinition.findMany({
      orderBy: { code: 'asc' },
      select: {
        id: true,
        code: true,
        name: true,
        scope: true,
        value_type: true,
        is_required: true,
        is_multi_value: true,
        is_active: true,
        version: true,
        attribute_options: {
          where: { is_active: true },
          orderBy: [{ sort_order: 'asc' }, { id: 'asc' }],
          select: { id: true, value_code: true, display_name: true, numeric_rank: true },
        },
      },
    });
  }

  async simulationInput(input: {
    subjectUserId: bigint;
    resourceDocumentId: string;
    action: PolicyEvaluationInput['action'];
    time: Date;
    ip: string;
    deviceTrust: boolean;
    mfa: boolean;
    riskScore: number;
  }): Promise<PolicyEvaluationInput> {
    const [user, document, assignments, classification] = await Promise.all([
      this.database.user.findUnique({
        where: { id: input.subjectUserId },
        select: { id: true, department_id: true, status: true },
      }),
      this.database.document.findUnique({
        where: { id: input.resourceDocumentId },
        select: { id: true, owner_id: true, department_id: true, status: true },
      }),
      this.database.userAttributeAssignment.findMany({
        where: {
          user_id: input.subjectUserId,
          valid_from: { lte: input.time },
          AND: [{ OR: [{ valid_to: null }, { valid_to: { gt: input.time } }] }],
          attribute_definitions: { is_active: true },
        },
        orderBy: [{ attribute_definition_id: 'asc' }, { id: 'asc' }],
        include: {
          attribute_definitions: { select: { code: true } },
          attribute_options: { select: { value_code: true, numeric_rank: true, is_active: true } },
        },
      }),
      this.database.documentClassificationHistory.findFirst({
        where: {
          document_id: input.resourceDocumentId,
          effective_from: { lte: input.time },
          OR: [{ effective_to: null }, { effective_to: { gt: input.time } }],
        },
        orderBy: [{ effective_from: 'desc' }, { id: 'desc' }],
        include: {
          classification_levels: { select: { rank: true } },
          business_categories: { select: { code: true } },
        },
      }),
    ]);
    if (!user || !document)
      throw new NotFoundException('Simulation subject or resource was not found.');
    const activeAssignments = assignments.filter((assignment) =>
      isAssignmentActive(
        { validFrom: assignment.valid_from, validTo: assignment.valid_to },
        input.time,
      ),
    );
    const clearance = activeAssignments.find(
      (assignment) =>
        assignment.attribute_definitions.code === 'CLEARANCE_LEVEL' &&
        assignment.attribute_options?.is_active === true,
    );
    const projects = activeAssignments
      .filter((assignment) => assignment.attribute_definitions.code === 'PROJECT')
      .map((assignment) => assignment.attribute_options?.value_code ?? assignment.value_text)
      .filter((value): value is string => value !== null && value !== undefined)
      .sort();
    return {
      resourceType: 'DOCUMENT',
      action: input.action,
      subject: {
        clearanceRank: clearance?.attribute_options?.numeric_rank ?? null,
        departmentId: user.department_id?.toString() ?? null,
        employmentStatus: user.status,
        projects,
      },
      resource: {
        classificationRank: classification?.classification_levels.rank ?? null,
        ownerId: document.owner_id.toString(),
        departmentId: document.department_id.toString(),
        category: classification?.business_categories.code ?? null,
        status: document.status,
      },
      environment: {
        currentTime: input.time.toISOString(),
        ip: input.ip,
        trustedNetwork: this.trustedCidrs.some((range) => cidrMatch(input.ip, range)),
        deviceTrust: input.deviceTrust,
        mfa: input.mfa,
        riskScore: input.riskScore,
      },
    };
  }
}
