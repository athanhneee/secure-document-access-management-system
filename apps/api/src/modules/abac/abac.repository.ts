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

  /**
   * Algorithm / Thuật toán: Truy vấn phiên bản tuần tự đơn điệu chính sách ABAC có xét cờ `is_called` (PostgreSQL Sequence State Normalization).
   * Trả về `0` khi `abac_policy_version_seq` chưa từng được gọi `nextval()` (`is_called = false`), tránh va chạm `1n === 1n` ở lần kích hoạt luật đầu tiên.
   */
  async currentPolicyVersion(): Promise<bigint> {
    const rows = await this.database.$queryRawUnsafe<Array<{ version: bigint | number | string }>>(
      'SELECT CASE WHEN is_called THEN last_value ELSE 0 END AS version FROM abac_policy_version_seq',
    );
    return BigInt(rows[0]?.version ?? 0);
  }

  async loadPolicySource(
    options: {
      includeInactiveRuleId?: bigint;
      client?: Pick<ReturnType<typeof getDatabaseClient>, 'attributeDefinition' | 'policyRule'>;
    } = {},
  ): Promise<{
    definitions: StoredDefinition[];
    rules: StoredRule[];
  }> {
    const db = options.client ?? this.database;
    const [definitions, rules] = await Promise.all([
      db.attributeDefinition.findMany({
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
      db.policyRule.findMany({
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

  /**
   * Thuật toán: Liệt kê toàn bộ luật chính sách kèm mô tả, nghĩa vụ và danh sách điều kiện DNF sắp xếp tất định.
   */
  async listPolicies() {
    // CONFLICT-RESOLVED: Nạp đầy đủ description, obligations và policy_rule_conditions kèm attribute_definitions cho UI biên tập (HIGH-04)
    return this.database.policyRule.findMany({
      orderBy: [{ priority: 'asc' }, { id: 'asc' }],
      select: {
        id: true,
        code: true,
        name: true,
        description: true,
        effect: true,
        priority: true,
        target_resource: true,
        target_action: true,
        combining_algorithm: true,
        obligations: true,
        is_active: true,
        valid_from: true,
        valid_to: true,
        version: true,
        policy_rule_conditions: {
          orderBy: [{ condition_group: 'asc' }, { sequence_no: 'asc' }, { id: 'asc' }],
          select: {
            id: true,
            policy_rule_id: true,
            attribute_definition_id: true,
            context_key: true,
            operator: true,
            expected_value: true,
            condition_group: true,
            sequence_no: true,
            attribute_definitions: { select: { code: true, scope: true, value_type: true } },
          },
        },
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

  /**
   * Thuật toán: Tái dựng ngữ cảnh thuộc tính lịch sử tại mốc thời gian điểm (Point-in-Time Attribute Context Reconstruction).
   * Cơ chế hoạt động: Truy vấn song song thông tin chủ thể, tài liệu, các phép gán thuộc tính và lịch sử phân loại mật
   * thỏa mãn khoảng nửa mở `[effective_from, effective_to)` tại mốc `input.time`, trích xuất thứ bậc độ mật
   * và đối chiếu IP nguồn với danh sách dải mạng tin cậy CIDR.
   */
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
    // CONFLICT-RESOLVED: Chọn mức độ mật cao nhất (MAX numeric_rank) thay vì bản ghi đầu tiên theo id ASC (MED-04)
    let highestClearanceRank: number | null = null;
    for (const assignment of activeAssignments) {
      if (
        assignment.attribute_definitions.code === 'CLEARANCE_LEVEL' &&
        assignment.attribute_options?.is_active === true &&
        typeof assignment.attribute_options.numeric_rank === 'number'
      ) {
        if (
          highestClearanceRank === null ||
          assignment.attribute_options.numeric_rank > highestClearanceRank
        ) {
          highestClearanceRank = assignment.attribute_options.numeric_rank;
        }
      }
    }
    const projects = activeAssignments
      .filter(
        (assignment) =>
          assignment.attribute_definitions.code === 'PROJECT' &&
          assignment.attribute_options?.is_active !== false,
      )
      .map((assignment) => assignment.attribute_options?.value_code ?? assignment.value_text)
      .filter((value): value is string => value !== null && value !== undefined)
      .sort();
    return {
      resourceType: 'DOCUMENT',
      action: input.action,
      subject: {
        clearanceRank: highestClearanceRank,
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
