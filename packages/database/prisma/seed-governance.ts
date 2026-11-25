import type { Prisma } from '../src/generated/prisma/client.js';
import { baselineAbacPolicies, tierWatermarkConfigs } from './seed-catalog.js';

/**
 * Thuật toán: Gieo dữ liệu cấu hình đóng dấu theo cấp độ mật (`SECRET`, `TOP_SECRET`) và các chính sách ABAC Zero-Trust nền tảng (`seedGovernanceConfigsAndPolicies`).
 * Cơ chế hoạt động:
 *   - Đảm bảo luôn tồn tại cấu hình đóng dấu mặc định toàn cục cùng cấu hình riêng cho bậc `SECRET` và `TOP_SECRET` (chống lỗi khóa ngoại `23503`).
 *   - Cập nhật lũy đẳng (`upsert`) các luật `POL-DENY-HIGH-RISK-SESSION`, `POL-DENY-TOP-SECRET-WITHOUT-MFA` và `POL-PERMIT-CLEARED-ACTIVE-STAFF` kèm danh sách điều kiện thuộc tính ngữ cảnh.
 */
export async function seedGovernanceConfigsAndPolicies(params: {
  transaction: Prisma.TransactionClient;
  seedActorId: bigint;
  classificationIdByCode: ReadonlyMap<string, bigint>;
}): Promise<void> {
  const { transaction, seedActorId, classificationIdByCode } = params;

  const existingDefaultWatermark = await transaction.watermarkConfig.findFirst({
    where: { is_default: true, classification_level_id: null },
    select: { id: true },
  });
  if (!existingDefaultWatermark) {
    await transaction.watermarkConfig.create({
      data: {
        name: 'Cấu hình đóng dấu mặc định toàn hệ thống',
        classification_level_id: null,
        is_default: true,
        is_visible: true,
        template_text:
          'CONFIDENTIAL | {username} ({employeeCode}) | {documentCode} | {timestamp} | {shortToken}',
        opacity_percent: 25,
        rotation_degrees: -30,
        font_size: 12,
        color_hex: '#808080',
        include_qr_code: true,
        is_active: true,
        created_by: seedActorId,
      },
    });
  }

  for (const [
    levelCode,
    wmName,
    templateText,
    opacity,
    fontSize,
    colorHex,
  ] of tierWatermarkConfigs) {
    const levelId = classificationIdByCode.get(levelCode);
    if (levelId === undefined) continue;
    const existingTierWatermark = await transaction.watermarkConfig.findFirst({
      where: { classification_level_id: levelId },
      select: { id: true },
    });
    if (!existingTierWatermark) {
      await transaction.watermarkConfig.create({
        data: {
          name: wmName,
          classification_level_id: levelId,
          is_default: false,
          is_visible: true,
          template_text: templateText,
          opacity_percent: opacity,
          rotation_degrees: -35,
          font_size: fontSize,
          color_hex: colorHex,
          include_qr_code: true,
          is_active: true,
          created_by: seedActorId,
        },
      });
    }
  }

  for (const policy of baselineAbacPolicies) {
    const normalizedObligations = policy.obligations.map((ob) => ({ ...ob }));
    const savedPolicy = await transaction.policyRule.upsert({
      where: { code: policy.code },
      update: {
        name: policy.name,
        description: policy.description,
        effect: policy.effect,
        priority: policy.priority,
        target_resource: policy.target_resource,
        target_action: policy.target_action,
        combining_algorithm: policy.combining_algorithm,
        obligations: normalizedObligations,
        is_active: true,
      },
      create: {
        code: policy.code,
        name: policy.name,
        description: policy.description,
        effect: policy.effect,
        priority: policy.priority,
        target_resource: policy.target_resource,
        target_action: policy.target_action,
        combining_algorithm: policy.combining_algorithm,
        obligations: normalizedObligations,
        is_active: true,
        created_by: seedActorId,
      },
    });

    for (const cond of policy.conditions) {
      await transaction.policyRuleCondition.upsert({
        where: {
          policy_rule_id_condition_group_sequence_no: {
            policy_rule_id: savedPolicy.id,
            condition_group: cond.condition_group,
            sequence_no: cond.sequence_no,
          },
        },
        update: {
          context_key: cond.context_key,
          operator: cond.operator,
          expected_value: cond.expected_value,
        },
        create: {
          policy_rule_id: savedPolicy.id,
          context_key: cond.context_key,
          operator: cond.operator,
          expected_value: cond.expected_value,
          condition_group: cond.condition_group,
          sequence_no: cond.sequence_no,
        },
      });
    }
  }
}
