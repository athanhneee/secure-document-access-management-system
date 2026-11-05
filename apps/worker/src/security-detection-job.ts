import { getDatabaseClient } from '@sda/database';
import {
  loadDetectionRules,
  type DetectionRuleConfig,
  type PrismaClient,
} from './detection/rule-defaults.js';
import { evaluateDetectionRule } from './detection/rule-evaluators.js';

export { type DetectionRuleConfig, loadDetectionRules };

/**
 * Algorithm / Thuật toán: Bộ máy phát hiện bất thường an ninh định kỳ theo cửa sổ trượt thời gian (Sliding-Window Security Anomaly Detection Engine)
 * Mục đích: Đánh giá các mẫu hành vi rủi ro trên tập nhật ký kiểm toán trong cửa sổ `[now - windowMinutes, now]` và phát cảnh báo SOC có giảm chấn `cooldownMinutes`.
 */
export async function runDetectionCycle(options?: {
  databaseClient?: PrismaClient;
  now?: Date;
}): Promise<{ alertsCreated: number; rulesEvaluated: number }> {
  const database = options?.databaseClient ?? getDatabaseClient();
  const now = options?.now ?? new Date();
  const rules = await loadDetectionRules(database);

  let alertsCreated = 0;
  let rulesEvaluated = 0;

  for (const rule of rules) {
    if (!rule.isEnabled) continue;
    rulesEvaluated++;

    const windowStart = new Date(now.getTime() - rule.windowMinutes * 60 * 1000);
    const cooldownStart = new Date(now.getTime() - rule.cooldownMinutes * 60 * 1000);

    try {
      alertsCreated += await evaluateDetectionRule(database, rule, now, windowStart, cooldownStart);
    } catch (err) {
      console.warn('Error evaluating rule %s:', rule.ruleCode, err);
    }
  }

  return { alertsCreated, rulesEvaluated };
}

/**
 * Algorithm / Thuật toán: Bộ lập lịch định kỳ chống chồng lấn chu kỳ (Non-Overlapping Interval Scheduler)
 * điều phối chu kỳ phát hiện bất thường an ninh và giải phóng bộ đếm khi nhận tín hiệu `AbortSignal`.
 */
export function startSecurityDetectionJob(intervalMs: number, signal: AbortSignal): void {
  if (signal.aborted) return;

  let isRunning = false;
  const timer = setInterval(async () => {
    if (signal.aborted) {
      clearInterval(timer);
      return;
    }
    if (isRunning) return;
    isRunning = true;

    try {
      const result = await runDetectionCycle();
      if (result.alertsCreated > 0) {
        console.info('Security detection job generated %d alert(s).', result.alertsCreated);
      }
    } catch (err) {
      console.error('Security detection cycle failed:', err);
    } finally {
      isRunning = false;
    }
  }, intervalMs);

  signal.addEventListener(
    'abort',
    () => {
      clearInterval(timer);
      console.info('Security detection job stopped cleanly.');
    },
    { once: true },
  );

  console.info(`Security detection worker started (interval: ${intervalMs}ms).`);
}
