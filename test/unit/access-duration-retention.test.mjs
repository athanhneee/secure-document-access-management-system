import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  DEFAULT_GRANT_MAX_DURATION_DAYS,
  buildAccessDurationPresets,
  resolveClassificationDefaultViewDays,
} from '../../packages/contracts/dist/index.js';
import {
  buildRequestWindowIso,
  mapReaderDocumentDto,
  mapReaderGrantDto,
  validateCustomRequestWindow,
} from '../../apps/web/app/reader/helpers.ts';
import {
  computeMaxGrantValidUntilLocal,
  validateDirectGrantTimeRange,
} from '../../apps/web/app/owner/grant-helpers.ts';
import { localizeApiErrorMessage } from '../../apps/web/lib/api-error-messages.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../..');

/**
 * Thuật toán: Kiểm Chứng Hồi Quy Đồng Bộ Trần 30 Ngày, Hạn Lưu Trữ Tài Liệu (`retention_until`),
 * Thời Hạn Mặc Định Theo Mức Mật (`default_view_days`) & Hộp Thoại Phê Duyệt Chủ Sở Hữu (`access-duration-retention`).
 */
describe('Frontend & Contracts Access Duration, Retention Ceiling & Default View Days', () => {
  it('caps quick request presets to 2 days when document retention_until is 2 days away (hides 3/7/14/30d)', () => {
    const now = new Date('2026-11-25T10:00:00.000Z');
    const plan = buildAccessDurationPresets({
      maxDurationDays: DEFAULT_GRANT_MAX_DURATION_DAYS,
      retentionUntil: '2026-11-27',
      defaultViewDays: 14,
      classificationCode: 'CONFIDENTIAL',
      now,
    });

    assert.equal(plan.ceiling.isRetentionExpired, false);
    assert.equal(plan.ceiling.cappedByRetention, true);
    assert.equal(plan.ceiling.maxWholeDays, 2);
    assert.equal(plan.defaultOptionKey, 'DAYS:2');
    const dayValues = plan.options.filter((o) => o.mode === 'DAYS').map((o) => o.days);
    assert.deepEqual(dayValues, [1, 2]);
    assert.ok(!dayValues.includes(3));
    assert.ok(!dayValues.includes(7));
    assert.ok(!dayValues.includes(14));
    assert.ok(!dayValues.includes(30));
  });

  it('applies classification default_view_days (TOP_SECRET=1, SECRET=7, CONFIDENTIAL=14, INTERNAL=30)', () => {
    assert.equal(resolveClassificationDefaultViewDays('TOP_SECRET'), 1);
    assert.equal(resolveClassificationDefaultViewDays('SECRET'), 7);
    assert.equal(resolveClassificationDefaultViewDays('CONFIDENTIAL'), 14);
    assert.equal(resolveClassificationDefaultViewDays('INTERNAL'), 30);

    const now = new Date('2026-11-25T10:00:00.000Z');
    const topSecretPlan = buildAccessDurationPresets({
      classificationCode: 'TOP_SECRET',
      defaultViewDays: 1,
      now,
    });
    assert.equal(topSecretPlan.defaultOptionKey, 'DAYS:1');
    assert.equal(topSecretPlan.recommendedDays, 1);

    const confidentialPlan = buildAccessDurationPresets({
      classificationCode: 'CONFIDENTIAL',
      defaultViewDays: 14,
      now,
    });
    assert.equal(confidentialPlan.defaultOptionKey, 'DAYS:14');
  });

  it('defaults download upgrade requests to KEEP_GRANT instead of extending a 2-day grant to 7 days', () => {
    const now = new Date('2026-11-25T10:00:00.000Z');
    const existingUntil = '2026-11-27T10:00:00.000Z';
    const plan = buildAccessDurationPresets({
      classificationCode: 'CONFIDENTIAL',
      defaultViewDays: 14,
      existingGrantValidUntil: existingUntil,
      intent: 'UPGRADE_DOWNLOAD',
      now,
    });

    assert.equal(plan.defaultOptionKey, 'KEEP_GRANT');
    const keepOption = plan.options.find((o) => o.key === 'KEEP_GRANT');
    assert.ok(keepOption);
    assert.equal(keepOption.untilIso, existingUntil);
  });

  it('offers UNTIL_RETENTION for documents expiring later today and blocks already-expired retention', () => {
    const sameDayNow = new Date('2026-11-25T05:00:00.000Z');
    const sameDayPlan = buildAccessDurationPresets({
      retentionUntil: '2026-11-25',
      classificationCode: 'INTERNAL',
      now: sameDayNow,
    });
    assert.equal(sameDayPlan.ceiling.isRetentionExpired, false);
    assert.equal(sameDayPlan.ceiling.maxWholeDays, 0);
    assert.equal(sameDayPlan.defaultOptionKey, 'UNTIL_RETENTION');

    const expiredPlan = buildAccessDurationPresets({
      retentionUntil: '2026-11-24',
      classificationCode: 'INTERNAL',
      now: sameDayNow,
    });
    assert.equal(expiredPlan.ceiling.isRetentionExpired, true);
    assert.deepEqual(expiredPlan.options, []);
  });

  it('enforces 30-day ceiling and retentionUntil in Reader validateCustomRequestWindow and buildRequestWindowIso', () => {
    // Use local-time anchor so naive datetime-local strings remain strictly after nowMs in any timezone.
    const nowMs = new Date(2026, 10, 25, 10, 0, 0).getTime();

    // > 30 days rejected (synced with GRANT_MAX_DURATION_DAYS)
    assert.match(
      validateCustomRequestWindow(true, '2026-11-26T10:00', '2026-12-30T10:00', nowMs) ?? '',
      /30 ngày/,
    );

    // Exceeding document retention_until rejected
    assert.match(
      validateCustomRequestWindow(true, '2026-11-25T11:00', '2026-12-01T11:00', nowMs, {
        retentionUntil: '2026-11-27',
      }) ?? '',
      /27\/11\/2026/,
    );

    // Within retention_until accepted (08:00 local is safely before both local & UTC end-of-day across all timezones)
    assert.equal(
      validateCustomRequestWindow(true, '2026-11-25T11:00', '2026-11-27T08:00', nowMs, {
        retentionUntil: '2026-11-27',
      }),
      null,
    );

    assert.throws(
      () =>
        buildRequestWindowIso(false, '', '', 7, {
          retentionUntil: '2026-11-27',
          now: new Date(nowMs),
        }),
      /27\/11\/2026/,
    );
  });

  it('enforces retentionUntil in Owner direct grant validation, max ceiling, DTO mappers, and API error localization', () => {
    const refNow = new Date('2026-11-25T07:00:00.000Z');
    assert.match(
      validateDirectGrantTimeRange('2026-11-25T07:00:00.000Z', '2026-12-02T07:00:00.000Z', {
        now: refNow,
        retentionUntil: '2026-11-27',
      }) ?? '',
      /27\/11\/2026/,
    );
    assert.equal(
      validateDirectGrantTimeRange('2026-11-25T07:00:00.000Z', '2026-11-27T07:00:00.000Z', {
        now: refNow,
        retentionUntil: '2026-11-27',
      }),
      null,
    );

    const maxLocal = computeMaxGrantValidUntilLocal('2026-11-25T07:00', 30, '2026-11-27');
    assert.ok(
      maxLocal && maxLocal.startsWith('2026-11-27T'),
      `Expected capped date on 2026-11-27, got ${maxLocal}`,
    );

    const mappedDoc = mapReaderDocumentDto({
      id: 'd-2d',
      title: 'Tài liệu 2 ngày',
      classificationLevelCode: 'TOP_SECRET',
      retentionUntil: '2026-11-27',
    });
    assert.equal(mappedDoc.retentionUntil, '2026-11-27');
    assert.equal(mappedDoc.defaultViewDays, 1);

    const mappedGrant = mapReaderGrantDto({
      grantId: 'g-2d',
      permissions: ['VIEW'],
      document: {
        id: 'd-2d',
        title: 'Tài liệu 2 ngày',
        classificationLevelCode: 'SECRET',
        retentionUntil: '2026-11-27',
        defaultViewDays: 7,
      },
    });
    assert.equal(mappedGrant.retentionUntil, '2026-11-27');
    assert.equal(mappedGrant.defaultViewDays, 7);

    const retentionExceededMsg = localizeApiErrorMessage(400, {
      errorCode: 'GRANT_DURATION_EXCEEDED',
      message: 'Requested access end time cannot exceed document retention date (2026-11-27).',
      details: { retentionUntil: '2026-11-27', reasonCode: 'EXCEEDS_DOCUMENT_RETENTION' },
    });
    assert.match(retentionExceededMsg, /27\/11\/2026/);
    assert.match(retentionExceededMsg, /thời hạn lưu trữ bảo mật/i);
  });

  it('wires default_view_days into Prisma seed-catalog and replaces hardcoded select in DecideRequestModal', () => {
    const seedCatalog = fs.readFileSync(
      path.join(repoRoot, 'packages/database/prisma/seed-catalog.ts'),
      'utf8',
    );
    assert.match(seedCatalog, /INTERNAL[\s\S]*default_view_days:\s*30/);
    assert.match(seedCatalog, /CONFIDENTIAL[\s\S]*default_view_days:\s*14/);
    assert.match(seedCatalog, /SECRET[\s\S]*default_view_days:\s*7/);
    assert.match(seedCatalog, /TOP_SECRET[\s\S]*default_view_days:\s*1/);

    const decideModal = fs.readFileSync(
      path.join(repoRoot, 'apps/web/app/owner/modals/decide-request-modal.tsx'),
      'utf8',
    );
    assert.doesNotMatch(decideModal, /<select\b/);
    assert.match(decideModal, /type="number"/);
    assert.match(decideModal, /existingGrant/);
    assert.match(decideModal, /Hạn lưu trữ tài liệu/);
  });
});
