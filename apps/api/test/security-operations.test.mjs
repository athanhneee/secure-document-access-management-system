import assert from 'node:assert/strict';
import { test } from 'node:test';
import { AppErrorCode } from '@sda/contracts';
import { sanitizeCsvCell, sanitizeCsvRow } from '../dist/modules/reports/csv-formula-sanitizer.js';
import { ExportJobService } from '../dist/modules/reports/export-job.service.js';
import { NotificationsService } from '../dist/modules/notifications/notifications.service.js';
import { HealthService } from '../dist/modules/system-health/health.service.js';
import { createExportJobFixtures } from './helpers/security-operations-mocks.mjs';

test('CSV Formula Sanitizer [SECURITY] — escapes dangerous formula prefixes (=, +, -, @, \\t, \\r)', () => {
  const dangerousCells = [
    '=CMD|"/C calc"!A0',
    '+123456',
    '-5+5',
    '@SUM(A1:A10)',
    '\t=1+1',
    '\r=HYPERLINK("http://attacker.com")',
  ];

  for (const cell of dangerousCells) {
    const sanitized = sanitizeCsvCell(cell);
    assert.ok(
      sanitized.startsWith("'"),
      `Cell "${cell}" must be prefixed with single quote, got "${sanitized}"`,
    );
  }

  const safeCells = ['Normal User Name', 'DOCUMENT_VIEWED', '12345', 'info@example.com'];
  for (const cell of safeCells) {
    assert.equal(sanitizeCsvCell(cell), cell);
  }

  const row = ['=2+2', 'normal', '@hack'];
  const sanitizedRow = sanitizeCsvRow(row);
  assert.equal(sanitizedRow[0], "'=2+2");
  assert.equal(sanitizedRow[1], 'normal');
  assert.equal(sanitizedRow[2], "'@hack");
});

test('ExportJobService — validates TTL and restricts download to requester or authorized roles', async () => {
  const requesterId = 101n;
  const otherUserId = 202n;
  const { expiredJobId, validJobId, mockDb } = createExportJobFixtures(requesterId);

  const exportService = new ExportJobService(mockDb);
  exportService['memoryStorage'].set(validJobId, Buffer.from('mock pdf content'));

  await assert.rejects(
    async () => {
      await exportService.downloadExportJob(expiredJobId, {
        userId: requesterId,
        username: 'user1',
        roles: ['USER'],
      });
    },
    (err) => {
      const resp = typeof err.getResponse === 'function' ? err.getResponse() : err.response;
      assert.equal(resp?.errorCode, AppErrorCode.EXPORT_JOB_EXPIRED);
      return true;
    },
  );

  await assert.rejects(
    async () => {
      await exportService.downloadExportJob(validJobId, {
        userId: otherUserId,
        username: 'user2',
        roles: ['USER'],
      });
    },
    (err) => {
      const resp = typeof err.getResponse === 'function' ? err.getResponse() : err.response;
      assert.equal(resp?.errorCode, AppErrorCode.EXPORT_UNAUTHORIZED);
      return true;
    },
  );

  const downloadInfo = await exportService.downloadExportJob(validJobId, {
    userId: requesterId,
    username: 'user1',
    roles: ['USER'],
  });
  assert.equal(downloadInfo.mimeType, 'application/pdf');
  assert.ok(downloadInfo.buffer.length > 0);
});

test('NotificationsService — deduplicates outbox entries with identical deduplication key', async () => {
  const outboxMap = new Map();
  const notificationsList = [];

  const mockDb = {
    notification: {
      create: async ({ data }) => {
        notificationsList.push(data);
        return data;
      },
    },
    notificationOutbox: {
      findUnique: async ({ where }) => outboxMap.get(where.deduplication_key) ?? null,
      create: async ({ data }) => {
        outboxMap.set(data.deduplication_key, data);
        return data;
      },
    },
  };

  const service = new NotificationsService(mockDb);

  const res1 = await service.sendNotification({
    recipientId: 456n,
    notificationType: 'SECURITY_ALERT',
    title: 'Suspicious login',
    body: 'Detected unrecognized IP',
    deduplicationKey: 'ALERT:MASS_DOWNLOAD:USER_456',
  });
  assert.equal(res1.isDuplicate, false);
  assert.ok(res1.outboxId);

  const res2 = await service.sendNotification({
    recipientId: 456n,
    notificationType: 'SECURITY_ALERT',
    title: 'Suspicious login',
    body: 'Detected unrecognized IP',
    deduplicationKey: 'ALERT:MASS_DOWNLOAD:USER_456',
  });
  assert.equal(
    res2.isDuplicate,
    true,
    'Second notification with identical key must be deduplicated',
  );
  assert.equal(outboxMap.size, 1, 'Only one outbox entry must be created');
});

test('HealthService — reads live operational metrics without replacing with business snapshots', async () => {
  const mockConfig = {
    get: (key) => {
      if (key === 'DATABASE_URL') return 'postgresql://localhost:5432/test?schema=public';
      if (key === 'REDIS_URL') return 'redis://127.0.0.1:6379';
      if (key === 'STORAGE_ENDPOINT') return '127.0.0.1';
      if (key === 'STORAGE_PORT') return '9000';
      return '';
    },
  };

  const healthService = new HealthService(mockConfig);

  const metrics = await healthService.getLiveMetrics();
  assert.ok(metrics.timestamp);
  assert.ok(metrics.process.uptimeSeconds >= 0);
  assert.ok(metrics.process.heapUsedMb > 0);
  assert.ok(metrics.operational.openAlertsCount >= 0);

  const snapshot = await healthService.captureBusinessSnapshot('SECURE_CORE', 'HEALTHY', {
    activeUsersCount: 150,
    openAlertsCount: 3,
  });
  assert.ok(snapshot === null || snapshot.id);
});
