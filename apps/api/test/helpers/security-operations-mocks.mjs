import { randomUUID } from 'node:crypto';

export function createMassDownloadDetectionHarness(actorUserId = 100n) {
  const alertsTable = [];
  const linksTable = [];
  const now = new Date('2026-09-23T10:00:00Z');

  const mockAuditLogs = Array.from({ length: 6 }, (_, i) => ({
    id: BigInt(i + 1),
    actor_user_id: actorUserId,
    document_id: randomUUID(),
    action: 'DOCUMENT_DOWNLOADED',
    outcome: 'SUCCESS',
    occurred_at: new Date(now.getTime() - (i + 1) * 60 * 1000),
  }));

  const mockDb = {
    detectionRuleConfig: {
      findMany: async () => [
        {
          rule_code: 'MASS_DOWNLOAD',
          name: 'Mass Download Rule',
          is_enabled: true,
          severity: 'HIGH',
          threshold: 5,
          window_minutes: 10,
          cooldown_minutes: 30,
          parameters: {},
        },
      ],
    },
    auditLog: {
      findMany: async () => mockAuditLogs,
    },
    securityAlert: {
      findFirst: async ({ where }) =>
        alertsTable.find(
          (a) =>
            a.alert_type === where.alert_type &&
            a.detected_user_id === where.detected_user_id &&
            a.detected_at >= where.detected_at.gte,
        ),
      create: async ({ data }) => {
        alertsTable.push(data);
        return data;
      },
    },
    alertAuditLink: {
      createMany: async ({ data }) => {
        linksTable.push(...data);
        return { count: data.length };
      },
    },
    $transaction: async (fn) => fn(mockDb),
  };

  return { mockDb, alertsTable, linksTable };
}

export function createExportJobFixtures(requesterId = 101n) {
  const expiredJobId = randomUUID();
  const validJobId = randomUUID();
  const now = new Date();

  const jobs = new Map([
    [
      expiredJobId,
      {
        id: expiredJobId,
        requester_user_id: requesterId,
        export_type: 'AUDIT_LOGS',
        format: 'CSV',
        status: 'COMPLETED',
        file_path: 'C:/temp/export.csv',
        file_size_bytes: 1024n,
        sha256_hash: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
        mime_type: 'text/csv',
        row_count: 50,
        error_message: null,
        created_at: new Date(now.getTime() - 25 * 3600 * 1000),
        completed_at: new Date(now.getTime() - 24 * 3600 * 1000),
        expires_at: new Date(now.getTime() - 1 * 3600 * 1000),
      },
    ],
    [
      validJobId,
      {
        id: validJobId,
        requester_user_id: requesterId,
        export_type: 'INCIDENT_SUMMARY',
        format: 'PDF',
        status: 'COMPLETED',
        file_path: 'C:/temp/incident.pdf',
        file_size_bytes: 2048n,
        sha256_hash: '123456abcdef123456abcdef123456abcdef123456abcdef123456abcdef123456',
        mime_type: 'application/pdf',
        row_count: 1,
        error_message: null,
        created_at: now,
        completed_at: now,
        expires_at: new Date(now.getTime() + 24 * 3600 * 1000),
      },
    ],
  ]);

  const mockDb = {
    asyncExportJob: {
      findUnique: async ({ where }) => jobs.get(where.id) ?? null,
    },
  };

  return { expiredJobId, validJobId, mockDb };
}
