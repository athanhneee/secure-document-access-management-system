import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import {
  UpdateAlertStatusSchema,
  CreateIncidentReportSchema,
  CompleteIncidentActionSchema,
  AppErrorCode,
} from '@sda/contracts';
import { SecurityDetectionService } from '../dist/modules/security-operations/security-detection.service.js';
import { SecurityAlertsService } from '../dist/modules/security-operations/security-alerts.service.js';
import { IncidentsService } from '../dist/modules/security-operations/incidents.service.js';
import { createMassDownloadDetectionHarness } from './helpers/security-operations-mocks.mjs';

test('UpdateAlertStatusSchema — requires resolutionNote when transitioning to RESOLVED or FALSE_POSITIVE', () => {
  const validResolved = UpdateAlertStatusSchema.safeParse({
    status: 'RESOLVED',
    resolutionNote: 'Investigated and verified legitimate batch job.',
  });
  assert.ok(validResolved.success);

  const validFalsePositive = UpdateAlertStatusSchema.safeParse({
    status: 'FALSE_POSITIVE',
    resolutionNote: 'Authorized pen-test drill activity.',
  });
  assert.ok(validFalsePositive.success);

  const missingNoteResolved = UpdateAlertStatusSchema.safeParse({
    status: 'RESOLVED',
    resolutionNote: '',
  });
  assert.ok(!missingNoteResolved.success, 'Should reject empty resolutionNote for RESOLVED');

  const missingNoteFp = UpdateAlertStatusSchema.safeParse({
    status: 'FALSE_POSITIVE',
  });
  assert.ok(!missingNoteFp.success, 'Should reject missing resolutionNote for FALSE_POSITIVE');

  const validInvestigating = UpdateAlertStatusSchema.safeParse({
    status: 'INVESTIGATING',
  });
  assert.ok(validInvestigating.success, 'INVESTIGATING does not require resolutionNote');
});

test('CreateIncidentReportSchema — validates required fields and title length', () => {
  const valid = CreateIncidentReportSchema.safeParse({
    alertId: randomUUID(),
    title: 'Suspicious mass download from department A',
    summary: 'Detected 20 downloads in 3 minutes.',
    findings: 'Credentials likely leaked through phishing.',
    impactAssessment: 'High confidentiality breach risk.',
  });
  assert.ok(valid.success);

  const shortTitle = CreateIncidentReportSchema.safeParse({
    title: 'Hi',
    summary: 'Summary text',
    findings: 'Findings text',
  });
  assert.ok(!shortTitle.success, 'Should reject title shorter than 5 chars');
});

test('CompleteIncidentActionSchema — requires non-empty completionNote', () => {
  const valid = CompleteIncidentActionSchema.safeParse({
    completionNote: 'User credentials revoked and session terminated.',
  });
  assert.ok(valid.success);

  const empty = CompleteIncidentActionSchema.safeParse({
    completionNote: '   ',
  });
  assert.ok(!empty.success, 'Should reject whitespace completionNote');
});

test('SecurityDetectionService — creates 1 alert and suppresses duplicates within cooldown', async () => {
  const actorUserId = 100n;
  const { mockDb, alertsTable, linksTable } = createMassDownloadDetectionHarness(actorUserId);
  const detectionService = new SecurityDetectionService(mockDb);

  const run1 = await detectionService.runAllDetections(10);
  const newAlerts1 = run1.filter((r) => r.isNewAlert);
  assert.equal(newAlerts1.length, 1);
  assert.equal(alertsTable.length, 1);
  assert.equal(alertsTable[0].alert_type, 'MASS_DOWNLOAD');
  assert.equal(alertsTable[0].detected_user_id, actorUserId);
  assert.equal(linksTable.length, 6, 'All 6 audit logs must be linked');

  const run2 = await detectionService.runAllDetections(10);
  const suppressed2 = run2.filter((r) => r.suppressedByCooldown);
  const newAlerts2 = run2.filter((r) => r.isNewAlert);
  assert.equal(suppressed2.length, 1, 'Must suppress duplicate alert within cooldown');
  assert.equal(newAlerts2.length, 0, 'No new alerts should be created');
  assert.equal(alertsTable.length, 1, 'Total alerts must remain 1');
});

test('SecurityAlertsService — enforces valid transitions and requires resolution note', async () => {
  const alertId = randomUUID();
  let currentAlert = {
    id: alertId,
    alert_type: 'MASS_DOWNLOAD',
    severity: 'HIGH',
    status: 'OPEN',
    title: 'Mass download',
    description: 'Test',
    detected_user_id: 10n,
    document_id: null,
    detected_at: new Date(),
    assigned_to: null,
    resolved_at: null,
    resolution_note: null,
    users_security_alerts_detected_user_idTousers: null,
    users_security_alerts_assigned_toTousers: null,
    alert_audit_links: [],
    incident_reports: [],
  };

  const mockDb = {
    securityAlert: {
      findUnique: async () => currentAlert,
      update: async ({ data }) => {
        currentAlert = { ...currentAlert, ...data };
        return currentAlert;
      },
    },
  };

  const alertService = new SecurityAlertsService(mockDb);
  const secOfficer = { userId: 50n, username: 'sec_officer', roles: ['SECURITY_OFFICER'] };

  const updated1 = await alertService.updateAlertStatus(
    alertId,
    { status: 'INVESTIGATING' },
    secOfficer,
  );
  assert.equal(updated1.status, 'INVESTIGATING');

  await assert.rejects(
    async () => {
      await alertService.updateAlertStatus(alertId, { status: 'RESOLVED' }, secOfficer);
    },
    (err) => {
      const resp = typeof err.getResponse === 'function' ? err.getResponse() : err.response;
      assert.equal(resp?.errorCode, AppErrorCode.RESOLUTION_NOTE_REQUIRED);
      return true;
    },
  );

  const updated2 = await alertService.updateAlertStatus(
    alertId,
    { status: 'RESOLVED', resolutionNote: 'Root cause resolved. Account secured.' },
    secOfficer,
  );
  assert.equal(updated2.status, 'RESOLVED');
  assert.ok(updated2.resolvedAt !== null);
  assert.equal(updated2.resolutionNote, 'Root cause resolved. Account secured.');

  await assert.rejects(
    async () => {
      await alertService.updateAlertStatus(alertId, { status: 'OPEN' }, secOfficer);
    },
    (err) => {
      const resp = typeof err.getResponse === 'function' ? err.getResponse() : err.response;
      assert.equal(resp?.errorCode, AppErrorCode.ALERT_INVALID_TRANSITION);
      return true;
    },
  );
});

test('IncidentsService [SoD] — blocks AUDITOR role from creating or mutating incidents', async () => {
  const mockDb = {
    incidentReport: {
      create: async () => ({ id: randomUUID() }),
    },
  };

  const incidentsService = new IncidentsService(mockDb);
  const auditorUser = {
    userId: 99n,
    username: 'auditor_bob',
    roles: ['AUDITOR'],
  };

  await assert.rejects(
    async () => {
      await incidentsService.createIncidentReport(
        {
          title: 'Incident from auditor',
          summary: 'Auditor found suspicious activity',
          findings: 'Details',
        },
        auditorUser,
      );
    },
    (err) => {
      assert.equal(err.response?.errorCode, AppErrorCode.AUDITOR_CANNOT_MUTATE_INCIDENTS);
      return true;
    },
  );

  await assert.rejects(
    async () => {
      await incidentsService.submitIncidentReport(randomUUID(), {}, auditorUser);
    },
    (err) => {
      assert.equal(err.response?.errorCode, AppErrorCode.AUDITOR_CANNOT_MUTATE_INCIDENTS);
      return true;
    },
  );
});

test('SecurityDetectionService — matches canonical REFRESH_REUSE audit events from AuthService', async () => {
  const alertsTable = [];
  const mockDb = {
    detectionRuleConfig: { findMany: async () => [] },
    auditLog: {
      findMany: async ({ where }) => {
        if (Array.isArray(where?.action?.in) && where.action.in.includes('REFRESH_REUSE')) {
          return [{ id: 99n, actor_user_id: 77n, occurred_at: new Date() }];
        }
        return [];
      },
    },
    securityAlert: {
      findFirst: async () => null,
      create: async ({ data }) => {
        alertsTable.push(data);
        return data;
      },
    },
    alertAuditLink: {
      createMany: async ({ data }) => ({ count: data.length }),
    },
    $transaction: async (fn) => fn(mockDb),
  };

  const detectionService = new SecurityDetectionService(mockDb);
  const results = await detectionService.runAllDetections();
  const reuseAlert = results.find((r) => r.ruleCode === 'REFRESH_TOKEN_REUSE');
  assert.ok(reuseAlert?.isNewAlert, 'REFRESH_REUSE action must trigger REFRESH_TOKEN_REUSE alert');
  assert.equal(alertsTable[0].severity, 'HIGH');
});
