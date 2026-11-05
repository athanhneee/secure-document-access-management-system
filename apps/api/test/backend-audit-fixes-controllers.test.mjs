import assert from 'node:assert/strict';
import { test } from 'node:test';
import { UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';

import { PUBLIC_ENDPOINT_METADATA } from '../dist/public-endpoint.js';
import { AccessSessionsController } from '../dist/modules/access-sessions/access-sessions.controller.js';
import { DocumentDeliveryController } from '../dist/modules/documents/document-delivery.controller.js';
import { DocumentsController } from '../dist/modules/documents/documents.controller.js';
import { SecurityOperationsController } from '../dist/modules/security-operations/security-operations.controller.js';
import { ReportsController } from '../dist/modules/reports/reports.controller.js';
import { NotificationsController } from '../dist/modules/notifications/notifications.controller.js';

test('AccessSessionsController — requires CSRF on terminateSession and 401 when unauthenticated', async () => {
  let csrfChecked = false;
  const mockCsrf = {
    assertRequest: () => {
      csrfChecked = true;
    },
  };

  const mockService = {
    listSessions: async () => ({ data: [] }),
    terminateSession: async (id) => ({ id, status: 'TERMINATED' }),
  };

  const controller = new AccessSessionsController(mockService, mockCsrf);

  await assert.rejects(
    () => controller.listSessions({ auth: null }),
    (err) => err instanceof UnauthorizedException,
  );

  await assert.rejects(
    () => controller.terminateSession('s-1', { auth: null }),
    (err) => err instanceof UnauthorizedException,
  );
  assert.equal(csrfChecked, true, 'CSRF assertion must be called before authentication check');
});

test('DocumentDeliveryController — downloadWithTicket is marked @PublicEndpoint() for one-time ticket redemption', () => {
  const reflector = new Reflector();
  const isPublic = reflector.get(
    PUBLIC_ENDPOINT_METADATA,
    DocumentDeliveryController.prototype.downloadWithTicket,
  );
  assert.equal(isPublic, true, 'downloadWithTicket must have @PublicEndpoint() metadata');
});

test('DocumentsController — checkRetention enforces CSRF protection and authentication', async () => {
  let csrfChecked = false;
  const mockCsrf = {
    assertRequest: () => {
      csrfChecked = true;
    },
  };
  const mockDocsService = {
    checkRetentionWarnings: async () => ({ checked: 10 }),
  };

  const controller = new DocumentsController(mockDocsService, null, mockCsrf);

  await assert.rejects(
    () => controller.checkRetention({ auth: null }),
    (err) => err instanceof UnauthorizedException,
  );
  assert.equal(csrfChecked, true, 'checkRetention must assert CSRF token');

  const res = await controller.checkRetention({
    auth: { userId: 1n, username: 'owner', roles: ['DOCUMENT_OWNER'], mfa: true },
  });
  assert.deepEqual(res, { checked: 10 });
});

test('SecurityOperationsController — mutation endpoints enforce CSRF and throw UnauthorizedException when unauthenticated', async () => {
  let csrfCheckCount = 0;
  const mockCsrf = {
    assertRequest: () => {
      csrfCheckCount++;
    },
  };

  const controller = new SecurityOperationsController(null, null, null, mockCsrf);
  const unauthReq = { auth: null };

  csrfCheckCount = 0;
  await assert.rejects(
    () => controller.updateAlertStatus('alt-1', { status: 'INVESTIGATING' }, unauthReq),
    (err) => err instanceof UnauthorizedException,
  );
  assert.equal(csrfCheckCount, 1);

  csrfCheckCount = 0;
  await assert.rejects(
    () => controller.assignAlert('alt-1', { assignedToUserId: '50' }, unauthReq),
    (err) => err instanceof UnauthorizedException,
  );
  assert.equal(csrfCheckCount, 1);

  csrfCheckCount = 0;
  await assert.rejects(
    () => controller.addAlertNote('alt-1', { note: 'test' }, unauthReq),
    (err) => err instanceof UnauthorizedException,
  );
  assert.equal(csrfCheckCount, 1);

  csrfCheckCount = 0;
  await assert.rejects(
    () => controller.createIncident({}, unauthReq),
    (err) => err instanceof UnauthorizedException,
  );
  assert.equal(csrfCheckCount, 1);

  csrfCheckCount = 0;
  await assert.rejects(
    () => controller.submitIncident('inc-1', {}, unauthReq),
    (err) => err instanceof UnauthorizedException,
  );
  assert.equal(csrfCheckCount, 1);

  csrfCheckCount = 0;
  await assert.rejects(
    () => controller.closeIncident('inc-1', {}, unauthReq),
    (err) => err instanceof UnauthorizedException,
  );
  assert.equal(csrfCheckCount, 1);

  csrfCheckCount = 0;
  await assert.rejects(
    () => controller.addIncidentAction('inc-1', {}, unauthReq),
    (err) => err instanceof UnauthorizedException,
  );
  assert.equal(csrfCheckCount, 1);

  csrfCheckCount = 0;
  await assert.rejects(
    () => controller.completeIncidentAction('123', {}, unauthReq),
    (err) => err instanceof UnauthorizedException,
  );
  assert.equal(csrfCheckCount, 1);

  csrfCheckCount = 0;
  await assert.rejects(
    () => controller.updateDetectionRule('MASS_DOWNLOAD', {}, unauthReq),
    (err) => err instanceof UnauthorizedException,
  );
  assert.equal(csrfCheckCount, 1);

  csrfCheckCount = 0;
  await assert.rejects(
    () => controller.runDetection({}, unauthReq),
    (err) => err instanceof UnauthorizedException,
  );
  assert.equal(csrfCheckCount, 1);
});

test('ReportsController & NotificationsController — mutation endpoints assert CSRF and throw UnauthorizedException', async () => {
  let reportsCsrf = false;
  const mockReportsCsrf = {
    assertRequest: () => {
      reportsCsrf = true;
    },
  };
  const reportsController = new ReportsController(null, mockReportsCsrf);

  await assert.rejects(
    () => reportsController.createExportJob({}, { auth: null }),
    (err) => err instanceof UnauthorizedException,
  );
  assert.equal(reportsCsrf, true, 'createExportJob must assert CSRF');

  let notificationsCsrf = false;
  const mockNotificationsCsrf = {
    assertRequest: () => {
      notificationsCsrf = true;
    },
  };
  const notificationsController = new NotificationsController(null, mockNotificationsCsrf);

  await assert.rejects(
    () => notificationsController.markAsRead('notif-1', { auth: null }),
    (err) => err instanceof UnauthorizedException,
  );
  assert.equal(notificationsCsrf, true, 'markAsRead must assert CSRF');
});
