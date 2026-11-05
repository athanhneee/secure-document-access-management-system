import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { BadRequestException, ForbiddenException, Logger, NotFoundException } from '@nestjs/common';
import {
  DatabaseConflictError,
  DatabaseConstraintError,
  DatabaseNotFoundError,
  DatabaseUnavailableError,
} from '@sda/database';
import { AppErrorCode } from '@sda/contracts';
import { AppConfigService } from '../dist/config/config.service.js';
import { HttpExceptionFilter } from '../dist/common/filters/http-exception.filter.js';
import { SecurityDetectionService } from '../dist/modules/security-operations/security-detection.service.js';
import { executeCloseIncidentReport } from '../dist/modules/security-operations/incident-transitions.helper.js';
import { ZipBombGuardService } from '../dist/modules/documents/zip-bomb-guard.service.js';
import { lookupUsersWithClearance } from '../dist/modules/users/users-clearance.helper.js';
import { enqueueNotificationOutbox } from '../dist/modules/notifications/notification-outbox.helper.js';
import { assertCrossUserExportScope } from '../dist/modules/reports/export-artifact.helper.js';

/**
 * Thuật toán: Bắt phản hồi HTTP từ `HttpExceptionFilter` trên đối tượng `ArgumentsHost` giả lập của Fastify (HIGH-11).
 */
function captureFilteredError(filter, exception) {
  let status = 0;
  let body = null;
  filter.catch(exception, {
    switchToHttp: () => ({
      getRequest: () => ({ correlationId: 'corr-filter', url: '/api/v1/test', headers: {} }),
      getResponse: () => ({
        status(code) {
          status = code;
          return {
            header() {
              return this;
            },
            send: (payload) => (body = payload),
          };
        },
      }),
    }),
  });
  return { status, body };
}

test('[HIGH-11, HIGH-12] HttpExceptionFilter maps DatabaseError subclasses, updateRule throws 404, ZipBombGuard throws 400 & closeIncident rejects DRAFT', async () => {
  const filter = new HttpExceptionFilter();
  const conflictResp = captureFilteredError(filter, new DatabaseConflictError('dup'));
  assert.equal(conflictResp.status, 409);
  assert.equal(conflictResp.body.errorCode, AppErrorCode.RESOURCE_CONFLICT);
  assert.equal(captureFilteredError(filter, new DatabaseConstraintError('chk')).status, 400);
  assert.equal(captureFilteredError(filter, new DatabaseNotFoundError('missing')).status, 404);
  assert.equal(captureFilteredError(filter, new DatabaseUnavailableError('down')).status, 503);

  const detectionSvc = new SecurityDetectionService({}, undefined);
  await assert.rejects(
    () =>
      detectionSvc.updateRule(
        'NON_EXISTENT_RULE',
        { threshold: 10 },
        { userId: 1n, sessionId: 's', username: 'sec', roles: ['SECURITY_OFFICER'], mfa: true },
      ),
    NotFoundException,
  );

  const zipGuard = new ZipBombGuardService(new AppConfigService({}));
  await assert.rejects(
    () => zipGuard.inspectOfficeZip(Buffer.from('not-a-valid-zip-archive'), '.docx'),
    BadRequestException,
  );

  await assert.rejects(
    () =>
      executeCloseIncidentReport(
        { incidentReport: { findUnique: async () => ({ id: randomUUID(), status: 'DRAFT' }) } },
        undefined,
        randomUUID(),
        { closingNote: 'Cannot close draft directly' },
        { userId: 1n, sessionId: 's', username: 'sec', roles: ['SECURITY_OFFICER'], mfa: true },
      ),
    BadRequestException,
  );
});

test('[HIGH-13, HIGH-14] Department-scoped clearance lookup & cross-user export guard, plus notification outbox P2002 vs real DB error handling', async () => {
  const mockUsersDb = {
    user: {
      findMany: async () => [
        {
          id: 10n,
          username: 'alpha.user',
          full_name: 'Alpha User',
          department_id: 1n,
          departments: { id: 1n, name: 'Dept 1' },
          user_attribute_assignments_user_attribute_assignments_user_idTousers: [
            {
              attribute_options: {
                numeric_rank: 3,
                value_code: 'SECRET',
                display_name: 'Tối mật',
                is_active: true,
              },
            },
          ],
        },
        {
          id: 20n,
          username: 'beta.user',
          full_name: 'Beta User',
          department_id: 2n,
          departments: { id: 2n, name: 'Dept 2' },
          user_attribute_assignments_user_attribute_assignments_user_idTousers: [
            {
              attribute_options: {
                numeric_rank: 4,
                value_code: 'TOP_SECRET',
                display_name: 'Tuyệt mật',
                is_active: true,
              },
            },
          ],
        },
      ],
    },
  };
  const scopedAuthz = {
    visibleDepartmentIds: async (_p, resource) => (resource === 'USER' ? [1n] : []),
    hasPermission: async () => true,
  };

  const unauthLookup = await lookupUsersWithClearance(mockUsersDb, scopedAuthz, undefined);
  assert.equal(unauthLookup.data[0].clearanceCode, 'REDACTED');
  assert.equal(unauthLookup.data[1].clearanceCode, 'REDACTED');

  const scopedLookup = await lookupUsersWithClearance(mockUsersDb, scopedAuthz, {
    userId: 1n,
    sessionId: 's',
    username: 'mgr1',
    roles: [],
    mfa: true,
  });
  assert.equal(scopedLookup.data[0].clearanceCode, 'SECRET');
  assert.equal(scopedLookup.data[1].clearanceCode, 'REDACTED');

  await assert.rejects(
    () =>
      assertCrossUserExportScope(
        { user: { findUnique: async () => ({ department_id: 2n }) } },
        { hasPermission: async () => true, visibleDepartmentIds: async () => [1n] },
        { requester_user_id: 20n, export_type: 'AUDIT_LOGS', filter_params: {} },
        { userId: 1n, sessionId: 's', username: 'auditor.dept1', roles: ['AUDITOR'], mfa: true },
      ),
    ForbiddenException,
  );

  const logger = new Logger('OutboxTest');
  const dupRes = await enqueueNotificationOutbox(
    {
      notificationOutbox: {
        findUnique: async () => null,
        create: async () => {
          throw new DatabaseConflictError('Unique violation', { code: 'P2002' });
        },
      },
    },
    logger,
    { recipientId: 1n, notificationType: 'T', title: 'T', body: 'B', dedupKey: 'k1' },
  );
  assert.equal(dupRes.isDuplicate, true);

  await assert.rejects(() =>
    enqueueNotificationOutbox(
      {
        notificationOutbox: {
          findUnique: async () => null,
          create: async () => {
            throw new Error('ECONNRESET PostgreSQL socket closed');
          },
        },
      },
      logger,
      { recipientId: 1n, notificationType: 'T', title: 'T', body: 'B', dedupKey: 'k2' },
    ),
  );
});
