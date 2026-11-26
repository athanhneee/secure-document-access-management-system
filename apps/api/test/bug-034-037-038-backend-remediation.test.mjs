import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { describe, it } from 'node:test';
import { ForbiddenException } from '@nestjs/common';
import { AuditService } from '../dist/modules/audit/audit.service.js';
import {
  executeCloseIncidentReport,
  executeCreateIncidentReport,
  executeSubmitIncidentReport,
} from '../dist/modules/security-operations/incident-transitions.helper.js';
import { AbacService } from '../dist/modules/abac/abac.service.js';
import { AbacRepository } from '../dist/modules/abac/abac.repository.js';
import { buildPepSubjectAttributes } from '../dist/modules/documents/pep-context-builder.js';
import { buildGrantSubjectAttributes } from '../dist/modules/access-grants/grant-pip.helper.js';
import { DepartmentsService } from '../dist/modules/departments/departments.service.js';
import { UsersService } from '../dist/modules/users/users.service.js';
import { PasswordService } from '../dist/modules/auth/password.service.js';

describe('BUG-034 Backend — Incident Audit documentId Linkage & IDOR-Safe Owner Query', () => {
  it('propagates security_alerts.document_id onto INCIDENT_REPORT_* audit log entries', async () => {
    const alertId = randomUUID();
    const linkedDocId = randomUUID();
    const writtenLogs = [];
    const storedReports = new Map();

    const mockDb = {
      securityAlert: {
        findUnique: async ({ where }) =>
          where.id === alertId ? { id: alertId, document_id: linkedDocId } : null,
      },
      user: {
        findUnique: async ({ where }) => ({ id: where.id }),
      },
      incidentAction: {
        count: async () => 0,
      },
      incidentReport: {
        create: async ({ data }) => {
          storedReports.set(data.id, { ...data });
          return data;
        },
        findUnique: async ({ where }) => storedReports.get(where.id) ?? null,
        update: async ({ where, data }) => {
          const cur = storedReports.get(where.id);
          Object.assign(cur, data);
          return cur;
        },
      },
    };
    const mockWriter = {
      writeLog: async (ev) => {
        writtenLogs.push(ev);
      },
    };
    const socActor = {
      userId: 4n,
      sessionId: 'soc-sess',
      username: 'soc.officer',
      roles: ['SECURITY_OFFICER'],
      mfa: true,
    };

    const incId = await executeCreateIncidentReport(
      mockDb,
      mockWriter,
      {
        alertId,
        title: 'Sự cố rò rỉ tài liệu mật',
        summary: 'Phát hiện truy cập trái phép vào tài liệu mật thuộc phòng Tài chính.',
      },
      socActor,
    );
    await executeSubmitIncidentReport(
      mockDb,
      mockWriter,
      incId,
      { submittedToOwner: 6n },
      socActor,
    );
    await executeCloseIncidentReport(
      mockDb,
      mockWriter,
      incId,
      { closingNote: 'Đã thu hồi quyền và khóa tài khoản vi phạm' },
      socActor,
    );

    assert.equal(writtenLogs.length, 3);
    for (const entry of writtenLogs) {
      assert.equal(entry.objectType, 'INCIDENT_REPORT');
      assert.equal(entry.documentId, linkedDocId);
    }
  });

  it('allows DOCUMENT_OWNER to query submittedToMe incidents (even with document_id = null) without leaking foreign/null-doc logs', async () => {
    const ownerId = 6n;
    const ownedDocId = randomUUID();
    const myIncidentId = randomUUID();
    const otherOwnerIncidentId = randomUUID();
    let capturedWhere = null;

    const allAuditRows = [
      {
        id: 1n,
        occurred_at: new Date('2026-11-26T08:00:00Z'),
        actor_user_id: 4n,
        actor_username: 'soc.officer',
        action: 'INCIDENT_REPORT_SUBMITTED',
        object_type: 'INCIDENT_REPORT',
        object_id: myIncidentId,
        document_id: null,
        access_session_id: null,
        outcome: 'SUCCESS',
        reason_code: null,
        ip_address: '10.0.0.1',
        user_agent: 'SOC',
        correlation_id: randomUUID(),
        details: { incidentCode: 'INC-MY-01' },
        chain_partition: 'SECURITY_OPERATIONS',
        chain_sequence: 1n,
        entry_hash: 'h1',
        previous_hash: null,
        hmac_key_version: 1,
        chain_algorithm: 'HMAC-SHA-256',
      },
      {
        id: 2n,
        occurred_at: new Date('2026-11-26T08:01:00Z'),
        actor_user_id: 99n,
        actor_username: 'other.user',
        action: 'LOGIN',
        object_type: 'AUTHENTICATION',
        object_id: null,
        document_id: null,
        access_session_id: null,
        outcome: 'SUCCESS',
        reason_code: null,
        ip_address: '10.0.0.2',
        user_agent: 'Web',
        correlation_id: randomUUID(),
        details: {},
        chain_partition: 'AUTH',
        chain_sequence: 2n,
        entry_hash: 'h2',
        previous_hash: null,
        hmac_key_version: 1,
        chain_algorithm: 'HMAC-SHA-256',
      },
      {
        id: 3n,
        occurred_at: new Date('2026-11-26T08:02:00Z'),
        actor_user_id: 4n,
        actor_username: 'soc.officer',
        action: 'INCIDENT_REPORT_SUBMITTED',
        object_type: 'INCIDENT_REPORT',
        object_id: otherOwnerIncidentId,
        document_id: null,
        access_session_id: null,
        outcome: 'SUCCESS',
        reason_code: null,
        ip_address: '10.0.0.1',
        user_agent: 'SOC',
        correlation_id: randomUUID(),
        details: { incidentCode: 'INC-OTHER-02' },
        chain_partition: 'SECURITY_OPERATIONS',
        chain_sequence: 3n,
        entry_hash: 'h3',
        previous_hash: null,
        hmac_key_version: 1,
        chain_algorithm: 'HMAC-SHA-256',
      },
    ];

    const matchesOwnerWhere = (row, where) => {
      if (where.action?.notIn?.includes(row.action)) return false;
      if (Array.isArray(where.OR)) {
        return where.OR.some((branch) => {
          if (branch.document_id?.in) {
            return row.document_id !== null && branch.document_id.in.includes(row.document_id);
          }
          if (branch.object_type && branch.object_id?.in) {
            return (
              row.object_type === branch.object_type &&
              row.object_id !== null &&
              branch.object_id.in.includes(row.object_id)
            );
          }
          return false;
        });
      }
      return false;
    };

    const mockDb = {
      document: {
        findMany: async () => [{ id: ownedDocId }],
      },
      incidentReport: {
        findMany: async ({ where }) =>
          where.submitted_to_owner === ownerId ? [{ id: myIncidentId }] : [],
      },
      auditLog: {
        count: async ({ where }) => {
          capturedWhere = where;
          return allAuditRows.filter((r) => matchesOwnerWhere(r, where)).length;
        },
        findMany: async ({ where }) => allAuditRows.filter((r) => matchesOwnerWhere(r, where)),
      },
    };

    const service = new AuditService({}, {}, mockDb);
    const res = await service.queryAuditLogs(
      {
        userId: ownerId,
        username: 'owner.demo',
        roles: ['DOCUMENT_OWNER'],
        sessionId: randomUUID(),
        mfa: true,
      },
      { page: 1, pageSize: 20, sort: 'occurred_at', order: 'desc' },
    );

    assert.ok(Array.isArray(capturedWhere.OR));
    // Must NEVER open { document_id: null } broadly
    assert.equal(
      capturedWhere.OR.some((clause) => 'document_id' in clause && clause.document_id === null),
      false,
    );
    assert.equal(res.data.length, 1);
    assert.equal(res.data[0].objectId, myIncidentId);
  });
});

describe('BUG-037 Backend — Custom Role POLICY:SIMULATE RBAC & Locked User employmentStatus', () => {
  it('checks AuthorizationService(POLICY, SIMULATE, requireGlobal: true) for Custom Roles and preserves unit-test fallback', async () => {
    const fakeEvalResult = {
      decision: 'PERMIT',
      reasonCode: 'POLICY_PERMIT',
      matchedRuleIds: ['1'],
      obligations: [],
      policyVersion: '1',
    };

    const repo = {
      simulationInput: async () => ({}),
    };
    const cache = {};
    const recordedAudits = [];
    const audit = {
      record: async (_tx, ev) => {
        recordedAudits.push(ev);
      },
    };
    const mockTxDb = {
      $transaction: async (fn) => fn({}),
    };

    // 1. With AuthorizationService injected: Custom Role with global POLICY:SIMULATE succeeds, scoped fails
    let grantGlobal = true;
    const authz = {
      hasPermission: async (_principal, resource, action, opts) =>
        resource === 'POLICY' &&
        action === 'SIMULATE' &&
        opts?.requireGlobal === true &&
        grantGlobal,
    };
    const serviceWithAuthz = new AbacService(repo, cache, audit, authz, mockTxDb);
    serviceWithAuthz.evaluate = async () => fakeEvalResult;

    const simOk = await serviceWithAuthz.simulate(
      {
        userId: 50n,
        sessionId: 's1',
        username: 'custom.global.sim',
        roles: ['CUSTOM_POLICY_AUDITOR'],
        mfa: true,
      },
      {
        subjectUserId: 2n,
        resourceDocumentId: randomUUID(),
        action: 'VIEW',
        time: new Date(),
        ip: '127.0.0.1',
        deviceTrust: true,
        mfa: true,
        riskScore: 0,
      },
      { ip: '127.0.0.1', correlationId: randomUUID() },
    );
    assert.equal(simOk.decision, 'PERMIT');
    assert.equal(recordedAudits.length, 1);
    assert.equal(recordedAudits[0].action, 'POLICY_SIMULATED');

    grantGlobal = false;
    await assert.rejects(
      () =>
        serviceWithAuthz.simulate(
          {
            userId: 50n,
            sessionId: 's1',
            username: 'scoped.sim',
            roles: ['CUSTOM_SCOPED_SIMULATOR'],
            mfa: true,
          },
          {
            subjectUserId: 2n,
            resourceDocumentId: randomUUID(),
            action: 'VIEW',
            time: new Date(),
            ip: '127.0.0.1',
            deviceTrust: true,
            mfa: true,
            riskScore: 0,
          },
          { ip: '127.0.0.1', correlationId: randomUUID() },
        ),
      ForbiddenException,
    );

    // 2. Without AuthorizationService injected: fallback canSimulatePolicy still blocks unauthorized roles
    const serviceFallback = new AbacService(repo, cache, audit);
    await assert.rejects(
      () =>
        serviceFallback.simulate(
          {
            userId: 51n,
            sessionId: 's2',
            username: 'auditor',
            roles: ['AUDITOR'],
            mfa: true,
          },
          {
            subjectUserId: 2n,
            resourceDocumentId: randomUUID(),
            action: 'VIEW',
            time: new Date(),
            ip: '127.0.0.1',
            deviceTrust: true,
            mfa: true,
            riskScore: 0,
          },
          { ip: '127.0.0.1', correlationId: randomUUID() },
        ),
      ForbiddenException,
    );
  });

  it('prevents stale EMPLOYMENT_STATUS=ACTIVE_STAFF from overriding LOCKED/DISABLED user.status in Simulator and PEP', async () => {
    const now = new Date('2026-11-26T09:00:00Z');
    const staleActiveAssignment = [
      {
        valid_from: new Date('2026-01-01T00:00:00Z'),
        valid_to: null,
        attribute_definitions: { code: 'EMPLOYMENT_STATUS', is_active: true },
        attribute_options: { value_code: 'ACTIVE_STAFF', is_active: true },
      },
    ];

    for (const nonActiveStatus of ['LOCKED', 'DISABLED']) {
      const mockDb = {
        user: {
          findUnique: async () => ({ id: 9n, department_id: 2n, status: nonActiveStatus }),
        },
        document: {
          findUnique: async () => ({
            id: 'doc-1',
            owner_id: 1n,
            department_id: 2n,
            status: 'ACTIVE',
          }),
        },
        userAttributeAssignment: {
          findFirst: async () => ({
            attribute_definitions: { is_active: true },
            attribute_options: { numeric_rank: 3, is_active: true },
          }),
          findMany: async () => staleActiveAssignment,
        },
        documentClassificationHistory: {
          findFirst: async () => ({
            classification_levels: { rank: 2 },
            business_categories: { code: 'OPS' },
          }),
        },
      };

      const pepAttrs = await buildPepSubjectAttributes(mockDb, 9n, now);
      const grantAttrs = await buildGrantSubjectAttributes(mockDb, 9n, now);
      assert.equal(pepAttrs.employmentStatus, nonActiveStatus);
      assert.equal(grantAttrs.employmentStatus, nonActiveStatus);

      const repo = Object.create(AbacRepository.prototype);
      repo.database = mockDb;
      repo.trustedCidrs = ['127.0.0.0/8'];
      const simInput = await repo.simulationInput({
        subjectUserId: 9n,
        resourceDocumentId: 'doc-1',
        action: 'VIEW',
        time: now,
        ip: '127.0.0.1',
        deviceTrust: true,
        mfa: true,
        riskScore: 10,
      });
      assert.equal(simInput.subject.employmentStatus, nonActiveStatus);
    }
  });
});

describe('BUG-038 Backend — Department Lookup Hierarchy & Scoped USER:MANAGE Profile Metadata', () => {
  it('exposes parentId in /departments/lookup and hasGlobalUserManage/userManageDepartmentIds in /users/me', async () => {
    const deptService = new DepartmentsService(
      { visibleDepartmentIds: async () => null },
      { record: async () => {} },
      {
        department: {
          findMany: async () => [
            { id: 1n, code: 'HQ', name: 'Trụ sở chính', parent_id: null },
            { id: 2n, code: 'FIN', name: 'Tài chính', parent_id: 1n },
          ],
        },
      },
    );
    const lookup = await deptService.lookup();
    assert.equal(lookup.data[0].parentId, null);
    assert.equal(lookup.data[1].parentId, '1');

    const userDb = {
      user: {
        findUnique: async () => ({
          id: 7n,
          username: 'dept.admin',
          email: 'dept.admin@sda.local',
          full_name: 'Quản trị Phòng',
          department_id: 2n,
          status: 'ACTIVE',
          version: 0,
          departments: { id: 2n, name: 'Tài chính' },
        }),
      },
      userAttributeAssignment: { findFirst: async () => null },
      mfaMethod: { count: async () => 1 },
    };
    const scopedUsersService = new UsersService(
      {
        effectiveGrants: async () => [
          {
            roleCode: 'DEPT_ADMIN',
            resource: 'USER',
            action: 'MANAGE',
            scopeDepartmentId: 2n,
          },
        ],
      },
      new PasswordService(),
      { record: async () => {} },
      userDb,
    );
    const meScoped = await scopedUsersService.currentUser({
      userId: 7n,
      sessionId: 's-dept',
      username: 'dept.admin',
      roles: ['DEPT_ADMIN'],
      mfa: true,
    });
    assert.equal(meScoped.hasGlobalUserManage, false);
    assert.deepEqual(meScoped.userManageDepartmentIds, ['2']);
  });
});
