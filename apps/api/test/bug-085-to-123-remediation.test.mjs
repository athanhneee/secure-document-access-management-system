import 'reflect-metadata';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { UniqueConstraintError, DatabaseConstraintError } from '@sda/database';
import { AppErrorCode } from '@sda/contracts';

import { REQUIRED_ANY_PERMISSION_METADATA } from '../dist/modules/rbac/require-permission.js';
import { SecurityOperationsController } from '../dist/modules/security-operations/security-operations.controller.js';
import { DepartmentsController } from '../dist/modules/departments/departments.controller.js';
import { UsersService } from '../dist/modules/users/users.service.js';
import { PasswordService } from '../dist/modules/auth/password.service.js';
import { expirePreviousDepartmentRoles } from '../dist/modules/users/users-clearance.helper.js';
import { assertDepartmentHasNoActiveDependents } from '../dist/modules/departments/department-tree.helper.js';
import { DepartmentsService } from '../dist/modules/departments/departments.service.js';
import { canonicalizeIpAddress } from '../dist/modules/abac/cidr.js';
import {
  matchesCondition,
  parseStrictIsoTimestamp,
} from '../dist/modules/abac/policy-condition-matcher.js';
import { buildPolicyConditionRows } from '../dist/modules/abac/abac-policy-dto.helper.js';
import { LoginRateLimitService } from '../dist/modules/auth/login-rate-limit.service.js';
import { executeChangePassword } from '../dist/modules/auth/auth-password.helper.js';
import { HttpExceptionFilter } from '../dist/common/filters/http-exception.filter.js';
import { redactSensitiveData } from '../dist/common/logger/redaction.js';
import { TokenService } from '../dist/modules/auth/token.service.js';
import { AuthController } from '../dist/modules/auth/auth.controller.js';
import { ALLOW_PRE_MFA_METADATA } from '../dist/modules/auth/allow-pre-mfa.js';
import { executeVerifyWebAuthnEnrollment } from '../dist/modules/auth/auth-webauthn.helper.js';
import { AccessRequestsService } from '../dist/modules/access-requests/access-requests.service.js';
import { executeAccessRequestDecision } from '../dist/modules/access-requests/access-request-decision.helper.js';
import { AccessGrantsService } from '../dist/modules/access-grants/access-grants.service.js';
import { assertWithinMaxGrantDuration } from '../dist/modules/access-grants/grant-retention-bounds.helper.js';
import { AccessSessionsService } from '../dist/modules/access-sessions/access-sessions.service.js';
import { persistCleanIngestedVersionWithStatus } from '../dist/modules/documents/ingestion-version.helper.js';
import { AuditRedactionService } from '../dist/modules/audit/audit-redaction.service.js';
import { AuditService } from '../dist/modules/audit/audit.service.js';
import { assertLiveExportDownloadAuthorization } from '../dist/modules/reports/export-access-policy.helper.js';
import { traceWatermarkToken } from '../dist/modules/watermarks/watermark-forensics.helper.js';
import {
  buildSearchWhereClause,
  escapeSqlLikePattern,
} from '../dist/modules/documents/document-search-query.helper.js';
import {
  executeActivateDocument,
  executeArchiveDocument,
} from '../dist/modules/documents/document-lifecycle-transitions.helper.js';
import { executeReclassifyDocument } from '../dist/modules/documents/document-classification.helper.js';

const adminPrincipal = {
  userId: 1n,
  sessionId: 'sess-admin',
  username: 'sysadmin',
  roles: ['SYSTEM_ADMIN'],
  mfa: true,
};

const reqCtx = { ip: '127.0.0.1', correlationId: 'corr-bug-suite' };

test('BUG-085 & BUG-092: RBAC @RequireAnyPermission metadata on detection rules and departments lookup', () => {
  const rulesMeta = Reflect.getMetadata(
    REQUIRED_ANY_PERMISSION_METADATA,
    SecurityOperationsController.prototype.getDetectionRules,
  );
  assert.ok(Array.isArray(rulesMeta), 'getDetectionRules must use @RequireAnyPermission');
  assert.ok(
    rulesMeta.some((p) => p.resource === 'SECURITY_ALERT' && p.action === 'VIEW'),
    'must include SECURITY_ALERT:VIEW',
  );
  assert.ok(
    rulesMeta.some((p) => p.resource === 'SECURITY_ALERT' && p.action === 'MANAGE'),
    'must include SECURITY_ALERT:MANAGE',
  );

  const lookupMeta = Reflect.getMetadata(
    REQUIRED_ANY_PERMISSION_METADATA,
    DepartmentsController.prototype.lookup,
  );
  assert.ok(Array.isArray(lookupMeta), 'departments.lookup must use @RequireAnyPermission');
  assert.ok(
    lookupMeta.some((p) => p.resource === 'ATTRIBUTE' && p.action === 'MANAGE'),
    'departments.lookup must permit ATTRIBUTE:MANAGE',
  );
});

test('BUG-098: UsersService.list supports backward-compatible default and server-side pagination/filtering', async () => {
  let capturedFindArgs = null;
  const sampleRow = {
    id: 5n,
    employee_code: 'EMP-005',
    username: 'nguyenvana',
    email: 'vana@sda.local',
    full_name: 'Nguyễn Văn A',
    department_id: null,
    status: 'ACTIVE',
    failed_login_count: 0,
    locked_until: null,
    disabled_at: null,
    last_login_at: null,
    password_changed_at: null,
    created_at: new Date(),
    updated_at: new Date(),
    version: 1,
    departments: null,
    user_roles_user_roles_user_idTousers: [],
    user_mfa_methods: [],
    user_attribute_assignments_user_attribute_assignments_user_idTousers: [],
  };

  const db = {
    user: {
      findMany: async (args) => {
        capturedFindArgs = args;
        return [sampleRow];
      },
      count: async () => 5,
    },
  };
  const authz = {
    visibleDepartmentIds: async () => null,
  };
  const service = new UsersService(authz, new PasswordService(), { record: async () => {} }, db);

  const defaultRes = await service.list(adminPrincipal);
  assert.equal(defaultRes.data.length, 1);
  assert.equal(defaultRes.page, 1);
  assert.equal(defaultRes.pageSize, 200);
  assert.equal(defaultRes.total, 5);
  assert.equal(defaultRes.totalPages, 1);
  assert.equal(defaultRes.truncated, true);

  const pagedRes = await service.list(adminPrincipal, {
    page: 2,
    pageSize: 2,
    search: 'nguyen',
    status: 'ACTIVE',
    departmentId: 'UNASSIGNED',
  });
  assert.equal(capturedFindArgs.skip, 2);
  assert.equal(capturedFindArgs.take, 2);
  assert.equal(capturedFindArgs.where.status, 'ACTIVE');
  assert.equal(capturedFindArgs.where.department_id, null);
  assert.ok(Array.isArray(capturedFindArgs.where.OR));
  assert.equal(pagedRes.page, 2);
  assert.equal(pagedRes.pageSize, 2);
  assert.equal(pagedRes.total, 5);
  assert.equal(pagedRes.totalPages, 3);
  assert.equal(pagedRes.truncated, true);
});

test('BUG-099 & BUG-123(3): executeArchiveDocument & executeReclassifyDocument publish SSE and executeActivateDocument uses CAS updateMany', async () => {
  const publishedEvents = [];
  const docId = randomUUID();
  const mockRealtime = {
    publish: (ev) => publishedEvents.push(ev),
  };
  const mockAuthz = { hasPermission: async () => true };

  let casReturnedZero = true;
  let updateManyCalls = 0;
  const casDb = {
    document: {
      findUnique: async () => ({
        id: docId,
        owner_id: 10n,
        department_id: 100n,
        title: 'Báo cáo Kiểm toán Q4',
        status: 'DRAFT',
        version: 3,
        current_version_id: 100n,
        users: { status: 'ACTIVE' },
        departments: { is_active: true },
        current_version: { id: 100n, scan_status: 'CLEAN' },
        classification_history: [
          {
            classification_level_id: 1n,
            business_category_id: 1n,
            classification_levels: {
              code: 'INTERNAL',
              rank: 1,
              is_active: true,
              allow_download: true,
            },
            business_categories: { code: 'FIN', is_active: true },
          },
        ],
      }),
      updateMany: async () => {
        updateManyCalls += 1;
        return { count: casReturnedZero ? 0 : 1 };
      },
    },
  };

  await assert.rejects(
    () =>
      executeActivateDocument({
        database: casDb,
        authorization: mockAuthz,
        audit: { record: async () => {} },
        documentId: docId,
        principal: {
          userId: 10n,
          sessionId: 's',
          username: 'owner',
          roles: ['DOCUMENT_OWNER'],
          mfa: false,
        },
        context: reqCtx,
      }),
    ConflictException,
  );

  casReturnedZero = false;
  await executeActivateDocument({
    database: casDb,
    authorization: mockAuthz,
    audit: { record: async () => {} },
    documentId: docId,
    principal: {
      userId: 10n,
      sessionId: 's',
      username: 'owner',
      roles: ['DOCUMENT_OWNER'],
      mfa: false,
    },
    context: reqCtx,
  });
  assert.equal(updateManyCalls, 2);

  const archiveDb = {
    document: {
      findUnique: async () => ({
        id: docId,
        owner_id: 10n,
        department_id: 100n,
        status: 'ACTIVE',
        version: 4,
        classification_history: [{ classification_levels: { rank: 1 } }],
      }),
      update: async () => ({ id: docId, status: 'ARCHIVED' }),
    },
    documentVersion: {
      findMany: async () => [{ id: 100n }],
    },
    accessGrant: {
      findMany: async () => [
        { id: 'grant-1', principal_type: 'USER', principal_user_id: 22n, principal_role_id: null },
      ],
      updateMany: async () => ({ count: 1 }),
    },
    accessSession: {
      findMany: async () => [{ id: 'sess-1', user_id: 22n }],
      updateMany: async () => ({ count: 1 }),
    },
    accessRequest: {
      updateMany: async () => ({ count: 0 }),
    },
  };
  archiveDb.$transaction = async (fn) => fn(archiveDb);

  await executeArchiveDocument({
    database: archiveDb,
    authorization: mockAuthz,
    cache: { invalidateAll: () => {} },
    audit: { record: async () => {} },
    realtime: mockRealtime,
    documentId: docId,
    input: { reason: 'Hết thời hạn hiệu lực' },
    principal: {
      userId: 10n,
      sessionId: 's',
      username: 'owner',
      roles: ['DOCUMENT_OWNER'],
      mfa: false,
    },
    context: reqCtx,
  });

  assert.ok(
    publishedEvents.some(
      (e) => e.type === 'ACCESS_GRANT_UPDATED' && e.payload.reason === 'DOCUMENT_ARCHIVED',
    ),
  );
  assert.ok(
    publishedEvents.some((e) => e.type === 'DOCUMENT_UPDATED' && e.payload.action === 'ARCHIVED'),
  );
  assert.ok(
    publishedEvents.some(
      (e) => e.type === 'ACCESS_SESSION_UPDATED' && e.payload.reason === 'DOCUMENT_ARCHIVED',
    ),
  );

  publishedEvents.length = 0;
  const reclassifyDb = {
    document: {
      findUnique: async () => ({
        id: docId,
        owner_id: 10n,
        department_id: 100n,
        status: 'ACTIVE',
      }),
    },
    classificationLevel: {
      findUnique: async () => ({
        id: 2n,
        code: 'CONFIDENTIAL',
        rank: 1,
        is_active: true,
        allow_download: false,
      }),
    },
    businessCategory: {
      findUnique: async () => ({ id: 1n, code: 'FIN', is_active: true }),
    },
    documentClassificationHistory: {
      findFirst: async () => ({
        id: 1n,
        classification_levels: { rank: 1 },
      }),
      update: async () => ({}),
      create: async () => ({}),
    },
    accessGrant: {
      findMany: async () => [],
    },
    accessGrantPermission: {
      findMany: async () => [],
      deleteMany: async () => ({ count: 0 }),
    },
    userAttributeAssignment: {
      findFirst: async () => ({ attribute_options: { numeric_rank: 3, is_active: true } }),
    },
  };
  reclassifyDb.$transaction = async (fn) => fn(reclassifyDb);

  await executeReclassifyDocument({
    database: reclassifyDb,
    authorization: mockAuthz,
    cache: { invalidateAll: () => {} },
    audit: { record: async () => {} },
    realtime: mockRealtime,
    documentId: docId,
    input: {
      classificationLevelId: 2n,
      businessCategoryId: 1n,
      reason: 'Điều chỉnh phân loại bảo mật',
    },
    principal: {
      userId: 10n,
      sessionId: 's',
      username: 'owner',
      roles: ['DOCUMENT_OWNER'],
      mfa: false,
    },
    context: reqCtx,
  });
  assert.ok(
    publishedEvents.some(
      (e) => e.type === 'ACCESS_GRANT_UPDATED' && e.payload.reason === 'DOCUMENT_RECLASSIFIED',
    ),
  );
  assert.ok(
    publishedEvents.some(
      (e) => e.type === 'DOCUMENT_UPDATED' && e.payload.action === 'RECLASSIFIED',
    ),
  );
});

test('BUG-104: ABAC PolicyConditionMatcher canonicalizes IPv4-mapped IPv6, IPv6 shorthand, and strict ISO timestamps', () => {
  assert.equal(canonicalizeIpAddress('::ffff:10.20.30.40'), canonicalizeIpAddress('10.20.30.40'));
  assert.equal(
    canonicalizeIpAddress('2001:0db8:0000:0000:0000:0000:0000:0001'),
    canonicalizeIpAddress('2001:DB8::1'),
  );

  const checkMatch = (operator, actual, expected) =>
    matchesCondition(
      { attribute: 'environment.ip', operator, expected },
      { 'environment.ip': actual },
    );

  assert.equal(checkMatch('EQ', '::ffff:192.168.1.50', '192.168.1.50'), true);
  assert.equal(checkMatch('IN', '::ffff:192.168.1.50', ['10.0.0.1', '192.168.1.50']), true);
  assert.equal(checkMatch('EQ', '2026-06-15T17:00:00+07:00', '2026-06-15T10:00:00.000Z'), true);
  assert.equal(parseStrictIsoTimestamp('DOC-2026-01'), null);
  assert.equal(parseStrictIsoTimestamp('2026-02-31T00:00:00Z'), null);
  assert.equal(checkMatch('EQ', 'DOC-2026-01', '2026-01-01T00:00:00.000Z'), false);
});

test('BUG-105: UsersService enforces strict explicit status state machine with 409 ConflictException', async () => {
  const users = new Map([
    [
      2n,
      {
        id: 2n,
        employee_code: 'E2',
        username: 'u2',
        email: 'u2@sda.local',
        full_name: 'User 2',
        department_id: null,
        status: 'DISABLED',
        failed_login_count: 3,
        locked_until: new Date(Date.now() + 60_000),
        disabled_at: new Date(),
        last_login_at: null,
        password_changed_at: null,
        created_at: new Date(),
        updated_at: new Date(),
        version: 1,
        departments: null,
        user_roles_user_roles_user_idTousers: [],
        user_mfa_methods: [],
        user_attribute_assignments_user_attribute_assignments_user_idTousers: [],
      },
    ],
    [
      3n,
      {
        id: 3n,
        employee_code: 'E3',
        username: 'u3',
        email: 'u3@sda.local',
        full_name: 'User 3',
        department_id: null,
        status: 'PENDING',
        failed_login_count: 0,
        locked_until: null,
        disabled_at: null,
        last_login_at: null,
        password_changed_at: null,
        created_at: new Date(),
        updated_at: new Date(),
        version: 0,
        departments: null,
        user_roles_user_roles_user_idTousers: [],
        user_mfa_methods: [],
        user_attribute_assignments_user_attribute_assignments_user_idTousers: [],
      },
    ],
  ]);

  const tx = {
    user: {
      findUnique: async ({ where }) => users.get(where.id) ?? null,
      findUniqueOrThrow: async ({ where }) => users.get(where.id),
      updateMany: async ({ where, data }) => {
        const cur = users.get(where.id);
        if (
          !cur ||
          cur.version !== where.version ||
          (where.status && cur.status !== where.status)
        ) {
          return { count: 0 };
        }
        const { version: _v, ...rest } = data;
        users.set(where.id, { ...cur, ...rest, version: cur.version + 1 });
        return { count: 1 };
      },
    },
    authSession: { updateMany: async () => ({ count: 0 }) },
  };
  const db = { ...tx, $transaction: async (fn) => fn(tx) };
  const authz = {
    hasPermission: async () => true,
    assertPermission: async () => {},
    invalidateUser: async () => {},
  };
  const service = new UsersService(authz, new PasswordService(), { record: async () => {} }, db);

  // Blocks DISABLED -> LOCKED bypass, DISABLED -> DISABLED, and PENDING -> UNLOCKED
  await assert.rejects(() => service.lock(adminPrincipal, 2n, 1, reqCtx), ConflictException);
  await assert.rejects(() => service.disable(adminPrincipal, 2n, 1, reqCtx), ConflictException);
  await assert.rejects(() => service.unlock(adminPrincipal, 3n, 0, reqCtx), ConflictException);
  await assert.rejects(() => service.lock(adminPrincipal, 3n, 0, reqCtx), ConflictException);

  // Allows PENDING -> ACTIVE via reactivate and DISABLED -> ACTIVE clearing disabled_at / locked_until / failed_login_count
  const reactivatedPending = await service.reactivate(adminPrincipal, 3n, 0, reqCtx);
  assert.equal(reactivatedPending.status, 'ACTIVE');

  const reactivatedDisabled = await service.reactivate(adminPrincipal, 2n, 1, reqCtx);
  assert.equal(reactivatedDisabled.status, 'ACTIVE');
  assert.equal(users.get(2n).disabled_at, null);
  assert.equal(users.get(2n).locked_until, null);
  assert.equal(users.get(2n).failed_login_count, 0);
});

test('BUG-106: Department deactivate checks dependents & expirePreviousDepartmentRoles deletes future user_roles cleanly', async () => {
  let deletedWhere = null;
  let updatedWhere = null;
  const now = new Date('2026-06-01T00:00:00.000Z');

  await expirePreviousDepartmentRoles(
    {
      userRole: {
        deleteMany: async ({ where }) => {
          deletedWhere = where;
          return { count: 1 };
        },
        updateMany: async ({ where }) => {
          updatedWhere = where;
          return { count: 1 };
        },
      },
    },
    10n,
    50n,
    now,
  );
  assert.deepEqual(deletedWhere.valid_from, { gte: now });
  assert.deepEqual(updatedWhere.valid_from, { lt: now });

  // Blocks deactivate when active business_categories exist
  await assert.rejects(
    () =>
      assertDepartmentHasNoActiveDependents(
        {
          department: { count: async () => 0 },
          user: { count: async () => 0 },
          document: { count: async () => 0 },
          businessCategory: { count: async () => 2 },
          userRole: { count: async () => 0 },
        },
        50n,
      ),
    ConflictException,
  );

  // Blocks repeated deactivation on already inactive department
  const inactiveDeptDb = {
    department: {
      findUnique: async () => ({
        id: 50n,
        code: 'D50',
        name: 'Inactive Dept',
        parent_id: null,
        is_active: false,
        version: 1,
      }),
    },
    $transaction: async (fn) => fn(inactiveDeptDb),
  };
  const deptSvc = new DepartmentsService(
    {
      hasPermission: async () => true,
      assertPermission: async () => {},
      invalidateAll: async () => {},
    },
    { record: async () => {} },
    inactiveDeptDb,
  );
  await assert.rejects(() => deptSvc.deactivate(adminPrincipal, 50n, 1, reqCtx), ConflictException);
});

test('BUG-107: Separate rate-limit buckets for forgot/change-password and DENIED audit on wrong current password', async () => {
  const rateLimit = new LoginRateLimitService();

  await rateLimit.recordFailure('203.0.113.10', 'userA', 'forgot-password');
  await rateLimit.recordFailure('203.0.113.10', 'userB', 'forgot-password');
  await rateLimit.recordFailure('203.0.113.10', 'userC', 'forgot-password');
  // forgot-password bucket is now blocked, but login bucket for same NAT IP must remain open!
  await assert.rejects(() => rateLimit.assertAllowed('203.0.113.10', 'userD', 'forgot-password'));
  await assert.doesNotReject(() => rateLimit.assertAllowed('203.0.113.10', 'userD', 'login'));

  const passwordSvc = new PasswordService();
  const realHash = await passwordSvc.hash('CorrectHorseBattery!1');
  const audits = [];
  await assert.rejects(() =>
    executeChangePassword(
      {
        repository: {
          findUserById: async () => ({
            id: 7n,
            username: 'staff7',
            passwordHash: realHash,
            status: 'ACTIVE',
          }),
        },
        passwords: passwordSvc,
        rateLimit,
        audit: { record: async (ev) => audits.push(ev) },
      },
      { userId: 7n, sessionId: 's7', username: 'staff7', roles: ['DOCUMENT_READER'], mfa: false },
      'WrongPassword!123',
      'NewStrongPassword!456',
      { ip: '203.0.113.99', correlationId: 'corr-pw' },
    ),
  );
  assert.equal(audits.length, 1);
  assert.equal(audits[0].action, 'PASSWORD_CHANGE');
  assert.equal(audits[0].outcome, 'DENIED');
});

test('BUG-108 & BUG-109(7): HttpExceptionFilter maps UniqueConstraintError->409, preserves INVALID_POLICY issues, and redaction handles cycles/BigInt/depth', () => {
  const filter = new HttpExceptionFilter();
  const responses = [];
  const makeHost = () => ({
    switchToHttp: () => ({
      getRequest: () => ({ url: '/test', correlationId: 'c-108', headers: {} }),
      getResponse: () => ({
        status(code) {
          this._status = code;
          return this;
        },
        header() {
          return this;
        },
        send(body) {
          responses.push({ status: this._status, body });
        },
      }),
    }),
  });

  filter.catch(new UniqueConstraintError('Duplicate key', ['code']), makeHost());
  assert.equal(responses[0].status, 409);
  assert.equal(responses[0].body.errorCode, AppErrorCode.RESOURCE_CONFLICT);

  filter.catch(new DatabaseConstraintError('23514', 'Check failed'), makeHost());
  assert.equal(responses[1].status, 400);

  filter.catch(
    new BadRequestException({
      errorCode: 'INVALID_POLICY',
      message: 'Policy failed compilation',
      issues: [{ path: 'groups.0', message: 'Invalid CIDR' }],
    }),
    makeHost(),
  );
  assert.equal(responses[2].status, 400);
  assert.deepEqual(responses[2].body.details, {
    issues: [{ path: 'groups.0', message: 'Invalid CIDR' }],
  });

  // Redaction: shared DAG vs cycle vs BigInt vs depth > 10
  const sharedLeaf = { label: 'safe', password: 'fixture-secret' };
  const cyclic = { id: 99n, a: sharedLeaf, b: sharedLeaf };
  cyclic.self = cyclic;
  let deep = { secretToken: 'top-secret' };
  for (let i = 0; i < 12; i++) {
    deep = { child: deep };
  }
  cyclic.deep = deep;

  const redacted = redactSensitiveData(cyclic);
  assert.equal(redacted.id, '99');
  assert.equal(redacted.self, '[CIRCULAR]');
  assert.equal(redacted.a.label, 'safe');
  assert.equal(redacted.a.password, '[REDACTED]');
  assert.equal(redacted.b.label, 'safe');
  assert.equal(redacted.b.password, '[REDACTED]');
  assert.equal(JSON.stringify(redacted).includes('top-secret'), false);
  assert.equal(JSON.stringify(redacted).includes('[MAX_DEPTH_REDACTED]'), true);
});

test('BUG-109: Pre-MFA token TTL <= 300s, @AllowPreMfa only on logout, WebAuthn duplicate guard & ABAC group renumbering', async () => {
  const tokenSvc = new TokenService({
    get: (key) => {
      if (key === 'AUTH_ACTIVE_KID') return 'kid-1';
      if (key === 'AUTH_ACCESS_TTL_SECONDS') return 900;
      if (key === 'AUTH_ISSUER') return 'sda';
      if (key === 'AUTH_AUDIENCE') return 'sda-web';
      return undefined;
    },
  });
  const preMfaToken = await tokenSvc.issueAccessToken(1n, 's1', false);
  const verified = await tokenSvc.verifyAccessToken(preMfaToken);
  assert.ok(verified.exp - verified.iat <= 300, 'Pre-MFA JWT TTL must be clamped <= 300s');

  assert.equal(Reflect.getMetadata(ALLOW_PRE_MFA_METADATA, AuthController.prototype.logout), true);
  assert.equal(
    Reflect.getMetadata(ALLOW_PRE_MFA_METADATA, AuthController.prototype.logoutAll),
    undefined,
  );

  // Duplicate WebAuthn credential rejected with 409 ConflictException
  await assert.rejects(
    () =>
      executeVerifyWebAuthnEnrollment(
        {
          repository: {
            findUserById: async () => ({
              id: 1n,
              username: 'admin',
              status: 'ACTIVE',
              roles: ['SYSTEM_ADMIN'],
            }),
            getActiveMfaMethods: async () => [
              { id: 'm1', encryptedSecret: 'enc-1', recoveryCodeHashes: ['h1'] },
            ],
          },
          webauthn: {
            verifyRegistration: async () => ({
              encryptedSecret: 'enc-dup',
              credential: { credentialId: 'cred-dup-1' },
            }),
            parseStoredCredential: () => ({ credentialId: 'cred-dup-1' }),
          },
          mfa: { createRecoveryCodes: () => ({ plaintext: ['A'], hashes: ['H'] }) },
          audit: { record: async () => {} },
        },
        adminPrincipal,
        {},
        'challenge',
        'YubiKey',
        reqCtx,
      ),
    ConflictException,
  );

  // Renumbers sparse/duplicate condition groups sequentially
  const rows = await buildPolicyConditionRows(
    { attributeDefinition: { findMany: async () => [] } },
    [
      { id: 5, conditions: [] },
      {
        id: 9,
        conditions: [
          { attribute: 'environment.ip', operator: 'EQ', expected: '10.0.0.1' },
          { attribute: 'environment.mfa', operator: 'EQ', expected: true },
        ],
      },
      {
        id: 9,
        conditions: [{ attribute: 'environment.trustedNetwork', operator: 'EQ', expected: true }],
      },
    ],
  );
  assert.deepEqual(
    rows.map((r) => [r.condition_group, r.sequence_no]),
    [
      [1, 1],
      [1, 2],
      [2, 1],
    ],
  );
});

test('BUG-110 & BUG-123: AccessRequests scope=all, approval expiry/note, ROLE grant department scope, endOwnSession CAS, and active v2 upload status', async () => {
  // 1. AccessRequests scope === 'all' uses OR scoped to permissions
  let capturedReqWhere = null;
  const reqService = new AccessRequestsService(
    { record: async () => {} },
    { createGrant: async () => ({ id: randomUUID() }) },
    {
      accessRequest: {
        findMany: async ({ where }) => {
          capturedReqWhere = where;
          return [];
        },
        count: async () => 0,
      },
    },
    undefined,
    undefined,
    undefined,
    undefined,
    {
      hasPermission: async (_p, _res, action) => action === 'VIEW_OWN' || action === 'DECIDE',
    },
  );
  await reqService.listRequests(
    { userId: 15n, sessionId: 's', username: 'dual', roles: ['DOCUMENT_OWNER'], mfa: false },
    { scope: 'all', page: 1, pageSize: 20 },
  );
  assert.equal(capturedReqWhere.OR.length, 2);

  // 2. Blind approval rejected when requested_until <= now; explicit validDays succeeds and forwards decisionNote
  let capturedGrantOptions = null;
  const expiredReq = {
    id: randomUUID(),
    document_id: randomUUID(),
    requester_id: 20n,
    status: 'PENDING',
    requested_from: new Date(Date.now() - 10 * 86_400_000),
    requested_until: new Date(Date.now() - 86_400_000),
    documents: { owner_id: 15n, retention_until: null },
    access_request_permissions: [{ permission: 'VIEW' }],
  };
  await assert.rejects(
    () =>
      executeAccessRequestDecision({
        id: expiredReq.id,
        input: { decision: 'APPROVED', decisionNote: 'Duyệt muộn' },
        principal: {
          userId: 15n,
          sessionId: 's',
          username: 'owner',
          roles: ['DOCUMENT_OWNER'],
          mfa: false,
        },
        context: reqCtx,
        database: { accessRequest: { findUnique: async () => expiredReq } },
        audit: { record: async () => {} },
        grantsService: { createGrant: async () => ({ id: 'g1' }) },
      }),
    BadRequestException,
  );

  await executeAccessRequestDecision({
    id: expiredReq.id,
    input: { decision: 'APPROVED', validDays: 5, decisionNote: 'Gia hạn 5 ngày mới' },
    principal: {
      userId: 15n,
      sessionId: 's',
      username: 'owner',
      roles: ['DOCUMENT_OWNER'],
      mfa: false,
    },
    context: reqCtx,
    database: { accessRequest: { findUnique: async () => expiredReq } },
    audit: { record: async () => {} },
    grantsService: {
      createGrant: async (_in, _pr, _ctx, opts) => {
        capturedGrantOptions = opts;
        return { id: 'g-override' };
      },
    },
  });
  assert.equal(capturedGrantOptions?.decisionNote, 'Gia hạn 5 ngày mới');

  // 3. AccessGrantsService.getGrant enforces ROLE grant department scope matching
  const roleGrantId = randomUUID();
  const grantSvc = new AccessGrantsService(
    { record: async () => {} },
    {
      departmentWithinScope: async (docDeptId, scopeDeptId) =>
        scopeDeptId === 10n && (docDeptId === 10n || docDeptId === 11n),
    },
    {},
    {},
    { get: () => 30 },
    {
      accessGrant: {
        findUnique: async () => ({
          id: roleGrantId,
          document_id: randomUUID(),
          principal_type: 'ROLE',
          principal_user_id: null,
          principal_role_id: 7n,
          source: 'DIRECT',
          access_request_id: null,
          status: 'ACTIVE',
          valid_from: new Date(),
          valid_until: new Date(Date.now() + 86_400_000),
          granted_by: 99n,
          granted_at: new Date(),
          revoked_by: null,
          revoked_at: null,
          revoke_reason: null,
          version: 0,
          access_grant_permissions: [{ permission: 'VIEW' }],
          documents: { owner_id: 99n, department_id: 11n, status: 'ACTIVE' },
        }),
      },
      userRole: {
        findMany: async ({ where }) =>
          where.user_id === 30n
            ? [{ role_id: 7n, scope_department_id: 10n }]
            : [{ role_id: 7n, scope_department_id: 999n }],
      },
    },
  );

  const allowedRoleGrant = await grantSvc.getGrant(roleGrantId, {
    userId: 30n,
    sessionId: 's',
    username: 'inScopeReader',
    roles: ['DOCUMENT_READER'],
    mfa: false,
  });
  assert.equal(allowedRoleGrant.id, roleGrantId);

  await assert.rejects(
    () =>
      grantSvc.getGrant(roleGrantId, {
        userId: 31n,
        sessionId: 's',
        username: 'outOfScopeReader',
        roles: ['DOCUMENT_READER'],
        mfa: false,
      }),
    NotFoundException,
  );

  // 4. AccessSessionsService: listSessions limit 200 & endOwnSession CAS count === 0 preserves TERMINATED
  let endedAudits = 0;
  const sessionId = randomUUID();
  const sessSvc = new AccessSessionsService(
    {
      accessSession: {
        findMany: async () => [],
        count: async () => 0,
        findUnique: async ({ select }) =>
          select?.user_id
            ? {
                id: sessionId,
                user_id: 30n,
                status: 'ACTIVE',
                document_versions: { document_id: null },
              }
            : { status: 'TERMINATED' },
        updateMany: async () => ({ count: 0 }),
      },
    },
    {
      writeLog: async () => {
        endedAudits += 1;
      },
    },
  );
  const listRes = await sessSvc.listSessions({ limit: 200 });
  assert.equal(listRes.meta.pageSize, 200);

  const endRes = await sessSvc.endOwnSession(sessionId, {
    userId: 30n,
    sessionId: 's',
    username: 'reader',
    roles: ['DOCUMENT_READER'],
    mfa: false,
  });
  assert.equal(endRes.status, 'TERMINATED');
  assert.equal(endedAudits, 0);

  // 5. Unified maxDurationDays helper & v2 upload onto ACTIVE document preserves 'ACTIVE'
  const now = new Date();
  assert.doesNotThrow(() =>
    assertWithinMaxGrantDuration({
      validFrom: new Date(now.getTime() - 20 * 86_400_000),
      validUntil: new Date(now.getTime() + 14 * 86_400_000),
      now,
      maxDurationDays: 30,
      mode: 'EXTEND',
    }),
  );

  const v2DocId = randomUUID();
  const ingDb = {
    $executeRawUnsafe: async () => 1,
    document: {
      findUnique: async () => ({
        id: v2DocId,
        owner_id: 10n,
        status: 'ACTIVE',
        versions: [{ version_no: 1 }],
        classification_history: [{ classification_levels: { rank: 1 } }],
      }),
      update: async () => ({}),
    },
    documentVersion: {
      findFirst: async () => ({ version_no: 1 }),
      findMany: async () => [{ version_no: 1 }],
      create: async () => ({ id: 200n, version_no: 2 }),
    },
    documentVersionKey: { create: async () => ({}) },
    documentScanResult: { create: async () => ({}) },
  };
  ingDb.$transaction = async (fn) => fn(ingDb);

  const persisted = await persistCleanIngestedVersionWithStatus({
    database: ingDb,
    audit: { record: async () => {} },
    input: {
      documentId: v2DocId,
      principal: {
        userId: 10n,
        sessionId: 's',
        username: 'owner',
        roles: ['DOCUMENT_OWNER'],
        mfa: false,
      },
      context: reqCtx,
    },
    targetDocId: v2DocId,
    isNewDoc: false,
    validatedInfo: { sanitizedFilename: 'v2.pdf', mimeType: 'application/pdf', extension: '.pdf' },
    encryptedKey: 'enc',
    encryptedStorageKey: 'docs/v2.enc',
    totalBytes: 1024,
    sha256Hash: 'a'.repeat(64),
    scanResult: { engine: 'CLAMAV', status: 'CLEAN', durationMs: 12 },
  });
  assert.equal(persisted.versionNo, 2);
  assert.equal(persisted.documentStatus, 'ACTIVE');
});

test('BUG-111 (API), BUG-112, BUG-121 & BUG-122: Audit reason clamp, export live authz, verifyChain bounds, watermark scope-before-ambiguity & ILIKE escape', async () => {
  // BUG-111(1): Clamp sanitizeReason to <= 80 UTF-16 code units without splitting surrogate pairs
  const redactor = new AuditRedactionService();
  const emojiReason = `${'A'.repeat(79)}🔒EXTRA_PADDING_BEYOND_80`;
  const clamped = redactor.sanitizeReason(emojiReason);
  assert.ok(clamped.length <= 80);
  const lastCode = clamped.charCodeAt(clamped.length - 1);
  assert.equal(
    lastCode >= 0xd800 && lastCode <= 0xdbff,
    false,
    'Must not leave lone high surrogate',
  );

  // BUG-111(3): Live export download authorization supports Custom Roles and blocks disabled users / revoked permission
  const customActor = {
    userId: 88n,
    sessionId: 's88',
    username: 'custom_auditor',
    roles: ['CUSTOM_AUDIT_EXPORTER'],
    mfa: true,
  };
  await assert.doesNotReject(() =>
    assertLiveExportDownloadAuthorization(
      { user: { findUnique: async () => ({ status: 'ACTIVE' }) } },
      {
        hasPermission: async (_actor, res, act) => res === 'AUDIT_LOG' && act === 'EXPORT',
        visibleDepartmentIds: async () => null,
      },
      { requester_user_id: 88n, export_type: 'AUDIT_LOGS', filter_params: {} },
      customActor,
    ),
  );
  await assert.rejects(
    () =>
      assertLiveExportDownloadAuthorization(
        { user: { findUnique: async () => ({ status: 'DISABLED' }) } },
        {
          hasPermission: async () => true,
          visibleDepartmentIds: async () => null,
        },
        { requester_user_id: 88n, export_type: 'AUDIT_LOGS', filter_params: {} },
        customActor,
      ),
    ForbiddenException,
  );

  // BUG-112: AuditService.verifyChain defensive sequence/partition validation
  const auditorPrincipal = { ...adminPrincipal, roles: ['AUDITOR'] };
  const auditSvc = new AuditService({}, {}, {});
  await assert.rejects(
    () => auditSvc.verifyChain(auditorPrincipal, { fromSequence: 1n }),
    BadRequestException,
  );
  await assert.rejects(
    () =>
      auditSvc.verifyChain(auditorPrincipal, {
        chainPartition: 'AUTH',
        fromSequence: 10n,
        toSequence: 5n,
      }),
    BadRequestException,
  );

  // BUG-121: Scoped officer resolves unique in-scope watermark prefix even when an out-of-scope prefix collision exists
  const makeWmRow = (token, deptId, classCode = 'CONFIDENTIAL') => ({
    watermark_token: token,
    watermark_text_rendered: token,
    output_sha256_hash: 'b'.repeat(64),
    generated_at: new Date(),
    users: {
      id: 5n,
      username: 'reader5',
      full_name: 'Reader 5',
      employee_code: 'E5',
      email: 'r5@sda.local',
    },
    access_sessions: {
      id: randomUUID(),
      started_at: new Date(),
      ip_address: '10.0.0.5',
      user_agent: 'Mozilla',
    },
    document_versions: {
      version_no: 1,
      sha256_hash: 'c'.repeat(64),
      document: {
        id: randomUUID(),
        title: 'Scoped Doc',
        document_code: 'DOC-WM',
        department_id: deptId,
        classification_history: [
          { classification_levels: { code: classCode, name: classCode, rank: 2 } },
        ],
      },
    },
    watermark_configs: {
      name: 'Default',
      opacity_percent: 20,
      font_size: 14,
      include_qr_code: false,
    },
  });

  const wmRes = await traceWatermarkToken(
    {
      watermarkInstance: {
        findMany: async () => [
          makeWmRow('WM-abcdef012345aaaa', 10n),
          makeWmRow('WM-abcdef012345bbbb', 99n),
        ],
      },
    },
    { writeLog: async () => {} },
    new Logger('WmTest'),
    'WM-abcdef012345',
    { userId: 77n, sessionId: 's', username: 'scoped_soc', roles: ['SECURITY_OFFICER'], mfa: true },
    { visibleDepartmentIds: async () => [10n] },
    reqCtx,
  );
  assert.equal(wmRes.watermarkToken, 'WM-abcdef012345aaaa');

  // BUG-122: SQL LIKE wildcard escaping & d."status" = 'ACTIVE' on grant branches
  assert.equal(escapeSqlLikePattern('100%_test!'), '100!%!_test!!');
  const whereSql = buildSearchWhereClause({
    userId: 10n,
    hasGlobalDiscover: false,
    discoverableDeptIds: [],
    roleIds: [3n],
    userClearanceRank: 2,
    input: { page: 1, pageSize: 20 },
    sanitizedQuery: '100%_doc',
  });
  const sqlText = whereSql.strings.join('?');
  assert.match(sqlText, /ESCAPE '!'/);
  const activeGrantChecks = sqlText.match(/d\."status" = 'ACTIVE' AND EXISTS/g) ?? [];
  assert.equal(activeGrantChecks.length, 2);
});
