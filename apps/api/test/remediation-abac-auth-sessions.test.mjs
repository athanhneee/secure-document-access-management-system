import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { ConflictException } from '@nestjs/common';
import { AbacRepository } from '../dist/modules/abac/abac.repository.js';
import {
  executeUpsertAbacPolicy,
  UpsertAbacPolicySchema,
} from '../dist/modules/abac/abac-policy-mutation.helper.js';
import { executeBeginMfaEnrollment } from '../dist/modules/auth/auth-mfa.helper.js';
import { createUserMfaEnrollment } from '../dist/modules/auth/auth-mfa.repository.js';
import {
  queryActiveUserSessions,
  revokeOtherActiveUserSessions,
} from '../dist/modules/auth/auth-sessions-management.helper.js';
import { executeRevokeUserRole } from '../dist/modules/rbac/rbac-assignments.helper.js';
import { executeReplaceRolePermissions } from '../dist/modules/rbac/rbac-roles.helper.js';

/**
 * Thuật toán: Tạo mock CSDL giao dịch `SERIALIZABLE` cho quy tắc chính sách ABAC để kiểm chứng tạo mới, cập nhật và làm mới epoch bộ nhớ đệm (HIGH-04).
 */
function createAbacMutationMockDb() {
  const storedRule = {
    id: 15n,
    code: 'POL_OFFICE',
    name: 'Office Policy',
    description: null,
    effect: 'PERMIT',
    priority: 10,
    target_resource: 'DOCUMENT',
    target_action: 'VIEW',
    combining_algorithm: 'DENY_OVERRIDES',
    obligations: [],
    is_active: true,
    version: 1n,
    valid_from: new Date('2026-01-01T00:00:00Z'),
    valid_to: null,
    policy_rule_conditions: [],
  };
  const tx = {
    policyRule: {
      findFirst: async () => null,
      create: async () => ({ id: 15n }),
      findUnique: async () => storedRule,
    },
    policyRuleCondition: { deleteMany: async () => ({ count: 0 }) },
  };
  return {
    $transaction: async (fn) => fn(tx),
  };
}

test('[HIGH-04, MED-04] AbacRepository.simulationInput selects highest active CLEARANCE_LEVEL rank & executeUpsertAbacPolicy bumps PolicyCache epoch', async () => {
  const repo = Object.create(AbacRepository.prototype);
  repo.trustedCidrs = [];
  repo.database = {
    user: {
      findUnique: async () => ({ id: 9n, department_id: 2n, status: 'ACTIVE' }),
    },
    document: {
      findUnique: async () => ({ id: 'd1', owner_id: 1n, department_id: 2n, status: 'ACTIVE' }),
    },
    userAttributeAssignment: {
      findMany: async () => [
        {
          valid_from: new Date('2025-01-01T00:00:00Z'),
          valid_to: null,
          value_text: null,
          attribute_definitions: { code: 'CLEARANCE_LEVEL' },
          attribute_options: { value_code: 'PUBLIC', numeric_rank: 1, is_active: true },
        },
        {
          valid_from: new Date('2026-01-01T00:00:00Z'),
          valid_to: null,
          value_text: null,
          attribute_definitions: { code: 'CLEARANCE_LEVEL' },
          attribute_options: { value_code: 'TOP_SECRET', numeric_rank: 4, is_active: true },
        },
      ],
    },
    documentClassificationHistory: {
      findFirst: async () => ({
        classification_levels: { rank: 3 },
        business_categories: { code: 'FIN' },
      }),
    },
  };
  const sim = await repo.simulationInput({
    subjectUserId: 9n,
    resourceDocumentId: randomUUID(),
    action: 'VIEW',
    time: new Date('2026-06-01T00:00:00Z'),
    ip: '10.0.0.1',
    deviceTrust: true,
    mfa: true,
    riskScore: 0,
  });
  assert.equal(sim.subject.clearanceRank, 4);

  let bumpedVersion = null;
  const parsedInput = UpsertAbacPolicySchema.parse({
    code: 'POL_OFFICE',
    name: 'Office Policy',
    effect: 'PERMIT',
    targetAction: 'VIEW',
  });
  const savedPolicy = await executeUpsertAbacPolicy({
    input: parsedInput,
    principal: {
      userId: 1n,
      sessionId: 's',
      username: 'admin',
      roles: ['SYSTEM_ADMIN'],
      mfa: true,
    },
    context: { ip: '127.0.0.1', correlationId: 'c-abac' },
    database: createAbacMutationMockDb(),
    repository: { currentPolicyVersion: async () => 7n },
    cache: {
      bumpPolicyEpoch: async (prev) => {
        bumpedVersion = prev;
      },
    },
    audit: { record: async () => {} },
  });
  assert.equal(savedPolicy.id, '15');
  assert.equal(savedPolicy.isActive, true);
  assert.equal(bumpedVersion, '7');
});

test('[HIGH-09, HIGH-10, HIGH-12] MFA enroll returns qrCodeDataUrl, duplicate active TOTP throws 409 & logout-others preserves current session', async () => {
  const enrolled = await executeBeginMfaEnrollment(
    {
      repository: {
        countEnabledMfaFactors: async () => 0,
        createMfaEnrollment: async () => {},
      },
      mfa: {
        createEnrollment: () => ({
          secret: 'JBSWY3DPEHPK3PXP',
          uri: 'otpauth://totp/SDA:admin.qr?secret=JBSWY3DPEHPK3PXP&issuer=SDA',
          encryptedSecret: 'enc-secret',
        }),
      },
      audit: { record: async () => {} },
    },
    { userId: 1n, sessionId: 's-cur', username: 'admin.qr', roles: [], mfa: true },
    'Authenticator',
    { ip: '127.0.0.1', correlationId: 'c-mfa' },
  );
  assert.ok(enrolled.qrCodeDataUrl.startsWith('data:image/png;base64,'));

  await assert.rejects(
    () =>
      createUserMfaEnrollment(
        {
          mfaMethod: {
            findFirst: async () => ({ id: 'mfa-1', enabled_at: new Date() }),
          },
        },
        1n,
        'enc',
      ),
    ConflictException,
  );

  const currentSessId = randomUUID();
  const otherSessId = randomUUID();
  let findWhere = null;
  const mockSessionDb = {
    authSession: {
      findMany: async ({ where }) => {
        findWhere = where;
        if (where?.id?.not) {
          return [{ id: otherSessId, token_family_id: 'fam-2' }];
        }
        return [
          {
            id: currentSessId,
            ip_address: '10.0.0.1',
            user_agent: 'Browser A',
            created_at: new Date('2026-11-05T08:00:00Z'),
            last_seen_at: new Date('2026-11-05T09:00:00Z'),
            expires_at: new Date('2026-11-06T08:00:00Z'),
          },
          {
            id: otherSessId,
            ip_address: '10.0.0.2',
            user_agent: 'Browser B',
            created_at: new Date('2026-11-05T07:00:00Z'),
            last_seen_at: new Date('2026-11-05T08:30:00Z'),
            expires_at: new Date('2026-11-06T07:00:00Z'),
          },
        ];
      },
      updateMany: async () => ({ count: 1 }),
    },
    refreshToken: { updateMany: async () => ({ count: 1 }) },
    $transaction: async (fn) => fn(mockSessionDb),
  };

  const listedSessions = await queryActiveUserSessions(mockSessionDb, 5n, currentSessId);
  assert.equal(listedSessions[0].isCurrent, true);
  assert.equal(listedSessions[1].isCurrent, false);

  const revokedCount = await revokeOtherActiveUserSessions(
    mockSessionDb,
    5n,
    currentSessId,
    'USER_LOGOUT_OTHERS',
  );
  assert.equal(revokedCount, 1);
  assert.deepEqual(findWhere.id, { not: currentSessId });
});

test('[HIGH-12] RBAC revokeUserRole deletes unstarted role assignment & replaceRolePermissions deduplicates permissionIds', async () => {
  let deletedAssignmentId = null;
  let createdRows = [];
  const tx = {
    userRole: {
      findFirst: async () => ({
        id: 77n,
        user_id: 9n,
        role_id: 3n,
        scope_department_id: null,
        valid_from: new Date(Date.now() + 86_400_000),
        valid_to: null,
        roles: { role_permissions: [] },
      }),
      delete: async ({ where }) => {
        deletedAssignmentId = where.id;
      },
      count: async () => 0,
    },
    user: { findUniqueOrThrow: async () => ({ id: 9n, department_id: 1n }) },
    role: {
      findUnique: async () => ({
        id: 3n,
        code: 'CUSTOM_ROLE',
        is_system_role: false,
        role_permissions: [],
      }),
    },
    permission: {
      findMany: async ({ where }) => where.id.in.map((id) => ({ id, code: `PERM_${id}` })),
    },
    rolePermission: {
      deleteMany: async () => ({ count: 0 }),
      createMany: async ({ data }) => {
        createdRows = data;
      },
    },
  };
  const mockDb = { $transaction: async (fn) => fn(tx), userRole: tx.userRole };
  const authz = {
    assertPermission: async () => {},
    assertCanDelegate: async () => {},
    invalidateUser: () => {},
    invalidateAll: () => {},
  };
  const principal = { userId: 1n, sessionId: 's', username: 'admin', roles: [], mfa: true };
  const context = { ip: '127.0.0.1', correlationId: 'c-rbac' };

  await executeRevokeUserRole(
    authz,
    { record: async () => {} },
    principal,
    9n,
    77n,
    context,
    mockDb,
  );
  assert.equal(deletedAssignmentId, 77n);

  const replaced = await executeReplaceRolePermissions({
    database: mockDb,
    authorization: authz,
    audit: { record: async () => {} },
    principal,
    roleId: 3n,
    permissionIds: [10n, 11n, 10n],
    context,
  });
  assert.equal(createdRows.length, 2);
  assert.deepEqual(replaced.permissionCodes, ['PERM_10', 'PERM_11']);
});
