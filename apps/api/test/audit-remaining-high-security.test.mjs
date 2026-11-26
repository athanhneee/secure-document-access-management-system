/**
 * Suite Kiểm Thử Hồi Quy Bảo Mật Backend Cho Báo Cáo Kiểm Toán Còn Lại (`HIGH-01`, `HIGH-02`, `HIGH-03`, `HIGH-07`, `HIGH-08`, `HIGH-10`, `MED-02`).
 */
import assert from 'node:assert/strict';
import test from 'node:test';
import { AuthGuard } from '../dist/modules/auth/auth.guard.js';
import { DistributedStateService } from '../dist/modules/concurrency/distributed-state.service.js';
import {
  canUserReadRoleGrant,
  resolveScopedRoleAccessForSql,
} from '../dist/modules/access-grants/grant-role-visibility.helper.js';
import { resolveAndEnforceSessionPolicy } from '../dist/modules/documents/session-policy-resolver.helper.js';
import { SESSION_POLICY_NAMESPACE } from '../dist/modules/documents/pep-obligations.helper.js';
import { RealtimeEventsService } from '../dist/modules/realtime/realtime-events.service.js';
import { validatePolicy } from '../dist/modules/abac/policy-validator.js';
import { AuditRedactionService } from '../dist/modules/audit/audit-redaction.service.js';

test('HIGH-01 — AuthGuard rejects stale L1/L2 cache write when auth-user epoch invalidates mid-flight', async () => {
  const stateStore = new DistributedStateService();
  let dbCalls = 0;
  let triggerInvalidationMidFlight = true;

  const mockRepository = {
    async principalForSession(userId, sessionId) {
      dbCalls += 1;
      if (triggerInvalidationMidFlight) {
        triggerInvalidationMidFlight = false;
        // Giả lập sự kiện logout/khóa tài khoản bắn ra ngay trong lúc truy vấn CSDL đang chạy
        await stateStore.bumpNamespaceEpoch('auth-user:42');
      }
      if (dbCalls === 1) {
        return {
          userId,
          sessionId,
          username: 'alice',
          roles: ['DOCUMENT_READER'],
          mfa: true,
        };
      }
      // Lần kiểm tra thứ 2 sau khi phiên đã bị thu hồi trong CSDL
      return null;
    },
    async touchSessionActivity() {},
  };

  const mockTokens = {
    async verifyAccessToken() {
      return { sub: '42', sid: 'sess-high-01', usr: 'alice', mfa: true };
    },
  };
  const mockReflector = { getAllAndOverride: () => false, get: () => false };
  const mockDefaultDeny = { canActivate: () => false };

  const guard = new AuthGuard(
    mockReflector,
    mockTokens,
    mockRepository,
    mockDefaultDeny,
    undefined,
    stateStore,
  );

  const makeCtx = () => {
    const req = {
      cookies: { sda_access: 'valid-jwt' },
      ip: '10.0.0.10',
      headers: { 'user-agent': 'test-agent' },
    };
    return {
      getHandler: () => ({}),
      getClass: () => ({}),
      switchToHttp: () => ({ getRequest: () => req }),
    };
  };

  // Lượt 1 hoàn tất với bản ghi DB đọc trước thu hồi, nhưng KHÔNG được phép nhiễm độc L1/L2 vì epoch đã nhảy
  const ok1 = await guard.canActivate(makeCtx());
  assert.equal(ok1, true);

  // Lượt 2 BẮT BUỘC phải gọi lại CSDL (không được trúng L1/L2 nhiễm độc) và từ chối 401
  await assert.rejects(() => guard.canActivate(makeCtx()), {
    status: 401,
  });
  assert.equal(dbCalls, 2);

  guard.onModuleDestroy();
  await stateStore.onModuleDestroy();
});

test('HIGH-02 — ROLE grant visibility enforces user_roles.scope_department_id and active department subtree', async () => {
  const departmentsById = new Map([
    [10n, { id: 10n, parent_id: null, is_active: true }],
    [11n, { id: 11n, parent_id: 10n, is_active: true }],
    [20n, { id: 20n, parent_id: null, is_active: true }],
  ]);

  const database = {
    userRole: {
      async findMany() {
        return [{ role_id: 5n, scope_department_id: 10n }];
      },
    },
    department: {
      async findUnique({ where }) {
        return departmentsById.get(where.id) ?? null;
      },
      async findMany() {
        return [...departmentsById.values()];
      },
    },
  };

  // Tài liệu thuộc Phòng 10 và Phòng con 11 -> ĐƯỢC phép
  assert.equal(
    await canUserReadRoleGrant({
      database,
      userId: 7n,
      roleId: 5n,
      docDepartmentId: 10n,
    }),
    true,
  );
  assert.equal(
    await canUserReadRoleGrant({
      database,
      userId: 7n,
      roleId: 5n,
      docDepartmentId: 11n,
    }),
    true,
  );

  // Tài liệu thuộc Phòng 20 ngoài phạm vi -> CHẶN BOLA xuyên phòng ban
  assert.equal(
    await canUserReadRoleGrant({
      database,
      userId: 7n,
      roleId: 5n,
      docDepartmentId: 20n,
    }),
    false,
  );

  const sqlAccess = await resolveScopedRoleAccessForSql({ database, userId: 7n });
  assert.deepEqual(sqlAccess.globalRoleIds, []);
  assert.equal(sqlAccess.scopedRoleDepts.length, 1);
  assert.equal(sqlAccess.scopedRoleDepts[0].roleId, 5n);
  assert.deepEqual(
    sqlAccess.scopedRoleDepts[0].departmentIds.sort((a, b) => Number(a - b)),
    [10n, 11n],
  );
});

test('HIGH-03 — ActiveSessionPolicy invalidates on resourceSnapshot drift and fails closed 403 when livePolicy cannot be evaluated', async () => {
  const stateStore = new DistributedStateService();
  const sessionId = 'sess-high-03';
  const now = new Date();

  await stateStore.putEphemeral(
    SESSION_POLICY_NAMESPACE,
    sessionId,
    {
      grantedAction: 'DOWNLOAD',
      forbidDownload: false,
      watermarkRequired: false,
      expiresAtMs: now.getTime() + 600_000,
      maxSessionMinutes: 30,
      abacEpoch: 0,
      userEpoch: 0,
      policyVersion: 1,
      resourceSnapshot: {
        classificationRank: 1, // INTERNAL cũ
        category: 'FINANCE',
        departmentId: '10',
        status: 'ACTIVE',
      },
    },
    600_000,
  );

  const database = {
    accessSession: {
      async findUnique() {
        return {
          id: sessionId,
          status: 'ACTIVE',
          user_id: 7n,
          ip_address: '10.0.0.10',
          user_agent: 'browser-v1',
        };
      },
    },
    userRole: {
      async findFirst() {
        return null;
      },
    },
    user: {
      async findUnique() {
        return { status: 'ACTIVE' };
      },
    },
  };

  // Tài liệu vừa bị nâng độ mật từ INTERNAL (1) lên SECRET (3), nhưng thiếu abac engine để tính livePolicy -> phải Fail-Closed 403 thay vì ăn lại cache cũ!
  await assert.rejects(
    () =>
      resolveAndEnforceSessionPolicy({
        session: {
          id: sessionId,
          status: 'ACTIVE',
          user_id: 7n,
          ip_address: '10.0.0.10',
          user_agent: 'browser-v1',
          started_at: now,
          document_versions: {
            document_id: 'doc-high-03',
            document: {
              id: 'doc-high-03',
              department_id: 10n,
              status: 'ACTIVE',
              owner_id: 99n,
              classification_history: [
                {
                  classification_levels: { rank: 3, require_watermark: true },
                  business_categories: { code: 'FINANCE' },
                },
              ],
            },
          },
        },
        requiredAction: 'DOWNLOAD',
        principal: {
          userId: 7n,
          sessionId: 'auth-sess-1',
          username: 'reader1',
          roles: ['DOCUMENT_READER'],
          mfa: false,
        },
        context: { ipAddress: '10.0.0.10', userAgent: 'browser-v1' },
        now,
        stateStore,
        database,
        abac: undefined,
      }),
    { status: 403 },
  );

  await stateStore.onModuleDestroy();
});

test('HIGH-10 — RealtimeEventsService isolates SOC events by per-event capabilities and allowedDeptIdsByEvent', async () => {
  const service = new RealtimeEventsService();
  const receivedFrames = [];

  service.registerClient({
    userId: '100',
    roles: ['CUSTOM_SOC_VIEWER'],
    allowedSocEvents: new Set(['SECURITY_ALERT_UPDATED']),
    allowedDeptIdsByEvent: new Map([['SECURITY_ALERT_UPDATED', new Set(['10'])]]),
    writeFrame(frame) {
      receivedFrames.push(frame);
      return true;
    },
    close() {},
  });

  // 1. Đúng loại sự kiện + đúng phòng ban 10 -> NHẬN
  await service.publish({
    type: 'SECURITY_ALERT_UPDATED',
    targetRoles: ['SECURITY_OFFICER'],
    targetDepartmentId: '10',
    payload: { id: 'alert-dept-10' },
  });

  // 2. Đúng loại sự kiện nhưng KHÁC phòng ban (20) -> CHẶN
  await service.publish({
    type: 'SECURITY_ALERT_UPDATED',
    targetRoles: ['SECURITY_OFFICER'],
    targetDepartmentId: '20',
    payload: { id: 'alert-dept-20' },
  });

  // 3. Sai loại sự kiện (ACCESS_SESSION_UPDATED không nằm trong allowedSocEvents) -> CHẶN
  await service.publish({
    type: 'ACCESS_SESSION_UPDATED',
    targetRoles: ['SECURITY_OFFICER'],
    targetDepartmentId: '10',
    payload: { id: 'session-dept-10' },
  });

  assert.equal(receivedFrames.length, 1);
  assert.match(receivedFrames[0], /alert-dept-10/);
  assert.doesNotMatch(receivedFrames[0], /alert-dept-20/);
  service.onModuleDestroy();
});

test('HIGH-07 & HIGH-08 — PolicyValidator rejects prototype keys and invalid IP/CIDR values', () => {
  const attributes = {
    'environment.ip': { key: 'environment.ip', scope: 'ENVIRONMENT', type: 'IP' },
  };
  const issues = validatePolicy(
    {
      version: 1,
      compiledAt: new Date().toISOString(),
      rules: [
        {
          id: '1',
          code: 'POL-PROTO-AND-IP',
          name: 'Prototype and invalid IP test',
          effect: 'DENY',
          combiningAlgorithm: 'DENY_OVERRIDES',
          priority: 10,
          targetAction: 'VIEW',
          obligations: [],
          groups: [
            {
              id: 'g1',
              conditions: [
                { attribute: 'constructor', operator: 'EQ', expected: 'x' },
                { attribute: 'environment.ip', operator: 'EQ', expected: 'not-an-ip' },
              ],
            },
          ],
        },
      ],
    },
    attributes,
  );

  assert.ok(issues.some((i) => i.code === 'UNKNOWN_ATTRIBUTE'));
  assert.ok(issues.some((i) => i.code === 'INVALID_EXPECTED_VALUE'));
});

test('MED-02 — AuditRedactionService truncates 4090+ strings safely without producing lone UTF-16 surrogates', () => {
  const redaction = new AuditRedactionService();
  // Tạo chuỗi 4089 chữ 'a' + 2 emoji (mỗi emoji là cặp surrogate 2 code units -> vị trí cắt 4090 rơi đúng giữa cặp surrogate!)
  const input = 'a'.repeat(4089) + '🔐🛡️';
  const result = redaction.sanitizeDetails({ note: input });
  const scrubbed = result.note;
  assert.equal(typeof scrubbed, 'string');
  assert.equal(scrubbed.isWellFormed(), true);
});
