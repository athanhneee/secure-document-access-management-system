import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  computeUserFilterFacets,
  DEFAULT_USER_LIST_QUERY,
  filterAndSortUsers,
  formatUserSortOption,
  hasActiveUserFilters,
  isNonDefaultUserQuery,
  parseUserSortOption,
  toggleUserSort,
} from '../../apps/web/app/admin/users-query.ts';

const DEPARTMENTS = Object.freeze([
  Object.freeze({ id: '3', name: 'Phòng An toàn thông tin' }),
  Object.freeze({ id: '1', name: 'Khối văn phòng' }),
  Object.freeze({ id: '2', name: 'Khối Công nghệ & Kỹ thuật' }),
  Object.freeze({ id: '4', name: 'Ban Pháp chế & Tuân thủ' }),
  Object.freeze({ id: '5', name: 'Phòng Tài chính' }),
]);

const USERS = Object.freeze([
  Object.freeze({
    id: '10',
    username: 'security.demo',
    fullName: 'Bảo mật demo',
    email: 'security.demo@local.invalid',
    employeeCode: null,
    status: 'DISABLED',
    departmentId: '3',
  }),
  Object.freeze({
    id: '11',
    username: 'qa.auditor',
    fullName: 'Hoàng Kiểm Toán Độc Lập',
    email: 'qa.auditor@corp.internal',
    employeeCode: 'QA-AUD-001',
    status: 'ACTIVE',
    departmentId: '4',
  }),
  Object.freeze({
    id: '12',
    username: 'qa.locked',
    fullName: 'Đỗ Tài Khoản Khóa',
    email: 'qa.locked@corp.internal',
    employeeCode: 'QA-LCK-002',
    status: 'LOCKED',
    departmentId: '1',
  }),
  Object.freeze({
    id: '13',
    username: 'qa.reader',
    fullName: 'Lê Chuyên Viên Nghiên Cứu',
    email: 'qa.reader@corp.internal',
    employeeCode: 'QA-RDR-001',
    status: 'ACTIVE',
    departmentId: '2',
  }),
  Object.freeze({
    id: '14',
    username: 'system.seed',
    fullName: 'System Seed Actor',
    email: 'system.seed@local.invalid',
    employeeCode: null,
    status: 'DISABLED',
    departmentId: null,
  }),
  Object.freeze({
    id: '15',
    username: 'qa.security',
    fullName: 'Phạm Chuyên Gia An Ninh SOC',
    email: 'qa.security@corp.internal',
    employeeCode: 'QA-SOC-001',
    status: 'ACTIVE',
    departmentId: '3',
  }),
]);

describe('Admin Users Filtering & Deterministic Sorting (users-query)', () => {
  it('sorts by status ascending (ACTIVE -> LOCKED -> DISABLED) by default without mutating input', () => {
    const result = filterAndSortUsers(USERS, DEPARTMENTS, DEFAULT_USER_LIST_QUERY);

    assert.deepEqual(
      result.map((u) => [u.username, u.status]),
      [
        ['qa.auditor', 'ACTIVE'],
        ['qa.reader', 'ACTIVE'],
        ['qa.security', 'ACTIVE'],
        ['qa.locked', 'LOCKED'],
        ['security.demo', 'DISABLED'],
        ['system.seed', 'DISABLED'],
      ],
    );
    assert.equal(USERS[0].username, 'security.demo');
  });

  it('sorts by status descending (DISABLED first) and by action (Vô hiệu vs Kích hoạt)', () => {
    const disabledFirst = filterAndSortUsers(USERS, DEPARTMENTS, {
      ...DEFAULT_USER_LIST_QUERY,
      sortField: 'status',
      sortDirection: 'desc',
    });
    assert.deepEqual(
      disabledFirst.map((u) => u.status),
      ['DISABLED', 'DISABLED', 'LOCKED', 'ACTIVE', 'ACTIVE', 'ACTIVE'],
    );

    const disableActionFirst = filterAndSortUsers(USERS, DEPARTMENTS, {
      ...DEFAULT_USER_LIST_QUERY,
      sortField: 'action',
      sortDirection: 'asc',
    });
    assert.deepEqual(
      disableActionFirst.map((u) => u.username),
      ['qa.auditor', 'qa.reader', 'qa.security', 'qa.locked', 'security.demo', 'system.seed'],
    );

    const reactivateActionFirst = filterAndSortUsers(USERS, DEPARTMENTS, {
      ...DEFAULT_USER_LIST_QUERY,
      sortField: 'action',
      sortDirection: 'desc',
    });
    assert.deepEqual(
      reactivateActionFirst.slice(0, 2).map((u) => u.username),
      ['security.demo', 'system.seed'],
    );
  });

  it('sorts by department using Vietnamese collation with unassigned placed last on asc and first on desc', () => {
    const deptAsc = filterAndSortUsers(USERS, DEPARTMENTS, {
      ...DEFAULT_USER_LIST_QUERY,
      sortField: 'department',
      sortDirection: 'asc',
    });
    assert.deepEqual(
      deptAsc.map((u) => u.username),
      ['qa.auditor', 'qa.reader', 'qa.locked', 'qa.security', 'security.demo', 'system.seed'],
    );

    const deptDesc = filterAndSortUsers(USERS, DEPARTMENTS, {
      ...DEFAULT_USER_LIST_QUERY,
      sortField: 'department',
      sortDirection: 'desc',
    });
    assert.equal(deptDesc[0].username, 'system.seed');
    assert.deepEqual(
      deptDesc.slice(1, 3).map((u) => u.username),
      ['qa.security', 'security.demo'],
    );
  });

  it('filters by status, department (including UNASSIGNED), available action, and search text', () => {
    const onlyDisabled = filterAndSortUsers(USERS, DEPARTMENTS, {
      ...DEFAULT_USER_LIST_QUERY,
      statusFilter: 'DISABLED',
    });
    assert.deepEqual(
      onlyDisabled.map((u) => u.username),
      ['security.demo', 'system.seed'],
    );

    const onlySecDept = filterAndSortUsers(USERS, DEPARTMENTS, {
      ...DEFAULT_USER_LIST_QUERY,
      departmentFilter: '3',
    });
    assert.deepEqual(
      onlySecDept.map((u) => u.username),
      ['qa.security', 'security.demo'],
    );

    const onlyUnassigned = filterAndSortUsers(USERS, DEPARTMENTS, {
      ...DEFAULT_USER_LIST_QUERY,
      departmentFilter: 'UNASSIGNED',
    });
    assert.deepEqual(
      onlyUnassigned.map((u) => u.username),
      ['system.seed'],
    );

    const canDisable = filterAndSortUsers(USERS, DEPARTMENTS, {
      ...DEFAULT_USER_LIST_QUERY,
      actionFilter: 'DISABLE',
    });
    assert.deepEqual(
      canDisable.map((u) => u.username),
      ['qa.auditor', 'qa.reader', 'qa.security', 'qa.locked'],
    );

    const canUnlock = filterAndSortUsers(USERS, DEPARTMENTS, {
      ...DEFAULT_USER_LIST_QUERY,
      actionFilter: 'UNLOCK',
    });
    assert.deepEqual(
      canUnlock.map((u) => u.username),
      ['qa.locked'],
    );

    const canReactivate = filterAndSortUsers(USERS, DEPARTMENTS, {
      ...DEFAULT_USER_LIST_QUERY,
      actionFilter: 'REACTIVATE',
    });
    assert.deepEqual(
      canReactivate.map((u) => u.username),
      ['security.demo', 'system.seed'],
    );

    const byEmployeeCode = filterAndSortUsers(USERS, DEPARTMENTS, {
      ...DEFAULT_USER_LIST_QUERY,
      searchQuery: 'qa-soc-001',
    });
    assert.deepEqual(
      byEmployeeCode.map((u) => u.username),
      ['qa.security'],
    );
  });

  it('computes accurate facet counts and sort state transitions', () => {
    const facets = computeUserFilterFacets(USERS, DEPARTMENTS);
    assert.deepEqual(facets.statusCounts, {
      ACTIVE: 3,
      LOCKED: 1,
      DISABLED: 2,
      PENDING: 0,
    });
    assert.deepEqual(facets.actionCounts, {
      DISABLE: 4,
      LOCK: 3,
      UNLOCK: 1,
      REACTIVATE: 2,
    });
    assert.equal(facets.unassignedDepartmentCount, 1);
    assert.deepEqual(
      facets.departmentOptions.map((d) => [d.name, d.count]),
      [
        ['Ban Pháp chế & Tuân thủ', 1],
        ['Khối Công nghệ & Kỹ thuật', 1],
        ['Khối văn phòng', 1],
        ['Phòng An toàn thông tin', 2],
        ['Phòng Tài chính', 0],
      ],
    );

    assert.equal(hasActiveUserFilters(DEFAULT_USER_LIST_QUERY), false);
    assert.equal(isNonDefaultUserQuery(DEFAULT_USER_LIST_QUERY), false);
    assert.equal(
      isNonDefaultUserQuery({ ...DEFAULT_USER_LIST_QUERY, sortField: 'department' }),
      true,
    );

    assert.deepEqual(toggleUserSort('status', 'asc', 'status'), {
      sortField: 'status',
      sortDirection: 'desc',
    });
    assert.deepEqual(toggleUserSort('status', 'desc', 'department'), {
      sortField: 'department',
      sortDirection: 'asc',
    });
    assert.equal(formatUserSortOption('action', 'desc'), 'action:desc');
    assert.deepEqual(parseUserSortOption('department:desc'), {
      sortField: 'department',
      sortDirection: 'desc',
    });
    assert.deepEqual(parseUserSortOption('invalid:value'), {
      sortField: 'status',
      sortDirection: 'asc',
    });
  });

  it('sorts and searches users by Bell-LaPadula clearance rank and label', () => {
    const withClearance = [
      { ...USERS[1], clearanceCode: 'SECRET', clearanceName: 'Tối mật', clearanceRank: 3 },
      { ...USERS[3], clearanceCode: 'INTERNAL', clearanceName: 'Nội bộ', clearanceRank: 1 },
      { ...USERS[5], clearanceCode: 'TOP_SECRET', clearanceName: 'Tuyệt mật', clearanceRank: 4 },
      { ...USERS[4], clearanceCode: null, clearanceName: null, clearanceRank: 0 },
    ];

    const byClearanceDesc = filterAndSortUsers(withClearance, DEPARTMENTS, {
      ...DEFAULT_USER_LIST_QUERY,
      sortField: 'clearance',
      sortDirection: 'desc',
    });
    assert.deepEqual(
      byClearanceDesc.map((u) => [u.username, u.clearanceRank]),
      [
        ['qa.security', 4],
        ['qa.auditor', 3],
        ['qa.reader', 1],
        ['system.seed', 0],
      ],
    );

    const searchSecret = filterAndSortUsers(withClearance, DEPARTMENTS, {
      ...DEFAULT_USER_LIST_QUERY,
      searchQuery: 'tối mật',
    });
    assert.deepEqual(
      searchSecret.map((u) => u.username),
      ['qa.auditor'],
    );
  });
});
