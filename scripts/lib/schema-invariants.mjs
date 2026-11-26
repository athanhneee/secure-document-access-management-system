/**
 * Module: Kiểm Định Chủ Động Các Bất Biến Phòng Thủ Theo Chiều Sâu Tầng Cơ Sở Dữ Liệu (`DatabaseInvariants`)
 * Thuật toán: Thăm Dò Phản Chứng Trigger, Ràng Buộc & Cấp Độ Mật Bell-LaPadula Trên Dữ Liệu Giả Lập Cô Lập (`Defense-in-Depth Invariant Probing`).
 *   1. Kiểm chứng tính bất biến chỉ ghi nối thêm (`Append-Only`) chống `UPDATE`/`DELETE`/`TRUNCATE` và tính liên tục `previous_hash` trên `audit_logs` & `audit_anchors`.
 *   2. Kiểm chứng hoàn tác giao dịch nguyên tử khi vi phạm `CHECK constraint` (`SQLSTATE 23514`).
 *   3. Kiểm chứng trigger đệ quy CTE chặn chu trình cây phòng ban và tự động làm mới `updated_at`.
 *   4. Kiểm chứng ràng buộc họ khóa `refresh_tokens` khớp `auth_sessions` và hỗ trợ `WEBAUTHN`.
 *   5. Kiểm chứng quyền sở hữu `current_version_id` và chỉ mục duy nhất bán phần SCD Type 2 của phân loại mật hiện hành.
 *   6. Kiểm chứng bất biến Bell-LaPadula (`clearance >= classification`), Phân Tách Trách Nhiệm (`SYSTEM_ADMIN` bị chặn nhận grant) và tự động tăng đơn điệu `version` ABAC.
 */
import assert from 'node:assert/strict';

/**
 * Thuật toán: Thực thi tuần tự 6 nhóm ca kiểm thử phản chứng trực tiếp trên engine PostgreSQL/PGlite để xác nhận toàn bộ trigger và ràng buộc CSDL hoạt động đúng.
 */
export async function verifyDatabaseInvariants(database) {
  const checks = [];

  // 1. Append-only audit logs, HMAC chain continuity, and immutable audit anchors
  const firstHash = 'a'.repeat(64);
  const audit = await database.query(
    `INSERT INTO audit_logs (actor_username, action, object_type, outcome, correlation_id, entry_hash, chain_sequence)
     VALUES ($1, 'BASELINE_VALIDATION', 'TEST', 'SUCCESS', $2, $3, 1) RETURNING id`,
    ['schema-validation-fixture', '10000000-0000-4000-8000-000000000001', firstHash],
  );
  const auditId = audit.rows[0].id;
  await assert.rejects(
    database.query("UPDATE audit_logs SET outcome = 'FAILED' WHERE id = $1", [auditId]),
    /audit_logs is append-only/,
  );
  await assert.rejects(
    database.query('DELETE FROM audit_logs WHERE id = $1', [auditId]),
    /audit_logs is append-only/,
  );
  await assert.rejects(
    database.query(
      `INSERT INTO audit_logs (actor_username, action, object_type, outcome, correlation_id, previous_hash, entry_hash, chain_sequence)
       VALUES ('schema-validation-fixture', 'CHAIN_TAMPER', 'TEST', 'SUCCESS', '10000000-0000-4000-8000-000000000002', $1, $2, 2)`,
      ['f'.repeat(64), 'b'.repeat(64)],
    ),
    /previous_hash mismatch/,
  );
  const anchor = await database.query(
    `INSERT INTO audit_anchors (chain_partition, anchor_sequence, entry_hash, signature, signer_key_id)
     VALUES ('GLOBAL', 1, $1, 'fixture-sig', 'kid-1') RETURNING id`,
    [firstHash],
  );
  await assert.rejects(
    database.query("UPDATE audit_anchors SET status = 'TAMPERED' WHERE id = $1", [
      anchor.rows[0].id,
    ]),
    /audit_logs is append-only/,
  );
  await assert.rejects(
    database.query('TRUNCATE TABLE audit_logs CASCADE'),
    /audit_logs is append-only/,
  );
  await assert.rejects(
    database.query('TRUNCATE TABLE audit_anchors CASCADE'),
    /audit_logs is append-only/,
  );
  const survivingAudits = await database.query('SELECT count(*)::int AS count FROM audit_logs');
  assert.equal(survivingAudits.rows[0].count, 1);
  checks.push(
    'audit_logs and audit_anchors enforce append-only (UPDATE, DELETE, TRUNCATE) and HMAC chain link continuity',
  );

  // 2. Atomic transaction rollback on CHECK constraint violation
  await assert.rejects(
    database.transaction(async (transaction) => {
      await transaction.query(
        "INSERT INTO departments (code, name) VALUES ('ROLLBACK_TEST', 'Rollback test')",
      );
      await transaction.query(
        "INSERT INTO system_health_snapshots (service_name, status, response_time_ms) VALUES ('test', 'HEALTHY', -1)",
      );
    }),
    { code: '23514' },
  );
  const rolledBack = await database.query(
    "SELECT id FROM departments WHERE code = 'ROLLBACK_TEST'",
  );
  assert.equal(rolledBack.rows.length, 0);
  checks.push('check constraint failure rolls back the entire transaction');

  // 3. Department hierarchy cycle prevention (recursive CTE trigger) and updated_at refresh
  const parentDept = await database.query(
    "INSERT INTO departments (code, name) VALUES ('VALIDATION_HQ', 'Validation HQ') RETURNING id",
  );
  const departmentId = parentDept.rows[0].id;
  const childDept = await database.query(
    "INSERT INTO departments (code, name, parent_id) VALUES ('VALIDATION_SUB', 'Validation Sub', $1) RETURNING id",
    [departmentId],
  );
  await assert.rejects(
    database.query('UPDATE departments SET parent_id = $1 WHERE id = $2', [
      childDept.rows[0].id,
      departmentId,
    ]),
    /department hierarchy cycle detected/,
  );
  await database.query(
    "UPDATE departments SET name = 'Validation HQ Updated', updated_at = '2000-01-01T00:00:00Z' WHERE id = $1",
    [departmentId],
  );
  const refreshed = await database.query(
    "SELECT updated_at > '2000-01-02T00:00:00Z' AS ok FROM departments WHERE id = $1",
    [departmentId],
  );
  assert.equal(refreshed.rows[0].ok, true);
  checks.push('department cycle trigger rejects loops and updated_at overrides stale timestamps');

  // 4. Hardened authentication refresh-token family trigger & WebAuthn MFA support
  const user = await database.query(
    `INSERT INTO users (username, email, password_hash, full_name, department_id, status)
     VALUES ('schema-fixture', 'schema-fixture@example.invalid', $1, 'Schema fixture', $2, 'ACTIVE') RETURNING id`,
    ['not-an-authentication-hash', departmentId],
  );
  const userId = user.rows[0].id;
  const sessionId = '40000000-0000-4000-8000-000000000001';
  const familyId = '40000000-0000-4000-8000-000000000002';
  await database.query(
    "INSERT INTO auth_sessions (id, user_id, token_family_id, expires_at) VALUES ($1, $2, $3, now() + interval '1 hour')",
    [sessionId, userId, familyId],
  );
  await assert.rejects(
    database.query(
      `INSERT INTO refresh_tokens (id, auth_session_id, token_family_id, token_hash, expires_at)
       VALUES ('40000000-0000-4000-8000-000000000003', $1, '40000000-0000-4000-8000-000000000099', $2, now() + interval '1 hour')`,
      [sessionId, 'c'.repeat(64)],
    ),
    /refresh token family does not match auth session/,
  );
  await database.query(
    `INSERT INTO mfa_methods (id, user_id, method_type, secret_encrypted)
     VALUES ('40000000-0000-4000-8000-000000000004', $1, 'WEBAUTHN', 'fixture-credential')`,
    [userId],
  );
  checks.push('auth refresh-token family trigger and WEBAUTHN MFA enum are enforced');

  // 5. Document current_version_id ownership & SCD Type 2 classification uniqueness
  const firstDocId = '20000000-0000-4000-8000-000000000001';
  const secondDocId = '20000000-0000-4000-8000-000000000002';
  for (const [id, code] of [
    [firstDocId, 'VALIDATION_A'],
    [secondDocId, 'VALIDATION_B'],
  ]) {
    await database.query(
      'INSERT INTO documents (id, document_code, title, owner_id, department_id) VALUES ($1, $2, $3, $4, $5)',
      [id, code, 'Synthetic schema validation', userId, departmentId],
    );
  }
  const version = await database.query(
    `INSERT INTO document_versions
     (document_id, version_no, original_filename, storage_key, mime_type, file_size_bytes, sha256_hash, encryption_key_ref, uploaded_by)
     VALUES ($1, 1, 'fixture.txt', 'validation/fixture', 'text/plain', 1, $2, 'nonexistent-fixture-reference', $3) RETURNING id`,
    [firstDocId, '1'.repeat(64), userId],
  );
  await database.query('UPDATE documents SET current_version_id = $1 WHERE id = $2', [
    version.rows[0].id,
    firstDocId,
  ]);
  await assert.rejects(
    database.query('UPDATE documents SET current_version_id = $1 WHERE id = $2', [
      version.rows[0].id,
      secondDocId,
    ]),
    /current_version_id does not belong to document/,
  );

  const classification = await database.query(
    "INSERT INTO classification_levels (code, name, rank) VALUES ('VALIDATION_HIGH', 'Validation high', 2) RETURNING id",
  );
  const category = await database.query(
    "INSERT INTO business_categories (code, name) VALUES ('VALIDATION', 'Validation') RETURNING id",
  );
  const classificationSql = `INSERT INTO document_classification_history
    (document_id, classification_level_id, business_category_id, classified_by) VALUES ($1, $2, $3, $4)`;
  const classificationParams = [firstDocId, classification.rows[0].id, category.rows[0].id, userId];
  await database.query(classificationSql, classificationParams);
  await assert.rejects(database.query(classificationSql, classificationParams), { code: '23505' });
  checks.push('document version ownership and single current classification constraints hold');

  // 6. Bell-LaPadula clearance validation & deterministic ABAC monotonic version bumps
  const definition = await database.query(
    "INSERT INTO attribute_definitions (code, name, scope, value_type) VALUES ('CLEARANCE_LEVEL', 'Clearance', 'USER', 'ENUM') RETURNING id, version",
  );
  const option = await database.query(
    "INSERT INTO attribute_options (attribute_definition_id, value_code, display_name, numeric_rank) VALUES ($1, 'LOW', 'Low', 1) RETURNING id",
    [definition.rows[0].id],
  );
  const bumpedDefinition = await database.query(
    'SELECT version FROM attribute_definitions WHERE id = $1',
    [definition.rows[0].id],
  );
  assert.ok(BigInt(bumpedDefinition.rows[0].version) > BigInt(definition.rows[0].version));

  await database.query(
    'INSERT INTO user_attribute_assignments (user_id, attribute_definition_id, option_id, assigned_by) VALUES ($1, $2, $3, $1)',
    [userId, definition.rows[0].id, option.rows[0].id],
  );
  const grantSql = `INSERT INTO access_grants
    (id, document_id, principal_type, principal_user_id, source, valid_from, valid_until, granted_by)
    VALUES ('30000000-0000-4000-8000-000000000001', $1, 'USER', $2, 'DIRECT', now(), now() + interval '1 hour', $2)`;
  await assert.rejects(
    database.query(grantSql, [firstDocId, userId]),
    /Clearance level is insufficient/,
  );
  await database.query('UPDATE attribute_options SET numeric_rank = 2 WHERE id = $1', [
    option.rows[0].id,
  ]);
  await database.query(grantSql, [firstDocId, userId]);

  const adminRole = await database.query(
    "INSERT INTO roles (code, name, is_system_role) VALUES ('SYSTEM_ADMIN', 'System Admin', TRUE) RETURNING id",
  );
  const readerRole = await database.query(
    "INSERT INTO roles (code, name, is_system_role) VALUES ('DOCUMENT_READER', 'Document Reader', TRUE) RETURNING id",
  );
  const roleGrantSql = `INSERT INTO access_grants
    (id, document_id, principal_type, principal_role_id, source, valid_from, valid_until, granted_by)
    VALUES ($1, $2, 'ROLE', $3, 'DIRECT', now(), now() + interval '1 hour', $4)`;

  await assert.rejects(
    database.query(roleGrantSql, [
      '30000000-0000-4000-8000-000000000002',
      firstDocId,
      adminRole.rows[0].id,
      userId,
    ]),
    /Separation of duties violation/,
  );
  await assert.rejects(
    database.query(roleGrantSql, [
      '30000000-0000-4000-8000-000000000003',
      firstDocId,
      readerRole.rows[0].id,
      userId,
    ]),
    /Clearance level is insufficient/,
  );
  await database.query(
    'INSERT INTO user_roles (user_id, role_id, assigned_by) VALUES ($1, $2, $1)',
    [userId, readerRole.rows[0].id],
  );
  await database.query(roleGrantSql, [
    '30000000-0000-4000-8000-000000000004',
    firstDocId,
    readerRole.rows[0].id,
    userId,
  ]);

  // 7. BUG-018: USER grant enforces users.status = 'ACTIVE', SoD (system + custom privileged roles), and is_active = TRUE guards
  const pendingUser = await database.query(
    `INSERT INTO users (username, email, password_hash, full_name, department_id, status)
     VALUES ('pending-fixture', 'pending-fixture@example.invalid', $1, 'Pending fixture', $2, 'PENDING') RETURNING id`,
    ['not-an-authentication-hash', departmentId],
  );
  await database.query(
    'INSERT INTO user_attribute_assignments (user_id, attribute_definition_id, option_id, assigned_by) VALUES ($1, $2, $3, $4)',
    [pendingUser.rows[0].id, definition.rows[0].id, option.rows[0].id, userId],
  );
  await assert.rejects(
    database.query(
      `INSERT INTO access_grants (id, document_id, principal_type, principal_user_id, source, valid_from, valid_until, granted_by)
       VALUES ('30000000-0000-4000-8000-000000000005', $1, 'USER', $2, 'DIRECT', now(), now() + interval '1 hour', $3)`,
      [firstDocId, pendingUser.rows[0].id, userId],
    ),
    /Target user is not active/,
  );

  const secOfficerRole = await database.query(
    "INSERT INTO roles (code, name, is_system_role) VALUES ('SECURITY_OFFICER', 'Security Officer', TRUE) RETURNING id",
  );
  const secUser = await database.query(
    `INSERT INTO users (username, email, password_hash, full_name, department_id, status)
     VALUES ('sec-fixture', 'sec-fixture@example.invalid', $1, 'Sec fixture', $2, 'ACTIVE') RETURNING id`,
    ['not-an-authentication-hash', departmentId],
  );
  await database.query(
    'INSERT INTO user_attribute_assignments (user_id, attribute_definition_id, option_id, assigned_by) VALUES ($1, $2, $3, $4)',
    [secUser.rows[0].id, definition.rows[0].id, option.rows[0].id, userId],
  );
  await database.query(
    'INSERT INTO user_roles (user_id, role_id, assigned_by) VALUES ($1, $2, $3)',
    [secUser.rows[0].id, secOfficerRole.rows[0].id, userId],
  );
  await assert.rejects(
    database.query(
      `INSERT INTO access_grants (id, document_id, principal_type, principal_user_id, source, valid_from, valid_until, granted_by)
       VALUES ('30000000-0000-4000-8000-000000000006', $1, 'USER', $2, 'DIRECT', now(), now() + interval '1 hour', $3)`,
      [firstDocId, secUser.rows[0].id, userId],
    ),
    /Separation of duties violation/,
  );

  // Custom role holding real privileged permission `POLICY:MANAGE` must be blocked for both ROLE and USER grants
  const policyPerm = await database.query(
    `INSERT INTO permissions (code, name, resource_type, action)
     VALUES ('POLICY_MANAGE', 'Manage Policies', 'POLICY', 'MANAGE') RETURNING id`,
  );
  const customPrivRole = await database.query(
    "INSERT INTO roles (code, name, is_system_role) VALUES ('CUSTOM_POLICY_MGR', 'Custom Policy Mgr', FALSE) RETURNING id",
  );
  await database.query(
    'INSERT INTO role_permissions (role_id, permission_id, granted_by) VALUES ($1, $2, $3)',
    [customPrivRole.rows[0].id, policyPerm.rows[0].id, userId],
  );
  await assert.rejects(
    database.query(roleGrantSql, [
      '30000000-0000-4000-8000-000000000007',
      firstDocId,
      customPrivRole.rows[0].id,
      userId,
    ]),
    /Separation of duties violation/,
  );

  // Inactive role must be rejected
  const inactiveRole = await database.query(
    "INSERT INTO roles (code, name, is_system_role, is_active) VALUES ('INACTIVE_READER', 'Inactive Reader', FALSE, FALSE) RETURNING id",
  );
  await assert.rejects(
    database.query(roleGrantSql, [
      '30000000-0000-4000-8000-000000000008',
      firstDocId,
      inactiveRole.rows[0].id,
      userId,
    ]),
    /Target role is not active/,
  );

  // DOCUMENT_OWNER with AUDIT_LOG:VIEW must remain allowed to receive USER grants (no false positive)
  const auditViewPerm = await database.query(
    `INSERT INTO permissions (code, name, resource_type, action)
     VALUES ('AUDIT_VIEW', 'View Audit', 'AUDIT_LOG', 'VIEW') RETURNING id`,
  );
  const ownerRole = await database.query(
    "INSERT INTO roles (code, name, is_system_role) VALUES ('DOCUMENT_OWNER', 'Document Owner', TRUE) RETURNING id",
  );
  await database.query(
    'INSERT INTO role_permissions (role_id, permission_id, granted_by) VALUES ($1, $2, $3)',
    [ownerRole.rows[0].id, auditViewPerm.rows[0].id, userId],
  );
  const ownerUser = await database.query(
    `INSERT INTO users (username, email, password_hash, full_name, department_id, status)
     VALUES ('owner-fixture', 'owner-fixture@example.invalid', $1, 'Owner fixture', $2, 'ACTIVE') RETURNING id`,
    ['not-an-authentication-hash', departmentId],
  );
  await database.query(
    'INSERT INTO user_attribute_assignments (user_id, attribute_definition_id, option_id, assigned_by) VALUES ($1, $2, $3, $4)',
    [ownerUser.rows[0].id, definition.rows[0].id, option.rows[0].id, userId],
  );
  await database.query(
    'INSERT INTO user_roles (user_id, role_id, assigned_by) VALUES ($1, $2, $3)',
    [ownerUser.rows[0].id, ownerRole.rows[0].id, userId],
  );
  await database.query(
    `INSERT INTO access_grants (id, document_id, principal_type, principal_user_id, source, valid_from, valid_until, granted_by)
     VALUES ('30000000-0000-4000-8000-000000000009', $1, 'USER', $2, 'DIRECT', now(), now() + interval '1 hour', $3)`,
    [firstDocId, ownerUser.rows[0].id, userId],
  );

  // Deactivating clearance option must cause subsequent USER grant to fail
  await database.query('UPDATE attribute_options SET is_active = FALSE WHERE id = $1', [
    option.rows[0].id,
  ]);
  await assert.rejects(
    database.query(
      `INSERT INTO access_grants (id, document_id, principal_type, principal_user_id, source, valid_from, valid_until, granted_by)
       VALUES ('30000000-0000-4000-8000-000000000010', $1, 'USER', $2, 'DIRECT', now(), now() + interval '1 hour', $3)`,
      [firstDocId, ownerUser.rows[0].id, userId],
    ),
    /Clearance level is insufficient/,
  );
  await database.query('UPDATE attribute_options SET is_active = TRUE WHERE id = $1', [
    option.rows[0].id,
  ]);

  // 8. BUG-017: Positive RLS role allowlist via sda_backend_rls_member & safe_postgrest_jwt_role()
  await database.exec(`
    CREATE ROLE bi_readonly_probe NOLOGIN;
    CREATE ROLE custom_backend_probe NOLOGIN;
    GRANT USAGE ON SCHEMA public TO bi_readonly_probe, custom_backend_probe;
    GRANT SELECT ON public.users TO bi_readonly_probe, custom_backend_probe;
    GRANT sda_backend_rls_member TO custom_backend_probe;
  `);

  // Unprivileged role must see 0 rows even after attempting to self-spoof app.trusted_db_role
  await database.transaction(async (tx) => {
    await tx.exec(
      "SET LOCAL ROLE bi_readonly_probe; SET LOCAL app.trusted_db_role = 'bi_readonly_probe';",
    );
    const spoofedRows = await tx.query('SELECT count(*)::int AS count FROM public.users');
    assert.equal(
      spoofedRows.rows[0].count,
      0,
      'Unprivileged role must be denied by FORCE RLS even with spoofed GUC',
    );
  });

  // Member of sda_backend_rls_member must see rows when JWT claims are clean, and fail closed on malformed JSON JWT claims without throwing
  await database.transaction(async (tx) => {
    await tx.exec('SET LOCAL ROLE custom_backend_probe;');
    const allowedRows = await tx.query('SELECT count(*)::int AS count FROM public.users');
    assert.ok(allowedRows.rows[0].count >= 1, 'Member of sda_backend_rls_member must pass RLS');

    await tx.exec("SET LOCAL request.jwt.claims = '{malformed-json';");
    const malformedJwtRows = await tx.query('SELECT count(*)::int AS count FROM public.users');
    assert.equal(
      malformedJwtRows.rows[0].count,
      0,
      'Malformed request.jwt.claims must fail closed without throwing JSON cast error',
    );
  });

  checks.push(
    'Bell-LaPadula clearance trigger (USER + ROLE Lattice Meet + SoD + active guards) and positive RLS group-role allowlist hold',
  );

  return checks;
}
