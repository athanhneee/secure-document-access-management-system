import assert from 'node:assert/strict';

/**
 * Algorithm: Defense-in-Depth Database Invariant Probing.
 * Exercises triggers, partial unique indexes, recursive CTE hierarchy checks,
 * Bell-LaPadula clearance rank comparisons, HMAC audit chain continuity, and
 * monotonic ABAC sequence bumps against synthetic in-memory fixtures.
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
    `INSERT INTO users (username, email, password_hash, full_name, department_id)
     VALUES ('schema-fixture', 'schema-fixture@example.invalid', $1, 'Schema fixture', $2) RETURNING id`,
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

  checks.push(
    'Bell-LaPadula clearance trigger (USER + ROLE Lattice Meet + SoD) and ABAC monotonic version bump triggers hold',
  );

  return checks;
}
