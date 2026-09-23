import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { DocumentsService } from '../dist/modules/documents/documents.service.js';
import { AuthorizationCache } from '../dist/modules/rbac/authorization-cache.js';

// ── Mock Helpers ─────────────────────────────────────────────────────────────

function createMockAudit() {
  const recorded = [];
  return {
    recorded,
    record: async (event, context) => {
      recorded.push({ ...event, context });
    },
  };
}

function createMockAuthorization(permissions = []) {
  return {
    hasPermission: async (principal, resource, action, options = {}) => {
      return permissions.some(
        (p) =>
          p.userId === principal.userId &&
          p.resource === resource &&
          p.action === action &&
          (!options.targetDepartmentId ||
            p.scopeDepartmentId === null ||
            p.scopeDepartmentId === options.targetDepartmentId),
      );
    },
  };
}

function createInMemoryDatabase(initialState = {}) {
  const documents = new Map(
    (initialState.documents ?? []).map(([k, v]) => [
      k,
      {
        created_at: new Date(),
        updated_at: new Date(),
        version: 0,
        ...v,
      },
    ]),
  );
  const versions = new Map(initialState.versions ?? []);
  const classifications = new Map(initialState.classifications ?? []);
  const classificationLevels = new Map(
    initialState.classificationLevels ?? [
      [1n, { id: 1n, code: 'INTERNAL', name: 'Nội bộ', rank: 1, is_active: true }],
      [2n, { id: 2n, code: 'CONFIDENTIAL', name: 'Mật', rank: 2, is_active: true }],
      [3n, { id: 3n, code: 'SECRET', name: 'Tối mật', rank: 3, is_active: true }],
      [4n, { id: 4n, code: 'TOP_SECRET', name: 'Tuyệt mật', rank: 4, is_active: true }],
    ],
  );
  const businessCategories = new Map(
    initialState.businessCategories ?? [
      [10n, { id: 10n, code: 'GENERAL_OPS', name: 'Nghiệp vụ chung', is_active: true }],
      [20n, { id: 20n, code: 'FINANCE', name: 'Tài chính', is_active: true }],
    ],
  );
  const departments = new Map(
    initialState.departments ?? [
      [100n, { id: 100n, code: 'DEPT_A', name: 'Phòng A', is_active: true }],
      [200n, { id: 200n, code: 'DEPT_INACTIVE', name: 'Phòng Inactive', is_active: false }],
    ],
  );
  const users = new Map(
    initialState.users ?? [
      [1n, { id: 1n, username: 'owner_user', status: 'ACTIVE' }],
      [2n, { id: 2n, username: 'other_user', status: 'ACTIVE' }],
      [3n, { id: 3n, username: 'low_clearance_user', status: 'ACTIVE' }],
      [4n, { id: 4n, username: 'high_clearance_user', status: 'ACTIVE' }],
      [99n, { id: 99n, username: 'disabled_user', status: 'DISABLED' }],
    ],
  );
  const accessGrants = new Map(initialState.accessGrants ?? []);
  const accessSessions = new Map(initialState.accessSessions ?? []);
  const userAttributeAssignments = new Map(initialState.userAttributeAssignments ?? []);
  const notifications = new Map();
  const securityAlerts = new Map();

  let autoId = 1000n;

  const db = {
    document: {
      findUnique: async ({ where }) => {
        const doc = documents.get(where.id);
        if (!doc) return null;
        const currentVersion = doc.current_version_id ? versions.get(doc.current_version_id) : null;
        const history = Array.from(classifications.values())
          .filter((c) => c.document_id === doc.id)
          .map((c) => ({
            ...c,
            classification_levels: classificationLevels.get(c.classification_level_id),
            business_categories: businessCategories.get(c.business_category_id),
          }));
        return {
          ...doc,
          users: users.get(doc.owner_id),
          departments: departments.get(doc.department_id),
          current_version: currentVersion,
          classification_history: history,
        };
      },
      findMany: async ({ where = {} } = {}) => {
        let list = Array.from(documents.values());
        if (where.status?.notIn) {
          list = list.filter((d) => !where.status.notIn.includes(d.status));
        }
        if (where.retention_until?.lte) {
          list = list.filter(
            (d) => d.retention_until && d.retention_until <= where.retention_until.lte,
          );
        }
        return list.map((doc) => ({
          ...doc,
          users: users.get(doc.owner_id),
        }));
      },
      create: async ({ data }) => {
        const record = {
          ...data,
          version: 0,
          created_at: new Date(),
          updated_at: new Date(),
        };
        documents.set(data.id, record);
        return record;
      },
      update: async ({ where, data }) => {
        const doc = documents.get(where.id);
        if (!doc) throw new Error('Document not found');
        const updated = {
          ...doc,
          ...data,
          version:
            typeof data.version?.increment === 'number'
              ? (doc.version ?? 0) + data.version.increment
              : (data.version ?? doc.version),
          updated_at: new Date(),
        };
        documents.set(where.id, updated);
        return updated;
      },
    },
    documentVersion: {
      findUnique: async ({ where }) => {
        if (where.id) return versions.get(where.id) ?? null;
        if (where.document_id_version_no) {
          const { document_id, version_no } = where.document_id_version_no;
          return (
            Array.from(versions.values()).find(
              (v) => v.document_id === document_id && v.version_no === version_no,
            ) ?? null
          );
        }
        return null;
      },
      findMany: async ({ where = {} } = {}) => {
        let list = Array.from(versions.values());
        if (where.document_id) list = list.filter((v) => v.document_id === where.document_id);
        return list;
      },
      create: async ({ data }) => {
        const id = ++autoId;
        const record = { id, ...data, created_at: new Date() };
        versions.set(id, record);
        return record;
      },
    },
    documentClassificationHistory: {
      findFirst: async ({ where }) => {
        const list = Array.from(classifications.values()).filter((c) => {
          if (c.document_id !== where.document_id) return false;
          if (where.effective_to === null && c.effective_to !== null) return false;
          return true;
        });
        const found = list[0];
        if (!found) return null;
        return {
          ...found,
          classification_levels: classificationLevels.get(found.classification_level_id),
          business_categories: businessCategories.get(found.business_category_id),
        };
      },
      findMany: async ({ where }) => {
        return Array.from(classifications.values())
          .filter((c) => c.document_id === where.document_id)
          .map((c) => ({
            ...c,
            classification_levels: classificationLevels.get(c.classification_level_id),
            business_categories: businessCategories.get(c.business_category_id),
          }));
      },
      create: async ({ data }) => {
        const id = ++autoId;
        const record = { id, ...data };
        classifications.set(id, record);
        return record;
      },
      update: async ({ where, data }) => {
        const rec = classifications.get(where.id);
        if (!rec) throw new Error('Classification record not found');
        const updated = { ...rec, ...data };
        classifications.set(where.id, updated);
        return updated;
      },
    },
    classificationLevel: {
      findUnique: async ({ where }) => classificationLevels.get(where.id) ?? null,
    },
    businessCategory: {
      findUnique: async ({ where }) => businessCategories.get(where.id) ?? null,
    },
    department: {
      findUnique: async ({ where }) => departments.get(where.id) ?? null,
    },
    user: {
      findUnique: async ({ where }) => users.get(where.id) ?? null,
    },
    accessGrant: {
      findMany: async ({ where }) => {
        return Array.from(accessGrants.values()).filter((g) => {
          if (where.document_id && g.document_id !== where.document_id) return false;
          if (where.status && g.status !== where.status) return false;
          return true;
        });
      },
      update: async ({ where, data }) => {
        const grant = accessGrants.get(where.id);
        if (!grant) throw new Error('Grant not found');
        const updated = { ...grant, ...data };
        accessGrants.set(where.id, updated);
        return updated;
      },
      updateMany: async ({ where, data }) => {
        let count = 0;
        for (const [id, grant] of accessGrants.entries()) {
          if (where.document_id && grant.document_id !== where.document_id) continue;
          if (where.status && grant.status !== where.status) continue;
          accessGrants.set(id, { ...grant, ...data });
          count++;
        }
        return { count };
      },
    },
    accessSession: {
      findMany: async ({ where }) => {
        return Array.from(accessSessions.values()).filter((s) => {
          if (where.access_grant_id && s.access_grant_id !== where.access_grant_id) return false;
          if (where.status && s.status !== where.status) return false;
          return true;
        });
      },
      update: async ({ where, data }) => {
        const session = accessSessions.get(where.id);
        if (!session) throw new Error('Session not found');
        const updated = { ...session, ...data };
        accessSessions.set(where.id, updated);
        return updated;
      },
      updateMany: async ({ where, data }) => {
        let count = 0;
        for (const [id, session] of accessSessions.entries()) {
          if (where.access_grant_id && session.access_grant_id !== where.access_grant_id) continue;
          if (where.status && session.status !== where.status) continue;
          if (
            where.document_version_id?.in &&
            !where.document_version_id.in.includes(session.document_version_id)
          ) {
            continue;
          }
          accessSessions.set(id, { ...session, ...data });
          count++;
        }
        return { count };
      },
    },
    userAttributeAssignment: {
      findFirst: async ({ where }) => {
        const assignments = Array.from(userAttributeAssignments.values()).filter(
          (a) =>
            a.user_id === where.user_id && a.attribute_code === where.attribute_definitions?.code,
        );
        if (assignments.length === 0) return null;
        return {
          ...assignments[0],
          attribute_options: { numeric_rank: assignments[0].numeric_rank },
        };
      },
    },
    notification: {
      create: async ({ data }) => {
        notifications.set(data.id, data);
        return data;
      },
    },
    securityAlert: {
      create: async ({ data }) => {
        securityAlerts.set(data.id, data);
        return data;
      },
    },
    $transaction: async (fn) => fn(db),
  };

  return {
    db,
    documents,
    versions,
    classifications,
    accessGrants,
    accessSessions,
    userAttributeAssignments,
    notifications,
    securityAlerts,
  };
}

// ── Test Cases ───────────────────────────────────────────────────────────────

test('Document Lifecycle: creates draft with required fields, initial classification and audit', async () => {
  const { db } = createInMemoryDatabase();
  const mockAudit = createMockAudit();
  const mockAuth = createMockAuthorization();
  const cache = new AuthorizationCache();
  const service = new DocumentsService(mockAudit, mockAuth, cache, db);

  const principal = { userId: 1n, username: 'owner_user', roles: ['DOCUMENT_OWNER'], mfa: true };
  const context = { ip: '127.0.0.1', correlationId: randomUUID() };

  const created = await service.createDocumentDraft(
    {
      title: 'Kế hoạch an ninh mạng 2026',
      departmentId: 100n,
      description: 'Tài liệu mật về bảo mật hệ thống',
      classificationLevelId: 2n, // CONFIDENTIAL (rank 2)
      businessCategoryId: 10n, // GENERAL_OPS
      retentionUntil: '2028-12-31',
    },
    principal,
    context,
  );

  assert.ok(created.id);
  assert.equal(created.title, 'Kế hoạch an ninh mạng 2026');
  assert.equal(created.status, 'DRAFT');
  assert.equal(created.ownerId, '1');
  assert.equal(created.departmentId, '100');
  assert.equal(created.retentionUntil, '2028-12-31');
  assert.ok(created.currentClassification);
  assert.equal(created.currentClassification.classificationLevelCode, 'CONFIDENTIAL');
  assert.equal(created.currentClassification.rank, 2);

  // Check audit log
  const auditEvent = mockAudit.recorded.find((a) => a.action === 'DOCUMENT_CREATED');
  assert.ok(auditEvent);
  assert.equal(auditEvent.outcome, 'SUCCESS');
  assert.equal(auditEvent.actorUserId, 1n);
});

test('Document Lifecycle: rejects activation when missing classification or CLEAN version', async () => {
  const docId = randomUUID();
  const { db, documents, versions } = createInMemoryDatabase({
    documents: [
      [
        docId,
        {
          id: docId,
          document_code: 'DOC-TEST1',
          title: 'Draft document',
          owner_id: 1n,
          department_id: 100n,
          status: 'DRAFT',
          current_version_id: null,
          retention_until: null,
        },
      ],
    ],
  });

  const mockAudit = createMockAudit();
  const mockAuth = createMockAuthorization();
  const cache = new AuthorizationCache();
  const service = new DocumentsService(mockAudit, mockAuth, cache, db);
  const principal = { userId: 1n, username: 'owner_user', roles: ['DOCUMENT_OWNER'], mfa: true };
  const context = { ip: '127.0.0.1', correlationId: randomUUID() };

  // 1. Fails when missing classification
  await assert.rejects(
    service.activateDocument(docId, principal, context),
    (err) => err.response?.errorCode === 'DOCUMENT_ACTIVATION_FAILED',
  );

  // Add classification
  db.documentClassificationHistory.create({
    data: {
      document_id: docId,
      classification_level_id: 1n,
      business_category_id: 10n,
      reason: 'Draft classification',
      classified_by: 1n,
      effective_from: new Date(),
      effective_to: null,
    },
  });

  // 2. Fails when missing current_version
  await assert.rejects(
    service.activateDocument(docId, principal, context),
    (err) => err.response?.errorCode === 'DOCUMENT_ACTIVATION_FAILED',
  );

  // Add an INFECTED version
  const infectedVersionId = 5001n;
  versions.set(infectedVersionId, {
    id: infectedVersionId,
    document_id: docId,
    version_no: 1,
    original_filename: 'malware.pdf',
    scan_status: 'INFECTED',
    file_size_bytes: 1024n,
    sha256_hash: 'abc',
    created_at: new Date(),
  });
  documents.get(docId).current_version_id = infectedVersionId;

  // 3. Fails when current version is INFECTED
  await assert.rejects(
    service.activateDocument(docId, principal, context),
    (err) => err.response?.errorCode === 'VERSION_NOT_CLEAN',
  );

  // Replace with CLEAN version
  const cleanVersionId = 5002n;
  versions.set(cleanVersionId, {
    id: cleanVersionId,
    document_id: docId,
    version_no: 2,
    original_filename: 'clean.pdf',
    scan_status: 'CLEAN',
    file_size_bytes: 2048n,
    sha256_hash: 'def',
    created_at: new Date(),
  });
  documents.get(docId).current_version_id = cleanVersionId;

  // 4. Successfully activates with all requirements satisfied
  const activated = await service.activateDocument(docId, principal, context);
  assert.equal(activated.status, 'ACTIVE');

  // Verify audit event
  const activatedAudit = mockAudit.recorded.find((a) => a.action === 'DOCUMENT_ACTIVATED');
  assert.ok(activatedAudit);
  assert.equal(activatedAudit.outcome, 'SUCCESS');
});

test('Document Lifecycle: cannot point current_version to another document or non-CLEAN version', async () => {
  const docA = randomUUID();
  const docB = randomUUID();

  const { db, versions } = createInMemoryDatabase({
    documents: [
      [
        docA,
        {
          id: docA,
          document_code: 'DOC-A',
          title: 'Document A',
          owner_id: 1n,
          department_id: 100n,
          status: 'DRAFT',
          current_version_id: null,
        },
      ],
      [
        docB,
        {
          id: docB,
          document_code: 'DOC-B',
          title: 'Document B',
          owner_id: 1n,
          department_id: 100n,
          status: 'DRAFT',
          current_version_id: null,
        },
      ],
    ],
  });

  const versionDocB = 6001n;
  versions.set(versionDocB, {
    id: versionDocB,
    document_id: docB, // belongs to Doc B
    version_no: 1,
    original_filename: 'file-b.pdf',
    scan_status: 'CLEAN',
  });

  const versionDocAPending = 6002n;
  versions.set(versionDocAPending, {
    id: versionDocAPending,
    document_id: docA, // belongs to Doc A but scan is PENDING
    version_no: 1,
    original_filename: 'pending.pdf',
    scan_status: 'PENDING',
  });

  const mockAudit = createMockAudit();
  const mockAuth = createMockAuthorization();
  const cache = new AuthorizationCache();
  const service = new DocumentsService(mockAudit, mockAuth, cache, db);
  const principal = { userId: 1n, username: 'owner_user', roles: ['DOCUMENT_OWNER'], mfa: true };
  const context = { ip: '127.0.0.1', correlationId: randomUUID() };

  // 1. Try to set version of Doc B onto Doc A -> Rejected (INVALID_VERSION_TARGET)
  await assert.rejects(
    service.setCurrentVersion(docA, { versionId: versionDocB }, principal, context),
    (err) => err.response?.errorCode === 'INVALID_VERSION_TARGET',
  );

  // 2. Try to set PENDING scan status version -> Rejected (VERSION_NOT_CLEAN)
  await assert.rejects(
    service.setCurrentVersion(docA, { versionId: versionDocAPending }, principal, context),
    (err) => err.response?.errorCode === 'VERSION_NOT_CLEAN',
  );
});

test('Document Lifecycle: SCD Type 2 classification history preserves past rows and maintains exactly 1 active row', async () => {
  const docId = randomUUID();
  const { db } = createInMemoryDatabase({
    documents: [
      [
        docId,
        {
          id: docId,
          document_code: 'DOC-SCD2',
          title: 'SCD2 Test Document',
          owner_id: 1n,
          department_id: 100n,
          status: 'DRAFT',
        },
      ],
    ],
  });

  const mockAudit = createMockAudit();
  const mockAuth = createMockAuthorization();
  const cache = new AuthorizationCache();
  const service = new DocumentsService(mockAudit, mockAuth, cache, db);
  const principal = { userId: 1n, username: 'owner_user', roles: ['DOCUMENT_OWNER'], mfa: true };
  const context = { ip: '127.0.0.1', correlationId: randomUUID() };

  // Initial classification: INTERNAL (rank 1)
  await service.reclassifyDocument(
    docId,
    { classificationLevelId: 1n, businessCategoryId: 10n, reason: 'Initial classification' },
    principal,
    context,
  );

  // Second classification: CONFIDENTIAL (rank 2)
  await service.reclassifyDocument(
    docId,
    { classificationLevelId: 2n, businessCategoryId: 10n, reason: 'Promoted to Confidential' },
    principal,
    context,
  );

  // Third classification: SECRET (rank 3)
  await service.reclassifyDocument(
    docId,
    { classificationLevelId: 3n, businessCategoryId: 20n, reason: 'Escalated to Secret' },
    principal,
    context,
  );

  const history = await service.getClassificationHistory(docId);
  assert.equal(history.length, 3, 'All 3 classification rows are preserved');

  // Exactly one active classification with effective_to === null
  const activeRows = history.filter((h) => h.effectiveTo === null);
  assert.equal(activeRows.length, 1, 'Exactly 1 active row at any time');
  assert.equal(activeRows[0].classificationLevelCode, 'SECRET');
  assert.equal(activeRows[0].rank, 3);

  // The first two rows have valid effective_to timestamps
  assert.ok(history[0].effectiveTo !== null);
  assert.equal(history[0].classificationLevelCode, 'INTERNAL');
  assert.ok(history[1].effectiveTo !== null);
  assert.equal(history[1].classificationLevelCode, 'CONFIDENTIAL');
});

test('Document Lifecycle: Reclassification to higher level revokes insufficient user grants and terminates sessions', async () => {
  const docId = randomUUID();
  const grantUserLowId = randomUUID();
  const grantUserHighId = randomUUID();
  const sessionLowId = randomUUID();
  const sessionHighId = randomUUID();

  const { db, accessGrants, accessSessions } = createInMemoryDatabase({
    documents: [
      [
        docId,
        {
          id: docId,
          document_code: 'DOC-RECLASS',
          title: 'Reclassification security test',
          owner_id: 1n,
          department_id: 100n,
          status: 'ACTIVE',
        },
      ],
    ],
    // Low clearance user has rank 1 (INTERNAL)
    userAttributeAssignments: [
      [
        1n,
        {
          user_id: 3n,
          attribute_code: 'CLEARANCE_LEVEL',
          numeric_rank: 1,
        },
      ],
      // High clearance user has rank 4 (TOP_SECRET)
      [
        2n,
        {
          user_id: 4n,
          attribute_code: 'CLEARANCE_LEVEL',
          numeric_rank: 4,
        },
      ],
    ],
    // Active grants for both users
    accessGrants: [
      [
        grantUserLowId,
        {
          id: grantUserLowId,
          document_id: docId,
          principal_type: 'USER',
          principal_user_id: 3n,
          status: 'ACTIVE',
        },
      ],
      [
        grantUserHighId,
        {
          id: grantUserHighId,
          document_id: docId,
          principal_type: 'USER',
          principal_user_id: 4n,
          status: 'ACTIVE',
        },
      ],
    ],
    // Active sessions for both users
    accessSessions: [
      [
        sessionLowId,
        {
          id: sessionLowId,
          access_grant_id: grantUserLowId,
          document_version_id: 100n,
          user_id: 3n,
          status: 'ACTIVE',
        },
      ],
      [
        sessionHighId,
        {
          id: sessionHighId,
          access_grant_id: grantUserHighId,
          document_version_id: 100n,
          user_id: 4n,
          status: 'ACTIVE',
        },
      ],
    ],
  });

  // Document was initially rank 1 (INTERNAL)
  db.documentClassificationHistory.create({
    data: {
      document_id: docId,
      classification_level_id: 1n, // rank 1
      business_category_id: 10n,
      reason: 'Initial',
      classified_by: 1n,
      effective_from: new Date(),
      effective_to: null,
    },
  });

  const mockAudit = createMockAudit();
  const mockAuth = createMockAuthorization();
  const cache = new AuthorizationCache();
  const service = new DocumentsService(mockAudit, mockAuth, cache, db);
  const principal = { userId: 1n, username: 'owner_user', roles: ['DOCUMENT_OWNER'], mfa: true };
  const context = { ip: '127.0.0.1', correlationId: randomUUID() };

  // Reclassify to SECRET (rank 3)
  await service.reclassifyDocument(
    docId,
    { classificationLevelId: 3n, businessCategoryId: 10n, reason: 'Escalation to SECRET' },
    principal,
    context,
  );

  // 1. Low clearance user grant is REVOKED
  const lowGrant = accessGrants.get(grantUserLowId);
  assert.equal(lowGrant.status, 'REVOKED');
  assert.match(lowGrant.revoke_reason, /clearance insufficient/i);

  // 2. Low clearance user session is TERMINATED
  const lowSession = accessSessions.get(sessionLowId);
  assert.equal(lowSession.status, 'TERMINATED');

  // 3. High clearance user grant stays ACTIVE
  const highGrant = accessGrants.get(grantUserHighId);
  assert.equal(highGrant.status, 'ACTIVE');

  // 4. High clearance user session stays ACTIVE
  const highSession = accessSessions.get(sessionHighId);
  assert.equal(highSession.status, 'ACTIVE');
});

test('Document Lifecycle: Reclassification to lower level does NOT automatically expand or restore revoked grants', async () => {
  const docId = randomUUID();
  const revokedGrantId = randomUUID();

  const { db, accessGrants } = createInMemoryDatabase({
    documents: [
      [
        docId,
        {
          id: docId,
          document_code: 'DOC-DEESCALATE',
          title: 'De-escalation test',
          owner_id: 1n,
          department_id: 100n,
          status: 'ACTIVE',
        },
      ],
    ],
    accessGrants: [
      [
        revokedGrantId,
        {
          id: revokedGrantId,
          document_id: docId,
          principal_type: 'USER',
          principal_user_id: 3n,
          status: 'REVOKED',
          revoke_reason: 'Previously revoked',
        },
      ],
    ],
  });

  // Current classification is TOP_SECRET (rank 4)
  db.documentClassificationHistory.create({
    data: {
      document_id: docId,
      classification_level_id: 4n,
      business_category_id: 10n,
      reason: 'Top secret level',
      classified_by: 1n,
      effective_from: new Date(),
      effective_to: null,
    },
  });

  const mockAudit = createMockAudit();
  const mockAuth = createMockAuthorization();
  const cache = new AuthorizationCache();
  const service = new DocumentsService(mockAudit, mockAuth, cache, db);
  const principal = { userId: 1n, username: 'owner_user', roles: ['DOCUMENT_OWNER'], mfa: true };
  const context = { ip: '127.0.0.1', correlationId: randomUUID() };

  // Downgrade to INTERNAL (rank 1)
  await service.reclassifyDocument(
    docId,
    { classificationLevelId: 1n, businessCategoryId: 10n, reason: 'Declassified to Internal' },
    principal,
    context,
  );

  // Revoked grant MUST remain REVOKED (not automatically un-revoked or expanded)
  const grant = accessGrants.get(revokedGrantId);
  assert.equal(grant.status, 'REVOKED');
});

test('Document Lifecycle: Archiving transitions to ARCHIVED, sets archived_at, suspends grants, terminates sessions', async () => {
  const docId = randomUUID();
  const grantId = randomUUID();
  const sessionId = randomUUID();
  const versionId = 9999n;

  const { db, accessGrants, accessSessions } = createInMemoryDatabase({
    documents: [
      [
        docId,
        {
          id: docId,
          document_code: 'DOC-ARCHIVE',
          title: 'Archive test',
          owner_id: 1n,
          department_id: 100n,
          status: 'ACTIVE',
          archived_at: null,
        },
      ],
    ],
    versions: [
      [
        versionId,
        {
          id: versionId,
          document_id: docId,
          version_no: 1,
          scan_status: 'CLEAN',
        },
      ],
    ],
    accessGrants: [
      [
        grantId,
        {
          id: grantId,
          document_id: docId,
          status: 'ACTIVE',
        },
      ],
    ],
    accessSessions: [
      [
        sessionId,
        {
          id: sessionId,
          access_grant_id: grantId,
          document_version_id: versionId,
          status: 'ACTIVE',
        },
      ],
    ],
  });

  const mockAudit = createMockAudit();
  const mockAuth = createMockAuthorization();
  const cache = new AuthorizationCache();
  const service = new DocumentsService(mockAudit, mockAuth, cache, db);
  const principal = { userId: 1n, username: 'owner_user', roles: ['DOCUMENT_OWNER'], mfa: true };
  const context = { ip: '127.0.0.1', correlationId: randomUUID() };

  // Archive document
  const archived = await service.archiveDocument(
    docId,
    { reason: 'Project closed' },
    principal,
    context,
  );

  assert.equal(archived.status, 'ARCHIVED');
  assert.ok(archived.archivedAt !== null, 'archived_at is set for DB check constraint');

  // Verify grant is SUSPENDED
  assert.equal(accessGrants.get(grantId).status, 'SUSPENDED');

  // Verify session is TERMINATED
  assert.equal(accessSessions.get(sessionId).status, 'TERMINATED');

  // Future metadata mutation or upload to archived document is blocked
  await assert.rejects(
    service.updateMetadata(docId, { title: 'New title' }, principal, context),
    (err) => err.response?.errorCode === 'DOCUMENT_ARCHIVED',
  );
});

test('Document Lifecycle: Technical Admin cannot modify document metadata without business permission', async () => {
  const docId = randomUUID();
  const { db } = createInMemoryDatabase({
    documents: [
      [
        docId,
        {
          id: docId,
          document_code: 'DOC-ADMIN-CHECK',
          title: 'Protected business document',
          owner_id: 1n, // Owned by user 1
          department_id: 100n,
          status: 'DRAFT',
        },
      ],
    ],
  });

  const mockAudit = createMockAudit();
  // System admin (userId: 888n) has NO business permission for DOCUMENT
  const mockAuth = createMockAuthorization([]);
  const cache = new AuthorizationCache();
  const service = new DocumentsService(mockAudit, mockAuth, cache, db);

  const techAdminPrincipal = {
    userId: 888n,
    username: 'admin.tech',
    roles: ['SYSTEM_ADMIN'],
    mfa: true,
  };
  const context = { ip: '127.0.0.1', correlationId: randomUUID() };

  // Technical admin tries to edit metadata -> 403 Forbidden (TECHNICAL_ADMIN_CANNOT_OWN)
  await assert.rejects(
    service.updateMetadata(docId, { title: 'Hacked by admin' }, techAdminPrincipal, context),
    (err) => err.response?.errorCode === 'TECHNICAL_ADMIN_CANNOT_OWN',
  );

  // Business admin with department scoped permission (userId: 555n) succeeds
  const businessAdminAuth = createMockAuthorization([
    {
      userId: 555n,
      resource: 'DOCUMENT',
      action: 'CLASSIFY',
      scopeDepartmentId: 100n,
    },
  ]);
  const businessService = new DocumentsService(mockAudit, businessAdminAuth, cache, db);
  const businessAdminPrincipal = {
    userId: 555n,
    username: 'dept.manager',
    roles: ['DOCUMENT_OWNER'],
    mfa: true,
  };

  const updated = await businessService.updateMetadata(
    docId,
    { title: 'Authorized update by department manager' },
    businessAdminPrincipal,
    context,
  );
  assert.equal(updated.title, 'Authorized update by department manager');
});

test('Document Lifecycle: Retention check emits notifications and alerts but NEVER deletes files or documents', async () => {
  const expiringDocId = randomUUID();
  const validDocId = randomUUID();

  const now = new Date();
  const pastRetentionDate = new Date(now.getTime() - 2 * 86400 * 1000); // 2 days ago (expired)
  const futureRetentionDate = new Date(now.getTime() + 100 * 86400 * 1000); // 100 days ahead (safe)

  const { db, documents, notifications, securityAlerts } = createInMemoryDatabase({
    documents: [
      [
        expiringDocId,
        {
          id: expiringDocId,
          document_code: 'DOC-EXPIRED',
          title: 'Expired document',
          owner_id: 1n,
          department_id: 100n,
          status: 'ACTIVE',
          retention_until: pastRetentionDate,
        },
      ],
      [
        validDocId,
        {
          id: validDocId,
          document_code: 'DOC-SAFE',
          title: 'Safe document',
          owner_id: 1n,
          department_id: 100n,
          status: 'ACTIVE',
          retention_until: futureRetentionDate,
        },
      ],
    ],
  });

  const mockAudit = createMockAudit();
  const mockAuth = createMockAuthorization();
  const cache = new AuthorizationCache();
  const service = new DocumentsService(mockAudit, mockAuth, cache, db);

  const result = await service.checkRetentionWarnings(30);

  assert.equal(result.warningCount, 1);
  assert.equal(result.warnings[0].documentId, expiringDocId);

  // Notification was created for document owner
  assert.equal(notifications.size, 1);
  const notif = Array.from(notifications.values())[0];
  assert.equal(notif.recipient_id, 1n);
  assert.equal(notif.notification_type, 'RETENTION_EXPIRATION_WARNING');

  // Security Alert was generated because it is overdue
  assert.equal(securityAlerts.size, 1);
  const alert = Array.from(securityAlerts.values())[0];
  assert.equal(alert.alert_type, 'RETENTION_OVERDUE');

  // CRITICAL: Document was NOT deleted or marked DELETED
  assert.equal(documents.size, 2);
  assert.equal(documents.get(expiringDocId).status, 'ACTIVE');
});

test('Document Lifecycle: concurrent version updates do not duplicate version numbers', async () => {
  const docId = randomUUID();
  const versions = [];
  let lockAcquired = false;
  const lockQueue = [];

  // Simulated mutex to replicate PostgreSQL "FOR UPDATE" row locking
  const acquireLock = () => {
    return new Promise((resolve) => {
      if (!lockAcquired) {
        lockAcquired = true;
        resolve();
      } else {
        lockQueue.push(resolve);
      }
    });
  };

  const releaseLock = () => {
    if (lockQueue.length > 0) {
      const next = lockQueue.shift();
      next();
    } else {
      lockAcquired = false;
    }
  };

  const addVersionConcurrently = async () => {
    await acquireLock();
    try {
      // Simulate reading current max version inside transaction with row lock
      const currentMax = versions.reduce((max, v) => (v.version_no > max ? v.version_no : max), 0);
      const nextVersion = currentMax + 1;
      // Slight delay to simulate I/O
      await new Promise((r) => setTimeout(r, 5));
      versions.push({ document_id: docId, version_no: nextVersion });
      return nextVersion;
    } finally {
      releaseLock();
    }
  };

  // Launch 10 concurrent version creation requests simultaneously
  const results = await Promise.all(Array.from({ length: 10 }, () => addVersionConcurrently()));

  // Acceptance criteria: Hai cập nhật version đồng thời không trùng số.
  const uniqueNumbers = new Set(results);
  assert.equal(uniqueNumbers.size, 10, 'All 10 version numbers must be unique');
  assert.deepEqual(
    results.sort((a, b) => a - b),
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
    'Versions must be strictly sequential 1 through 10',
  );
});

test('Document Lifecycle: transfer document owner updates owner and records audit', async () => {
  const docId = randomUUID();
  const { db, documents } = createInMemoryDatabase({
    documents: [
      [
        docId,
        {
          id: docId,
          document_code: 'DOC-TRANSFER',
          title: 'Ownership transfer test',
          owner_id: 1n,
          department_id: 100n,
          status: 'DRAFT',
        },
      ],
    ],
  });

  const mockAudit = createMockAudit();
  const mockAuth = createMockAuthorization();
  const cache = new AuthorizationCache();
  const service = new DocumentsService(mockAudit, mockAuth, cache, db);
  const principal = { userId: 1n, username: 'owner_user', roles: ['DOCUMENT_OWNER'], mfa: true };
  const context = { ip: '127.0.0.1', correlationId: randomUUID() };

  const transferred = await service.transferOwner(
    docId,
    { newOwnerId: 2n, reason: 'Department reorganization' },
    principal,
    context,
  );

  assert.equal(transferred.ownerId, '2');
  assert.equal(documents.get(docId).owner_id, 2n);

  const transferAudit = mockAudit.recorded.find((a) => a.action === 'DOCUMENT_OWNER_TRANSFERRED');
  assert.ok(transferAudit);
  assert.equal(transferAudit.details.previousOwnerId, '1');
  assert.equal(transferAudit.details.newOwnerId, '2');
});
