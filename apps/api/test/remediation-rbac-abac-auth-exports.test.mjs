import 'reflect-metadata';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { ForbiddenException } from '@nestjs/common';
import { DocumentsController } from '../dist/modules/documents/documents.controller.js';
import { assertDocumentMutationPermission } from '../dist/modules/documents/document-access-guard.helper.js';
import { REQUIRED_PERMISSION_METADATA } from '../dist/modules/rbac/require-permission.js';
import { executeGrantedDocumentsQuery } from '../dist/modules/documents/document-grants-search.helper.js';
import { toGrantDetail } from '../dist/modules/access-grants/access-grants.types.js';
import { executeAccessRequestDecision } from '../dist/modules/access-requests/access-request-decision.helper.js';
import { ExportJobService } from '../dist/modules/reports/export-job.service.js';

/**
 * Thuật toán: Giả lập `AuthorizationService` trả về toàn quyền để kiểm chứng hàng rào sở hữu nghiêm ngặt chống BOLA ngang hàng.
 */
function createPermissiveAuthz() {
  return {
    hasPermission: async () => true,
  };
}

test('[CRIT-04] Strict ownership guard blocks non-owners across ALL document mutations & controller enforces operation-specific RBAC', async () => {
  const authz = createPermissiveAuthz();
  const doc = { id: randomUUID(), owner_id: 10n, department_id: 1n };
  const nonOwner = {
    userId: 99n,
    sessionId: 's',
    username: 'peer.owner',
    roles: ['DOCUMENT_OWNER'],
    mfa: true,
  };
  const owner = {
    userId: 10n,
    sessionId: 's-owner',
    username: 'true.owner',
    roles: ['DOCUMENT_OWNER'],
    mfa: true,
  };

  for (const op of ['ARCHIVE', 'TRANSFER_OWNER', 'CLASSIFY', 'METADATA', 'VERSION', 'ACTIVATE']) {
    await assert.rejects(
      () => assertDocumentMutationPermission(authz, doc, nonOwner, op),
      ForbiddenException,
    );
    await assert.doesNotReject(() => assertDocumentMutationPermission(authz, doc, owner, op));
  }

  assert.deepEqual(
    Reflect.getMetadata(
      REQUIRED_PERMISSION_METADATA,
      DocumentsController.prototype.archiveDocument,
    ),
    { resource: 'DOCUMENT', action: 'ARCHIVE', global: false },
  );
  assert.deepEqual(
    Reflect.getMetadata(REQUIRED_PERMISSION_METADATA, DocumentsController.prototype.transferOwner),
    { resource: 'DOCUMENT', action: 'MANAGE', global: false },
  );
  assert.deepEqual(
    Reflect.getMetadata(
      REQUIRED_PERMISSION_METADATA,
      DocumentsController.prototype.reclassifyDocument,
    ),
    { resource: 'DOCUMENT', action: 'CLASSIFY', global: false },
  );
  assert.deepEqual(
    Reflect.getMetadata(
      REQUIRED_PERMISSION_METADATA,
      DocumentsController.prototype.setCurrentVersion,
    ),
    { resource: 'DOCUMENT_VERSION', action: 'CREATE', global: false },
  );
});

test('[CRIT-05, CRIT-06, HIGH-06, CRIT-08, HIGH-07] Enriched grant/document DTOs, DOWNLOAD->VIEW inclusion, EXPORT_STORAGE_DIR & scoped listExportJobs', async () => {
  const grantId = randomUUID();
  let queryIdx = 0;
  const myGrants = await executeGrantedDocumentsQuery({
    database: {
      userAttributeAssignment: {
        findFirst: async () => ({ attribute_options: { numeric_rank: 4, is_active: true } }),
      },
      $queryRaw: async () =>
        ++queryIdx === 1
          ? [
              {
                grant_id: grantId,
                grant_status: 'ACTIVE',
                valid_from: new Date('2026-01-01T00:00:00Z'),
                valid_until: new Date('2026-12-31T00:00:00Z'),
                granted_at: new Date('2026-01-01T00:00:00Z'),
                doc_id: randomUUID(),
                doc_code: 'DOC-SEC-01',
                doc_title: 'Hồ sơ Tối mật',
                doc_status: 'ACTIVE',
                cl_name: 'Tối mật',
                cl_code: 'SECRET',
                cl_allow_download: false,
              },
            ]
          : [{ access_grant_id: grantId, permission: 'VIEW' }],
    },
    authorization: { effectiveGrants: async () => [] },
    input: { page: 1, pageSize: 20, sort: 'granted_at', order: 'desc' },
    principal: { userId: 7n, sessionId: 's', username: 'u', roles: [], mfa: true },
  });
  assert.equal(myGrants.data[0].document.classificationLevelCode, 'SECRET');
  assert.equal(myGrants.data[0].document.allowDownload, false);

  const enrichedGrant = toGrantDetail({
    id: randomUUID(),
    document_id: randomUUID(),
    principal_type: 'USER',
    principal_user_id: 7n,
    principal_role_id: null,
    source: 'DIRECT',
    access_request_id: null,
    valid_from: new Date('2026-01-01T00:00:00Z'),
    valid_until: new Date('2026-02-01T00:00:00Z'),
    status: 'ACTIVE',
    granted_by: 1n,
    granted_at: new Date('2026-01-01T00:00:00Z'),
    revoked_by: null,
    revoked_at: null,
    revoke_reason: null,
    version: 0,
    access_grant_permissions: [{ permission: 'VIEW' }],
    documents: { title: 'Kế hoạch An ninh', document_code: 'DOC-AN-09' },
    users_access_grants_principal_user_idTousers: { full_name: 'Nguyễn Văn A', username: 'nva' },
    roles: null,
  });
  assert.deepEqual(enrichedGrant.document, {
    title: 'Kế hoạch An ninh',
    documentCode: 'DOC-AN-09',
  });
  assert.deepEqual(enrichedGrant.principalUser, { fullName: 'Nguyễn Văn A', username: 'nva' });

  let createdGrantPermissions = [];
  const reqId = randomUUID();
  const docId = randomUUID();
  await executeAccessRequestDecision({
    id: reqId,
    input: { decision: 'APPROVED', validDays: 3 },
    principal: {
      userId: 1n,
      sessionId: 's',
      username: 'owner',
      roles: ['DOCUMENT_OWNER'],
      mfa: true,
    },
    context: { ip: '127.0.0.1', correlationId: 'c-req' },
    database: {
      accessRequest: {
        findUnique: async () => ({
          id: reqId,
          requester_id: 7n,
          document_id: docId,
          status: 'PENDING',
          documents: { id: docId, owner_id: 1n },
          access_request_permissions: [{ permission: 'DOWNLOAD' }],
        }),
      },
    },
    audit: { record: async () => {} },
    grantsService: {
      createGrant: async (input) => {
        createdGrantPermissions = input.permissions;
        return { id: randomUUID() };
      },
    },
  });
  assert.deepEqual(createdGrantPermissions, ['VIEW', 'DOWNLOAD']);

  const tmpExportDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sda-export-test-'));
  const prevEnv = process.env['EXPORT_STORAGE_DIR'];
  process.env['EXPORT_STORAGE_DIR'] = tmpExportDir;
  try {
    let capturedWhere = null;
    const exportSvc = new ExportJobService({
      asyncExportJob: {
        findMany: async ({ where }) => {
          capturedWhere = where;
          return [];
        },
      },
    });
    const history = await exportSvc.listExportJobs({
      userId: 55n,
      sessionId: 's',
      username: 'u',
      roles: [],
    });
    assert.deepEqual(history, { data: [] });
    assert.deepEqual(capturedWhere, { requester_user_id: 55n });
  } finally {
    if (prevEnv === undefined) delete process.env['EXPORT_STORAGE_DIR'];
    else process.env['EXPORT_STORAGE_DIR'] = prevEnv;
    fs.rmSync(tmpExportDir, { recursive: true, force: true });
  }
});
