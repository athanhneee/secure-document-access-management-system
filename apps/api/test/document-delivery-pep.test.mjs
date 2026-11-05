import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { AppErrorCode } from '../../../packages/contracts/dist/error-codes.js';
import { DocumentPepService } from '../dist/modules/documents/document-pep.service.js';
import { createActivePepDocumentRow } from './helpers/document-delivery-mocks.mjs';

test('DocumentPEP — rejects access if document does not exist', async () => {
  const mockDb = {
    document: { findUnique: async () => null },
  };
  const pep = new DocumentPepService({}, {}, { record: async () => {} }, mockDb);
  const principal = { userId: 1n, username: 'test', mfa: true };
  const context = { ip: '127.0.0.1', userAgent: 'test-agent' };

  await assert.rejects(
    async () => {
      await pep.enforceAccess(randomUUID(), principal, context, { action: 'VIEW' });
    },
    (err) => err.getResponse?.()?.errorCode === AppErrorCode.DOCUMENT_NOT_FOUND,
  );
});

test('DocumentPEP — rejects DOWNLOAD if classification level has allow_download = false', async () => {
  const docId = randomUUID();
  const grantId = randomUUID();

  const mockDb = {
    document: {
      findUnique: async () =>
        createActivePepDocumentRow(docId, {
          rank: 3,
          allow_download: false,
          require_watermark: true,
        }),
    },
  };
  const mockGrants = { assertGrantValidForAccess: async () => {} };
  const mockAbac = { evaluate: async () => ({ decision: 'PERMIT', obligations: [] }) };
  const mockAudit = { record: async () => {} };

  const pep = new DocumentPepService(mockAbac, mockGrants, mockAudit, mockDb);
  const principal = { userId: 1n, username: 'test', mfa: true };
  const context = { ip: '127.0.0.1', userAgent: 'test-agent' };

  await assert.rejects(
    async () => {
      await pep.enforceAccess(docId, principal, context, { action: 'DOWNLOAD', grantId });
    },
    (err) => err.getResponse?.()?.errorCode === AppErrorCode.GRANT_DOWNLOAD_FORBIDDEN,
  );
});

test('DocumentPEP — rejects DOWNLOAD if ABAC policy returns FORBID_DOWNLOAD obligation', async () => {
  const docId = randomUUID();
  const grantId = randomUUID();

  const mockDb = {
    document: {
      findUnique: async () =>
        createActivePepDocumentRow(docId, {
          rank: 2,
          allow_download: true,
          require_watermark: true,
        }),
    },
    user: { findUnique: async () => ({ department_id: 1n, status: 'ACTIVE' }) },
    userAttributeAssignment: {
      findFirst: async () => ({ attribute_options: { numeric_rank: 5 } }),
    },
    userDepartmentHistory: { findFirst: async () => ({ department_id: 1n }) },
    userProjectMembership: { findMany: async () => [] },
  };
  const mockGrants = { assertGrantValidForAccess: async () => {} };
  const mockAbac = {
    evaluate: async () => ({
      decision: 'PERMIT',
      obligations: [{ type: 'FORBID_DOWNLOAD' }],
    }),
  };
  const mockAudit = { record: async () => {} };

  const pep = new DocumentPepService(mockAbac, mockGrants, mockAudit, mockDb);
  const principal = { userId: 1n, username: 'test', mfa: true };
  const context = { ip: '127.0.0.1', userAgent: 'test-agent' };

  await assert.rejects(
    async () => {
      await pep.enforceAccess(docId, principal, context, { action: 'DOWNLOAD', grantId });
    },
    (err) => err.getResponse?.()?.errorCode === AppErrorCode.GRANT_DOWNLOAD_FORBIDDEN,
  );
});

test('DocumentPEP — on PERMIT, creates ACTIVE access_session tied to user, grant, and version', async () => {
  const docId = randomUUID();
  const grantId = randomUUID();
  let createdSession = null;

  const mockDb = {
    document: {
      findUnique: async () =>
        createActivePepDocumentRow(
          docId,
          { rank: 1, allow_download: true, require_watermark: true },
          { document_code: 'DOC-ACTIVE-01', title: 'Active Document' },
        ),
    },
    accessSession: {
      create: async ({ data }) => {
        createdSession = data;
        return data;
      },
    },
    user: { findUnique: async () => ({ department_id: 1n, status: 'ACTIVE' }) },
    userAttributeAssignment: {
      findFirst: async () => ({ attribute_options: { numeric_rank: 5 } }),
    },
    userDepartmentHistory: { findFirst: async () => ({ department_id: 1n }) },
    userProjectMembership: { findMany: async () => [] },
  };
  const mockGrants = { assertGrantValidForAccess: async () => {} };
  const mockAbac = {
    evaluate: async () => ({
      decision: 'PERMIT',
      obligations: [{ type: 'REQUIRE_WATERMARK' }],
    }),
  };
  const mockAudit = { record: async () => {} };

  const pep = new DocumentPepService(mockAbac, mockGrants, mockAudit, mockDb);
  const principal = { userId: 77n, username: 'authorized_user', mfa: true };
  const context = { ip: '192.168.1.100', userAgent: 'SafeClient' };

  const result = await pep.enforceAccess(docId, principal, context, {
    action: 'VIEW',
    grantId,
    deviceFingerprint: 'dev-fp-77',
  });

  assert.ok(result.sessionId);
  assert.equal(result.watermarkRequired, true);
  assert.equal(createdSession.access_grant_id, grantId);
  assert.equal(createdSession.user_id, 77n);
  assert.equal(createdSession.document_version_id, 100n);
  assert.equal(createdSession.status, 'ACTIVE');
  assert.equal(createdSession.device_fingerprint, 'dev-fp-77');
});

test('DocumentPEP — automatically allows Document Owner to preview with sufficient clearance', async () => {
  const docId = randomUUID();
  const mockDb = {
    user: {
      findUnique: async () => ({
        id: 10n,
        department_id: 1n,
        status: 'ACTIVE',
      }),
    },
    document: {
      findUnique: async () =>
        createActivePepDocumentRow(docId, {
          rank: 2,
          allow_download: true,
          require_watermark: true,
        }),
    },
    userAttributeAssignment: {
      findFirst: async () => ({
        attribute_options: { numeric_rank: 3 },
      }),
    },
    accessGrant: {
      findFirst: async () => null,
      create: async ({ data }) => ({ id: 'auto-owner-grant-id', ...data }),
    },
    userRole: {
      findMany: async () => [],
    },
    accessSession: {
      create: async () => ({ id: 'new-session-id' }),
    },
  };
  const mockGrants = { assertGrantValidForAccess: async () => {} };
  const mockAbac = { evaluate: async () => ({ decision: 'PERMIT', obligations: [] }) };
  const mockAudit = { record: async () => {} };

  const pep = new DocumentPepService(mockAbac, mockGrants, mockAudit, mockDb);
  const principal = { userId: 10n, username: 'owner_user', mfa: true };
  const context = { ip: '127.0.0.1', userAgent: 'test-agent' };

  const result = await pep.enforceAccess(docId, principal, context, { action: 'VIEW' });
  assert.ok(result.sessionId);
  assert.equal(result.documentId, docId);
  assert.equal(result.versionNo, 1);
});
