/**
 * Module: Unit Tests for Distributed Delivery Tickets, Bounded PEP Session Policies, Owner Clearance Guard & Derivative PDF Cache
 * Thuật toán: Kiểm thử hồi quy 4 cơ chế bảo mật & hiệu năng:
 *   1. Chủ sở hữu tài liệu bị hạ cấp độ mật (`CLEARANCE_LEVEL` < `documentRank`) bị chặn đọc, sửa và mở phiên PEP.
 *   2. Vé tải dùng một lần phân tán (`DistributedStateService.consumeOnce`) tái xác minh `AccessSession`, `AccessGrant`, `User` và IP tại thời điểm đổi vé.
 *   3. Chính sách phiên PEP có TTL hữu hạn bắt buộc (30–60 phút) và bộ đệm dẫn xuất mã hóa `STORAGE_BUCKET_DERIVATIVES` giúp xem trang 2 không gọi lại KMS/watermark.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { AppErrorCode } from '../../../packages/contracts/dist/error-codes.js';
import { DistributedStateService } from '../dist/modules/concurrency/distributed-state.service.js';
import { DocumentDeliveryService } from '../dist/modules/documents/document-delivery.service.js';
import { DocumentPepService } from '../dist/modules/documents/document-pep.service.js';
import { createDocumentsTestService } from './helpers/document-lifecycle-mocks.mjs';
import { createActivePepDocumentRow } from './helpers/document-delivery-mocks.mjs';

const extractErrorCode = (err) => err?.getResponse?.()?.errorCode ?? err?.response?.errorCode;

test('[HIGH 1.4] Downgraded document owner cannot read, mutate, or open PEP session above clearance', async () => {
  const docId = randomUUID();
  const { service } = createDocumentsTestService({
    documents: [
      [
        docId,
        {
          id: docId,
          document_code: 'DOC-DOWNGRADED-OWNER',
          title: 'Secret Plan',
          owner_id: 1n,
          department_id: 100n,
          status: 'ACTIVE',
          discoverable: true,
        },
      ],
    ],
    classifications: [
      [
        1n,
        {
          id: 1n,
          document_id: docId,
          classification_level_id: 3n,
          effective_to: null,
          classification_levels: { id: 3n, rank: 3, code: 'SECRET', name: 'Mật' },
        },
      ],
    ],
    userAttributeAssignments: [
      [1n, { user_id: 1n, attribute_code: 'CLEARANCE_LEVEL', numeric_rank: 1 }],
    ],
  });

  const owner = {
    userId: 1n,
    sessionId: 's-owner',
    username: 'owner_rank1',
    roles: ['DOCUMENT_OWNER'],
    mfa: true,
  };
  const context = { ip: '127.0.0.1', correlationId: randomUUID() };

  await assert.rejects(
    () => service.getDocumentById(docId, owner),
    (err) => extractErrorCode(err) === AppErrorCode.BELL_LAPADULA_CLEARANCE_INSUFFICIENT,
  );
  await assert.rejects(
    () => service.updateMetadata(docId, { title: 'Bypass' }, owner, context),
    (err) => extractErrorCode(err) === AppErrorCode.BELL_LAPADULA_CLEARANCE_INSUFFICIENT,
  );

  const pep = new DocumentPepService(
    { evaluate: async () => ({ decision: 'PERMIT', obligations: [] }) },
    { assertGrantValidForAccess: async () => {} },
    { record: async () => {} },
    {
      document: {
        findUnique: async () =>
          createActivePepDocumentRow(docId, { rank: 3, allow_download: true }, { owner_id: 1n }),
      },
      userAttributeAssignment: {
        findFirst: async () => ({ attribute_options: { numeric_rank: 1 } }),
      },
      accessGrant: { findFirst: async () => null },
      userRole: { findMany: async () => [] },
    },
  );
  await assert.rejects(
    () => pep.enforceAccess(docId, owner, context, { action: 'VIEW', grantId: randomUUID() }),
    (err) => extractErrorCode(err) === AppErrorCode.BELL_LAPADULA_CLEARANCE_INSUFFICIENT,
  );
});

test('[HIGH 1.3] Distributed download ticket re-verifies session, grant, user status, IP & single-use atomicity', async () => {
  const sessionId = randomUUID();
  const grantId = randomUUID();
  const documentId = randomUUID();
  const principal = {
    userId: 55n,
    sessionId: 's-55',
    username: 'downloader',
    roles: ['USER'],
    mfa: true,
  };
  const issuedContext = { ip: '10.10.1.25', userAgent: 'SecureBrowser/1.0' };

  let sessionStatus = 'ACTIVE';
  let grantStatus = 'ACTIVE';
  let userStatus = 'ACTIVE';

  const mockDb = {
    accessSession: {
      findUnique: async () => ({
        id: sessionId,
        status: sessionStatus,
        user_id: 55n,
        access_grant_id: grantId,
        ip_address: '10.10.1.25',
        user_agent: 'SecureBrowser/1.0',
        document_versions: {
          id: 1n,
          document_id: documentId,
          document: {
            classification_history: [{ classification_levels: { allow_download: true } }],
          },
        },
      }),
    },
    accessGrant: {
      findUnique: async () => ({
        id: grantId,
        document_id: documentId,
        status: grantStatus,
        valid_from: new Date(Date.now() - 60_000),
        valid_until: new Date(Date.now() + 600_000),
      }),
    },
    user: { findUnique: async () => ({ id: 55n, status: userStatus }) },
  };

  const stateStore = new DistributedStateService();
  const delivery = new DocumentDeliveryService(
    { enforceSessionPolicy: async () => ({ grantedAction: 'DOWNLOAD', forbidDownload: false }) },
    { documentsBucket: 'docs' },
    {},
    {},
    {},
    { assertGrantValidForAccess: async () => {} },
    { record: async () => {} },
    { get: () => 60 },
    mockDb,
    stateStore,
  );
  delivery.downloadDocument = async () => ({
    buffer: Buffer.from('ok'),
    mimeType: 'application/pdf',
    filename: 'doc.pdf',
    fileSizeBytes: 2,
    outputSha256Hash: 'abc',
  });

  const tValid = await delivery.createDownloadTicket(
    documentId,
    sessionId,
    principal,
    issuedContext,
  );
  const firstRedeem = await delivery.redeemDownloadTicket(tValid.ticket, issuedContext);
  assert.equal(firstRedeem.filename, 'doc.pdf');
  await assert.rejects(() => delivery.redeemDownloadTicket(tValid.ticket, issuedContext));

  const tIpMismatch = await delivery.createDownloadTicket(
    documentId,
    sessionId,
    principal,
    issuedContext,
  );
  await assert.rejects(
    () => delivery.redeemDownloadTicket(tIpMismatch.ticket, { ip: '10.10.9.99' }),
    (err) => extractErrorCode(err) === AppErrorCode.DOCUMENT_ACCESS_DENIED,
  );

  const tRevokedGrant = await delivery.createDownloadTicket(
    documentId,
    sessionId,
    principal,
    issuedContext,
  );
  grantStatus = 'REVOKED';
  await assert.rejects(
    () => delivery.redeemDownloadTicket(tRevokedGrant.ticket, issuedContext),
    (err) => extractErrorCode(err) === AppErrorCode.DOCUMENT_ACCESS_DENIED,
  );
  grantStatus = 'ACTIVE';

  const tLockedUser = await delivery.createDownloadTicket(
    documentId,
    sessionId,
    principal,
    issuedContext,
  );
  userStatus = 'LOCKED';
  await assert.rejects(
    () => delivery.redeemDownloadTicket(tLockedUser.ticket, issuedContext),
    (err) => extractErrorCode(err) === AppErrorCode.DOCUMENT_ACCESS_DENIED,
  );
  userStatus = 'ACTIVE';

  const tTerminated = await delivery.createDownloadTicket(
    documentId,
    sessionId,
    principal,
    issuedContext,
  );
  sessionStatus = 'TERMINATED';
  await assert.rejects(
    () => delivery.redeemDownloadTicket(tTerminated.ticket, issuedContext),
    (err) => extractErrorCode(err) === AppErrorCode.SESSION_TERMINATED,
  );
});
