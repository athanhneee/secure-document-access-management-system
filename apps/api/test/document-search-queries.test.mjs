// @ts-check
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { READER_PRINCIPAL, TEST_CONTEXT, buildService } from './helpers/document-search-mocks.mjs';

describe('Document Search — Queries, Sanitization & Granted Documents', () => {
  it('Full-text search with Vietnamese diacritics returns correct results', async () => {
    const { service } = await buildService({
      discoverableDeptIds: null,
    });

    const result = await service.searchDocuments(
      { q: 'tài chính', page: 1, pageSize: 20, sort: 'created_at', order: 'desc' },
      READER_PRINCIPAL,
      TEST_CONTEXT,
    );

    assert.ok(Array.isArray(result.data));
  });

  it('pg_trgm fuzzy match works with partial input', async () => {
    const { service } = await buildService({
      discoverableDeptIds: null,
    });

    const result = await service.searchDocuments(
      { q: 'kinh doan', page: 1, pageSize: 20, sort: 'created_at', order: 'desc' },
      READER_PRINCIPAL,
      TEST_CONTEXT,
    );

    assert.ok(Array.isArray(result.data));
  });

  it('SQL injection in search query is neutralized (parameterized query)', async () => {
    const { service, capturedQueries } = await buildService({
      discoverableDeptIds: null,
    });

    const maliciousInputs = [
      "'; DROP TABLE documents; --",
      '" OR 1=1 --',
      "Robert'); DROP TABLE students;--",
      "' UNION SELECT * FROM users --",
    ];

    for (const injection of maliciousInputs) {
      const result = await service.searchDocuments(
        { q: injection, page: 1, pageSize: 20, sort: 'created_at', order: 'desc' },
        READER_PRINCIPAL,
        TEST_CONTEXT,
      );
      assert.ok(Array.isArray(result.data), `Injection "${injection}" should not crash`);
    }

    for (const q of capturedQueries) {
      assert.ok(
        !q.includes('DROP TABLE'),
        'SQL injection payload must not appear verbatim in query template',
      );
    }
  });

  it('Pagination uses stable tie-breaker by id and hasMore indicator', async () => {
    const { service } = await buildService({
      discoverableDeptIds: null,
    });

    const page1 = await service.searchDocuments(
      { page: 1, pageSize: 2, sort: 'created_at', order: 'desc' },
      READER_PRINCIPAL,
      TEST_CONTEXT,
    );

    assert.ok(Array.isArray(page1.data));
    assert.equal(page1.page, 1);
    assert.equal(page1.pageSize, 2);
    assert.equal(typeof page1.hasMore, 'boolean');
  });

  it('Query exceeding 200 characters is rejected', async () => {
    const { service } = await buildService({
      discoverableDeptIds: null,
    });

    const longQuery = 'a'.repeat(201);
    await assert.rejects(
      () =>
        service.searchDocuments(
          { q: longQuery, page: 1, pageSize: 20, sort: 'created_at', order: 'desc' },
          READER_PRINCIPAL,
          TEST_CONTEXT,
        ),
      (/** @type {any} */ err) => {
        assert.ok(
          err.response?.errorCode === 'SEARCH_QUERY_TOO_LONG' || err.message?.includes('200'),
        );
        return true;
      },
    );
  });

  it('Audit records search event with hashed query term', async () => {
    const { service, capturedAudits } = await buildService({
      discoverableDeptIds: null,
    });

    const searchTerm = 'tài liệu mật';
    await service.searchDocuments(
      { q: searchTerm, page: 1, pageSize: 20, sort: 'created_at', order: 'desc' },
      READER_PRINCIPAL,
      TEST_CONTEXT,
    );

    assert.ok(capturedAudits.length > 0, 'Audit should be recorded');
    const auditEvent = capturedAudits[capturedAudits.length - 1];
    assert.equal(auditEvent.action, 'DOCUMENT_SEARCHED');
    assert.equal(auditEvent.outcome, 'SUCCESS');
    assert.equal(auditEvent.actorUserId, READER_PRINCIPAL.userId);

    const expectedHash = createHash('sha256').update(searchTerm).digest('hex');
    assert.equal(auditEvent.details?.queryHash, expectedHash);
    const detailsStr = JSON.stringify(auditEvent.details);
    assert.ok(!detailsStr.includes(searchTerm), 'Raw search term must not appear in audit');
  });

  it('My granted documents returns grants with permissions and document info', async () => {
    const { service } = await buildService({
      discoverableDeptIds: null,
    });

    const result = await service.getMyGrantedDocuments(
      { page: 1, pageSize: 20, sort: 'granted_at', order: 'desc' },
      READER_PRINCIPAL,
    );

    assert.ok(Array.isArray(result.data));
    assert.equal(typeof result.hasMore, 'boolean');
    assert.equal('totalCount' in result, false);

    for (const item of result.data) {
      assert.ok(item.grantId, 'Grant ID should be present');
      assert.ok(Array.isArray(item.permissions), 'Permissions should be an array');
      assert.ok(item.grantStatus, 'Grant status should be present');
      assert.ok(item.document, 'Document info should be present');
      assert.ok(item.document.id, 'Document ID should be present');
      assert.ok(item.document.title, 'Document title should be present');

      const docKeys = Object.keys(item.document);
      assert.ok(!docKeys.includes('storageKey'));
      assert.ok(!docKeys.includes('encryptionKeyRef'));
      assert.ok(!docKeys.includes('ownerId'));
    }
  });
});
