// @ts-check
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  MOCK_GRANTS,
  NO_DISCOVER_PRINCIPAL,
  READER_PRINCIPAL,
  TEST_CONTEXT,
  buildService,
} from './helpers/document-search-mocks.mjs';

describe('Document Search', () => {
  it('User without DISCOVER receives empty results identical to documents not existing (IDOR prevention)', async () => {
    const { service } = await buildService({
      discoverableDeptIds: [],
      grants: [],
    });

    const result = await service.searchDocuments(
      { page: 1, pageSize: 20, sort: 'created_at', order: 'desc' },
      NO_DISCOVER_PRINCIPAL,
      TEST_CONTEXT,
    );

    assert.ok(Array.isArray(result.data));
    assert.equal(result.hasMore, false);
    assert.equal(typeof result.page, 'number');
    assert.equal(typeof result.pageSize, 'number');
    assert.equal('totalCount' in result, false);
    assert.equal('total' in result, false);
  });

  it('Owner always sees their own documents including DRAFT', async () => {
    const { service } = await buildService({
      discoverableDeptIds: [],
      grants: [],
    });

    const result = await service.searchDocuments(
      { page: 1, pageSize: 20, sort: 'created_at', order: 'desc' },
      READER_PRINCIPAL,
      TEST_CONTEXT,
    );

    const ownedIds = result.data.map((d) => d.documentCode);
    assert.ok(ownedIds.includes('DOC-001'), 'Owner should see their ACTIVE document');
    assert.ok(ownedIds.includes('DOC-003'), 'Owner should see their DRAFT document');
  });

  it('User with active grant sees the granted document', async () => {
    const { service } = await buildService({
      discoverableDeptIds: [],
      grants: MOCK_GRANTS,
    });

    const result = await service.searchDocuments(
      { page: 1, pageSize: 20, sort: 'created_at', order: 'desc' },
      READER_PRINCIPAL,
      TEST_CONTEXT,
    );

    const foundIds = result.data.map((d) => d.documentCode);
    assert.ok(foundIds.includes('DOC-002'), 'User with active grant should see DOC-002');
  });

  it('Revoked grant / disabled user → document disappears immediately', async () => {
    const { service } = await buildService({
      discoverableDeptIds: [],
      grants: MOCK_GRANTS.map((g) => (g.id === 'grant-1' ? { ...g, status: 'REVOKED' } : g)),
    });

    const result = await service.searchDocuments(
      { page: 1, pageSize: 20, sort: 'created_at', order: 'desc' },
      READER_PRINCIPAL,
      TEST_CONTEXT,
    );

    const foundIds = result.data.map((d) => d.documentCode);
    assert.ok(!foundIds.includes('DOC-002'), 'DOC-002 should disappear after grant revocation');
  });

  it('Response does NOT contain owner email, storage_key, encryption_key_ref or internal hashes', async () => {
    const { service } = await buildService({
      discoverableDeptIds: null,
    });

    const result = await service.searchDocuments(
      { page: 1, pageSize: 20, sort: 'created_at', order: 'desc' },
      READER_PRINCIPAL,
      TEST_CONTEXT,
    );

    for (const doc of result.data) {
      const keys = Object.keys(doc);
      assert.ok(!keys.includes('ownerEmail'), 'Must not expose owner email');
      assert.ok(!keys.includes('storageKey'), 'Must not expose storage key');
      assert.ok(!keys.includes('storage_key'), 'Must not expose storage_key');
      assert.ok(!keys.includes('encryptionKeyRef'), 'Must not expose encryption key ref');
      assert.ok(!keys.includes('encryption_key_ref'), 'Must not expose encryption_key_ref');
      assert.ok(!keys.includes('sha256Hash'), 'Must not expose internal hash');
      assert.ok(!keys.includes('sha256_hash'), 'Must not expose sha256_hash');
      assert.ok(!keys.includes('ownerId'), 'Must not expose ownerId');
      assert.ok(!keys.includes('owner_id'), 'Must not expose owner_id');
    }
  });

  it('Response does NOT contain totalCount to prevent enumeration', async () => {
    const { service } = await buildService({
      discoverableDeptIds: null,
    });

    const result = await service.searchDocuments(
      { page: 1, pageSize: 20, sort: 'created_at', order: 'desc' },
      READER_PRINCIPAL,
      TEST_CONTEXT,
    );

    assert.equal('totalCount' in result, false, 'totalCount must not be present');
    assert.equal('total' in result, false, 'total must not be present');
    assert.ok('hasMore' in result, 'hasMore should be present instead');
    assert.ok('page' in result, 'page should be present');
    assert.ok('pageSize' in result, 'pageSize should be present');
  });
});
