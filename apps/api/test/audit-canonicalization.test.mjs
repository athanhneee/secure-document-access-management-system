import 'reflect-metadata';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { test } from 'node:test';
import { canonicalizeJson } from '../dist/modules/audit/audit-canonicalizer.js';

test('Audit Canonicalization — lexicographically sorts object keys per RFC 8785 (JCS)', () => {
  const input = {
    zebra: 'last',
    alpha: 'first',
    middle: 'mid',
    beta: 2,
  };
  const canonical = canonicalizeJson(input);
  assert.equal(canonical, '{"alpha":"first","beta":2,"middle":"mid","zebra":"last"}');
});

test('Audit Canonicalization — recursively canonicalizes nested objects and arrays', () => {
  const input = {
    details: {
      userRole: 'ADMIN',
      documentId: 'doc-123',
      actions: ['VIEW', 'DOWNLOAD'],
      metadata: {
        z: 99,
        a: 11,
      },
    },
    action: 'AUDIT_QUERY',
    sequence: 42n,
  };

  const canonical = canonicalizeJson(input);
  assert.equal(
    canonical,
    '{"action":"AUDIT_QUERY","details":{"actions":["VIEW","DOWNLOAD"],"documentId":"doc-123","metadata":{"a":11,"z":99},"userRole":"ADMIN"},"sequence":"42"}',
  );
});

test('Audit Canonicalization — omits undefined, symbol, and function values in objects', () => {
  const input = {
    keep: 'value',
    omitUndefined: undefined,
    omitFunction: () => 'ignored',
    omitSymbol: Symbol('skip'),
    nested: {
      valid: 123,
      skipMe: undefined,
    },
  };

  const canonical = canonicalizeJson(input);
  assert.equal(canonical, '{"keep":"value","nested":{"valid":123}}');
});

test('Audit Canonicalization — serializes undefined, symbol, and function in arrays as null', () => {
  const input = ['hello', undefined, 42, () => {}, null];
  const canonical = canonicalizeJson(input);
  assert.equal(canonical, '["hello",null,42,null,null]');
});

test('Audit Canonicalization — formats BigInt, Date, and edge-case numbers deterministically', () => {
  const fixedDate = new Date('2026-09-23T12:00:00.000Z');
  const input = {
    bigNumber: 9007199254740993n,
    timestamp: fixedDate,
    zero: 0,
    negativeFloat: -12.34,
    nanValue: NaN,
    infinityValue: Infinity,
  };

  const canonical = canonicalizeJson(input);
  assert.equal(
    canonical,
    '{"bigNumber":"9007199254740993","infinityValue":null,"nanValue":null,"negativeFloat":-12.34,"timestamp":"2026-09-23T12:00:00.000Z","zero":0}',
  );
});

test('Audit Canonicalization — preserves Vietnamese diacritics and Unicode characters accurately', () => {
  const input = {
    title: 'Hệ thống Quản lý Truy cập Tài liệu Mật',
    reason: 'Phê duyệt cấp quyền xem hồ sơ bảo mật quốc gia',
    department: 'Phòng Kế hoạch & Đầu tư',
  };

  const canonical = canonicalizeJson(input);
  assert.equal(
    canonical,
    '{"department":"Phòng Kế hoạch & Đầu tư","reason":"Phê duyệt cấp quyền xem hồ sơ bảo mật quốc gia","title":"Hệ thống Quản lý Truy cập Tài liệu Mật"}',
  );
});

test('Audit Canonicalization — supports custom toJSON methods on objects', () => {
  class CustomEntity {
    constructor(name, secret) {
      this.name = name;
      this.secret = secret;
    }
    toJSON() {
      return { publicName: this.name };
    }
  }

  const entity = {
    target: new CustomEntity('Document_A', 'secret_dont_log'),
    status: 'ACTIVE',
  };

  const canonical = canonicalizeJson(entity);
  assert.equal(canonical, '{"status":"ACTIVE","target":{"publicName":"Document_A"}}');
  assert.ok(!canonical.includes('secret_dont_log'));
});

test('Audit Canonicalization [NFR-AUDIT01] — produces identical HMAC regardless of input property order', () => {
  const hmacSecret = 'production-audit-chain-hmac-master-secret-key-32b';

  // Two objects constructed with completely different key insertion orders
  const payload1 = {
    sequence: 100n,
    action: 'DOCUMENT_ACCESSED',
    actorUserId: '42',
    documentId: 'doc-uuid-999',
    timestamp: '2026-09-23T14:00:00Z',
    details: {
      watermarkToken: 'WM-abc123',
      ip: '10.0.0.1',
      userAgent: 'Mozilla/5.0',
    },
  };

  const payload2 = {
    details: {
      userAgent: 'Mozilla/5.0',
      ip: '10.0.0.1',
      watermarkToken: 'WM-abc123',
    },
    timestamp: '2026-09-23T14:00:00Z',
    documentId: 'doc-uuid-999',
    actorUserId: '42',
    action: 'DOCUMENT_ACCESSED',
    sequence: 100n,
  };

  const canon1 = canonicalizeJson(payload1);
  const canon2 = canonicalizeJson(payload2);

  assert.equal(canon1, canon2, 'Canonical JSON strings must be strictly identical.');

  const hash1 = crypto.createHmac('sha256', hmacSecret).update(canon1).digest('hex');
  const hash2 = crypto.createHmac('sha256', hmacSecret).update(canon2).digest('hex');

  assert.equal(
    hash1,
    hash2,
    'HMAC digests must match 100%, proving tamper-evident chain stability.',
  );
});
