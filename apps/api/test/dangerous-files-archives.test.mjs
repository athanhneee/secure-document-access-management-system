import 'reflect-metadata';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ZipBombGuardService } from '../dist/modules/documents/zip-bomb-guard.service.js';
import { createZipBuffer } from './helpers/zip-builder.mjs';

function createMockConfig(overrides = {}) {
  const values = {
    ZIP_MAX_ENTRIES: 100,
    ZIP_MAX_TOTAL_UNCOMPRESSED_SIZE: 50 * 1024 * 1024,
    ZIP_MAX_DEPTH: 5,
    ZIP_MAX_COMPRESSION_RATIO: 100,
    ...overrides,
  };
  return {
    get: (key) => values[key],
  };
}

test('Dangerous Files: Zip Bomb Guard — rejects zip archives with path traversal entries', async () => {
  const guard = new ZipBombGuardService(createMockConfig());
  const maliciousZip = createZipBuffer([
    { name: '[Content_Types].xml', content: '<Types/>' },
    { name: 'word/document.xml', content: '<doc/>' },
    { name: '../../etc/passwd', content: 'root:x:0:0:root:/root:/bin/bash' },
  ]);

  await assert.rejects(
    async () => guard.inspectOfficeZip(maliciousZip, '.docx'),
    /dangerous path traversal|invalid relative path/u,
  );
});

test('Dangerous Files: Zip Bomb Guard — rejects zip archives exceeding nesting depth', async () => {
  const guard = new ZipBombGuardService(createMockConfig({ ZIP_MAX_DEPTH: 2 }));
  const deepZip = createZipBuffer([
    { name: '[Content_Types].xml', content: '<Types/>' },
    { name: 'word/a/b/c/d/e/deep.xml', content: '<deep/>' },
  ]);

  await assert.rejects(
    async () => guard.inspectOfficeZip(deepZip, '.docx'),
    /exceeds directory nesting depth limit/u,
  );
});

test('Dangerous Files: Zip Bomb Guard — rejects zip archives exceeding maximum entry count', async () => {
  const guard = new ZipBombGuardService(createMockConfig({ ZIP_MAX_ENTRIES: 5 }));
  const manyEntries = [
    { name: '[Content_Types].xml', content: '<Types/>' },
    { name: 'word/document.xml', content: '<doc/>' },
    { name: 'word/part1.xml', content: '1' },
    { name: 'word/part2.xml', content: '2' },
    { name: 'word/part3.xml', content: '3' },
    { name: 'word/part4.xml', content: '4' },
  ];
  const zip = createZipBuffer(manyEntries);

  await assert.rejects(
    async () => guard.inspectOfficeZip(zip, '.docx'),
    /contains too many entries/u,
  );
});

test('Dangerous Files: Office OpenXML — rejects packages missing [Content_Types].xml', async () => {
  const guard = new ZipBombGuardService(createMockConfig());
  const missingContentTypes = createZipBuffer([{ name: 'word/document.xml', content: '<doc/>' }]);

  await assert.rejects(
    async () => guard.inspectOfficeZip(missingContentTypes, '.docx'),
    /missing \[Content_Types\]\.xml/u,
  );
});

test('Dangerous Files: Office OpenXML — rejects packages missing required application directory', async () => {
  const guard = new ZipBombGuardService(createMockConfig());
  const missingWordDir = createZipBuffer([
    { name: '[Content_Types].xml', content: '<Types/>' },
    { name: 'random/file.xml', content: '<random/>' },
  ]);

  await assert.rejects(
    async () => guard.inspectOfficeZip(missingWordDir, '.docx'),
    /missing word\/ package structure/u,
  );
});
