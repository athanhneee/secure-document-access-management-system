import assert from 'node:assert/strict';
import * as net from 'node:net';
import { test } from 'node:test';
import { brotliCompressSync, deflateRawSync, gzipSync, zstdCompressSync } from 'node:zlib';
import { DlpEngine } from '../dist/icap/dlp-engine.js';
import { InspectionSemaphore } from '../dist/icap/icap-request-handler.js';
import { IcapServer } from '../dist/icap/icap-server.js';
import { getWorkerMetricsSnapshot, resetWorkerMetricsForTesting } from '../dist/worker-metrics.js';

/**
 * Helper tạo kho lưu trữ ZIP tối giản hợp lệ (kèm Central Directory + EOCD) phục vụ kiểm thử `.docx`/`.xlsx` và cờ mã hóa.
 */
function buildMinimalZipBuffer(entryName, rawContent, { deflate = false, encrypted = false } = {}) {
  const nameBuf = Buffer.from(entryName, 'utf8');
  const uncompressed = Buffer.from(rawContent, 'utf8');
  const compressed = deflate ? deflateRawSync(uncompressed) : uncompressed;
  const method = deflate ? 8 : 0;
  const flags = encrypted ? 0x0001 : 0x0000;

  const localHeader = Buffer.alloc(30 + nameBuf.length);
  localHeader.writeUInt32LE(0x04034b50, 0);
  localHeader.writeUInt16LE(20, 4);
  localHeader.writeUInt16LE(flags, 6);
  localHeader.writeUInt16LE(method, 8);
  localHeader.writeUInt32LE(compressed.length, 18);
  localHeader.writeUInt32LE(uncompressed.length, 22);
  localHeader.writeUInt16LE(nameBuf.length, 26);
  nameBuf.copy(localHeader, 30);

  const cdOffset = localHeader.length + compressed.length;
  const centralDir = Buffer.alloc(46 + nameBuf.length);
  centralDir.writeUInt32LE(0x02014b50, 0);
  centralDir.writeUInt16LE(20, 4);
  centralDir.writeUInt16LE(20, 6);
  centralDir.writeUInt16LE(flags, 8);
  centralDir.writeUInt16LE(method, 10);
  centralDir.writeUInt32LE(compressed.length, 20);
  centralDir.writeUInt32LE(uncompressed.length, 24);
  centralDir.writeUInt16LE(nameBuf.length, 28);
  centralDir.writeUInt32LE(0, 42);
  nameBuf.copy(centralDir, 46);

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(centralDir.length, 12);
  eocd.writeUInt32LE(cdOffset, 16);

  return Buffer.concat([localHeader, compressed, centralDir, eocd]);
}

test('DlpEngine.scanPayloadAsync — inspects zstd/br/gzip, fails closed on unknown/corrupt/bomb encodings, and scans URI/Headers/URL/Base64/UTF-16LE/.docx/.xlsx', async () => {
  const zstdLeak = zstdCompressSync(
    Buffer.from('Exfiltrating token WM-0123456789abcdef01234567!', 'utf8'),
  );
  const zstdRes = await DlpEngine.scanPayloadAsync(zstdLeak, { contentEncoding: 'zstd' });
  assert.equal(zstdRes.action, 'BLOCK');
  assert.ok(zstdRes.violations.some((v) => v.type === 'FORENSIC_WATERMARK_LEAK'));

  const brLeak = brotliCompressSync(Buffer.from('Báo cáo STRICTLY CONFIDENTIAL nội bộ.', 'utf8'));
  const brRes = await DlpEngine.scanPayloadAsync(brLeak, { contentEncoding: 'br' });
  assert.equal(brRes.action, 'BLOCK');

  // Fail-closed on unknown or corrupt Content-Encoding and decompression bombs
  const unknownEnc = await DlpEngine.scanPayloadAsync(Buffer.from('benign', 'utf8'), {
    contentEncoding: 'x-unknown-lz4',
  });
  assert.equal(unknownEnc.action, 'BLOCK');
  assert.ok(
    unknownEnc.violations.some((v) => v.rule === 'RULE_UNSUPPORTED_OR_CORRUPT_CONTENT_ENCODING'),
  );

  const corruptGzip = await DlpEngine.scanPayloadAsync(
    Buffer.from('not-valid-gzip-bytes', 'utf8'),
    {
      contentEncoding: 'gzip',
    },
  );
  assert.equal(corruptGzip.action, 'BLOCK');

  const bombPayload = gzipSync(Buffer.alloc(8192, 'A'));
  const bombRes = await DlpEngine.scanPayloadAsync(bombPayload, {
    contentEncoding: 'gzip',
    maxBodyBytes: 1024,
  });
  assert.equal(bombRes.action, 'BLOCK');
  assert.ok(bombRes.violations.some((v) => v.rule === 'RULE_COMPRESSED_BOMB_EGRESS_PREVENTION'));

  // URI / query string & HTTP headers & URL-encoded & Base64 (>=24 chars) & UTF-16LE
  const uriRes = await DlpEngine.scanPayloadAsync(Buffer.alloc(0), {
    httpUri: 'https://paste.example/upload?trace=WM-abcdef0123456789',
  });
  assert.equal(uriRes.action, 'BLOCK');

  const hdrRes = await DlpEngine.scanPayloadAsync(Buffer.alloc(0), {
    httpHeaders: { 'x-exfil-marker': 'WM-feedfacecafebeef1234' },
  });
  assert.equal(hdrRes.action, 'BLOCK');

  const urlEncoded = Buffer.from('note=%57%4D-1122334455667788', 'utf8');
  assert.equal((await DlpEngine.scanPayloadAsync(urlEncoded)).action, 'BLOCK');

  const b64Blob = Buffer.from(
    'Leak token WM-aabbccddeeff001122334455 inside base64!',
    'utf8',
  ).toString('base64');
  assert.equal(
    (await DlpEngine.scanPayloadAsync(Buffer.from(`data=${b64Blob}`, 'utf8'))).action,
    'BLOCK',
  );

  const utf16LeBuf = Buffer.from('Hồ sơ TÀI LIỆU MẬT lưu hành hạn chế', 'utf16le');
  assert.equal((await DlpEngine.scanPayloadAsync(utf16LeBuf)).action, 'BLOCK');

  // .docx (split <w:t> runs) & .xlsx (xl/sharedStrings.xml DEFLATE) & encrypted ZIP fail-closed
  const docxBuf = buildMinimalZipBuffer(
    'word/document.xml',
    '<w:document><w:body><w:p><w:r><w:t>WM-deadbeef</w:t></w:r><w:r><w:t>cafebabe9988</w:t></w:r></w:p></w:body></w:document>',
    { deflate: true },
  );
  const docxRes = await DlpEngine.scanPayloadAsync(docxBuf);
  assert.equal(docxRes.action, 'BLOCK');
  assert.ok(docxRes.violations.some((v) => v.type === 'FORENSIC_WATERMARK_LEAK'));

  const xlsxBuf = buildMinimalZipBuffer(
    'xl/sharedStrings.xml',
    '<sst><si><t>Danh sách BÍ MẬT NỘI BỘ 2026</t></si></sst>',
    { deflate: true },
  );
  assert.equal((await DlpEngine.scanPayloadAsync(xlsxBuf)).action, 'BLOCK');

  const encryptedZip = buildMinimalZipBuffer('word/document.xml', 'encrypted', { encrypted: true });
  assert.equal((await DlpEngine.scanPayloadAsync(encryptedZip)).action, 'BLOCK');
});

test('InspectionSemaphore & IcapServer — enforces concurrency cap and preserves pipelined requests on keep-alive socket', async () => {
  const sem = new InspectionSemaphore(3);
  let peakActive = 0;
  await Promise.all(
    Array.from({ length: 12 }, async () => {
      const release = await sem.acquire();
      peakActive = Math.max(peakActive, sem.getActiveCount());
      await new Promise((r) => setTimeout(r, 8));
      release();
    }),
  );
  assert.equal(peakActive, 3, 'Semaphore must cap concurrent inspections at 3');

  resetWorkerMetricsForTesting();
  const server = new IcapServer({
    enabled: true,
    host: '127.0.0.1',
    port: 0,
    action: 'BLOCK',
    maxConcurrentInspections: 4,
  });
  const { port } = await server.start();

  try {
    const httpHdr = 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n';
    const b1 = 'Clean first pipelined message.';
    const req1 =
      `RESPMOD icap://127.0.0.1/sda-dlp ICAP/1.0\r\n` +
      `Host: 127.0.0.1\r\nConnection: keep-alive\r\n` +
      `Encapsulated: res-hdr=0, res-body=${Buffer.byteLength(httpHdr)}\r\n\r\n` +
      httpHdr +
      `${Buffer.byteLength(b1).toString(16)}\r\n${b1}\r\n0\r\n\r\n`;

    const b2 = 'Second pipelined message leaking WM-abcdef0123456789!';
    const req2 =
      `RESPMOD icap://127.0.0.1/sda-dlp ICAP/1.0\r\n` +
      `Host: 127.0.0.1\r\nConnection: close\r\n` +
      `Encapsulated: res-hdr=0, res-body=${Buffer.byteLength(httpHdr)}\r\n\r\n` +
      httpHdr +
      `${Buffer.byteLength(b2).toString(16)}\r\n${b2}\r\n0\r\n\r\n`;

    const combinedResponse = await new Promise((resolve, reject) => {
      const socket = net.createConnection({ host: '127.0.0.1', port }, () => {
        // Send BOTH ICAP requests back-to-back in a single write to test 0\r\n\r\n pipelining boundary
        socket.write(Buffer.from(req1 + req2, 'utf8'));
      });
      let chunks = '';
      socket.on('data', (c) => {
        chunks += c.toString('utf8');
      });
      socket.on('end', () => resolve(chunks));
      socket.on('error', reject);
    });

    assert.ok(combinedResponse.includes('ICAP/1.0 204 No modifications'));
    assert.ok(combinedResponse.includes('HTTP/1.1 403 Forbidden'));
    assert.equal(server.getMetrics().totalRequests, 2);
    assert.equal(server.getMetrics().cleanPassThrough, 1);
    assert.equal(server.getMetrics().blockedViolations, 1);
    assert.equal(getWorkerMetricsSnapshot().icapBlockedTotal, 1);
  } finally {
    await server.stop();
  }
});
