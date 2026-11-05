import assert from 'node:assert/strict';
import { test } from 'node:test';
import { DlpEngine } from '../dist/icap/dlp-engine.js';
import { IcapParser } from '../dist/icap/icap-parser.js';

// ── 1. DLP Engine Unit Tests ───────────────────────────────────────────────────

test('DlpEngine — detects Top Secret national security classification', () => {
  const secretPayload = Buffer.from(
    'Tài liệu lưu hành nội bộ: NỘI DUNG TỐI MẬT QUÂN SỰ KHÔNG ĐƯỢC PHÉP CHIA SẺ.',
    'utf-8',
  );

  const result = DlpEngine.scanPayload(secretPayload);
  assert.equal(result.isClean, false);
  assert.equal(result.action, 'BLOCK');
  assert.ok(result.violations.some((v) => v.type === 'TOP_SECRET_CLASSIFICATION'));
  assert.equal(result.violations[0].severity, 'CRITICAL');
});

test('DlpEngine — detects private keys and cloud API credentials', () => {
  const pemPayload = Buffer.from(
    Buffer.from(
      'LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBMFkuLi4KLS0tLS1FTkQgUlNBIFBSSVZBVEUgS0VZLS0tLS0=',
      'base64',
    ).toString('utf-8'),
    'utf-8',
  );
  const resultPem = DlpEngine.scanPayload(pemPayload);
  assert.equal(resultPem.isClean, false);
  assert.equal(resultPem.action, 'BLOCK');
  assert.ok(resultPem.violations.some((v) => v.type === 'PRIVATE_KEY_CREDENTIAL'));

  const mockAwsKey = Buffer.from('QUtJQUlPU0ZPRE5ON0VYQU1QTEU=', 'base64').toString('utf-8');
  const awsPayload = Buffer.from(`Deploy config: AWS_ACCESS_KEY_ID=${mockAwsKey}`, 'utf-8');
  const resultAws = DlpEngine.scanPayload(awsPayload);
  assert.equal(resultAws.isClean, false);
  assert.ok(resultAws.violations.some((v) => v.type === 'PRIVATE_KEY_CREDENTIAL'));
});

test('DlpEngine — detects leaked forensic watermark tokens (WM-...)', () => {
  const wmToken = 'WM-1234567890abcdef1234567890abcdef1234567890abcdef';
  const leakedDoc = Buffer.from(
    `Trích xuất tài liệu mật kèm mã kiểm toán ${wmToken} ra ngoài.`,
    'utf-8',
  );

  const result = DlpEngine.scanPayload(leakedDoc);
  assert.equal(result.isClean, false);
  assert.equal(result.action, 'BLOCK');
  assert.ok(result.violations.some((v) => v.type === 'FORENSIC_WATERMARK_LEAK'));
  assert.equal(result.violations[0].severity, 'CRITICAL');
});

test('DlpEngine — validates credit card numbers using Luhn checksum', () => {
  assert.equal(DlpEngine.isValidLuhn('4532015112830366'), true);
  assert.equal(DlpEngine.isValidLuhn('4532015112830367'), false);

  const payloadWithCard = Buffer.from(
    'Thông tin thanh toán khách hàng: 4532-0151-1283-0366',
    'utf-8',
  );
  const result = DlpEngine.scanPayload(payloadWithCard);
  assert.equal(result.isClean, false);
  assert.ok(result.violations.some((v) => v.type === 'PAYMENT_CARD_DATA'));

  const payloadWithFake = Buffer.from(
    'Mã số hợp đồng 16 chữ số ngẫu nhiên: 1234-5678-9012-3456',
    'utf-8',
  );
  const resultFake = DlpEngine.scanPayload(payloadWithFake);
  assert.equal(resultFake.isClean, true);
});

test('DlpEngine — allows clean benign payloads', () => {
  const cleanDoc = Buffer.from(
    'Báo cáo tổng kết quý 3 năm 2026: Doanh thu đạt kế hoạch, không có sai phạm nghiệp vụ.',
    'utf-8',
  );
  const result = DlpEngine.scanPayload(cleanDoc);
  assert.equal(result.isClean, true);
  assert.equal(result.action, 'ALLOW');
  assert.equal(result.violations.length, 0);
});

// ── 2. ICAP RFC 3507 Parser Unit Tests ─────────────────────────────────────────

test('IcapParser — parses OPTIONS request and builds standard 200 OK capability response', () => {
  const rawOptions = Buffer.from(
    'OPTIONS icap://127.0.0.1:1344/sda-dlp ICAP/1.0\r\n' +
      'Host: 127.0.0.1:1344\r\n' +
      'User-Agent: Squid/5.7\r\n' +
      'Encapsulated: null-body=0\r\n\r\n',
    'utf-8',
  );

  const req = IcapParser.parseRequest(rawOptions);
  assert.ok(req);
  assert.equal(req.method, 'OPTIONS');
  assert.equal(req.version, 'ICAP/1.0');
  assert.equal(req.headers['host'], '127.0.0.1:1344');

  const optionsResponse = IcapParser.buildOptionsResponse().toString('utf-8');
  assert.ok(optionsResponse.startsWith('ICAP/1.0 200 OK'));
  assert.ok(optionsResponse.includes('Methods: RESPMOD, REQMOD'));
  assert.ok(optionsResponse.includes('ISTag: "SDA-DLP-1.0.0"'));
  assert.ok(optionsResponse.includes('Allow: 204'));
});

test('IcapParser — parses RESPMOD with chunked body and generates HTML-escaped Block or 204 response', () => {
  const httpHeader = 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 12\r\n\r\n';
  const bodyText = 'Hello World!';
  const chunkSizeHex = Buffer.from(bodyText, 'utf-8').length.toString(16);
  const chunkedBody = `${chunkSizeHex}\r\n${bodyText}\r\n0\r\n\r\n`;

  const icapHeader =
    'RESPMOD icap://gateway:1344/sda-dlp ICAP/1.0\r\n' +
    'Host: gateway:1344\r\n' +
    `Encapsulated: res-hdr=0, res-body=${Buffer.byteLength(httpHeader)}\r\n\r\n`;

  const rawReq = Buffer.concat([
    Buffer.from(icapHeader, 'utf-8'),
    Buffer.from(httpHeader, 'utf-8'),
    Buffer.from(chunkedBody, 'utf-8'),
  ]);

  const req = IcapParser.parseRequest(rawReq);
  assert.ok(req);
  assert.equal(req.method, 'RESPMOD');
  assert.equal(req.body.toString('utf-8'), 'Hello World!');

  const res204 = IcapParser.build204Response().toString('utf-8');
  assert.ok(res204.startsWith('ICAP/1.0 204 No modifications'));

  const blockRes = IcapParser.buildBlockResponse([
    {
      type: 'TOP_SECRET_CLASSIFICATION',
      severity: 'CRITICAL',
      rule: 'RULE_<script>alert(1)</script>',
      description: 'Chặn rò rỉ Tuyệt Mật',
      matchedSnippet: 'TUYỆT MẬT',
    },
  ]).toString('utf-8');

  assert.ok(blockRes.startsWith('ICAP/1.0 200 OK'));
  assert.ok(blockRes.includes('HTTP/1.1 403 Forbidden'));
  assert.ok(blockRes.includes('X-DLP-Status: BLOCKED'));
  assert.ok(!blockRes.includes('<script>alert(1)</script>'));
  assert.ok(blockRes.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
});
