import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as net from 'node:net';
import { IcapServer } from '../dist/icap/icap-server.js';
import { resolveIcapDlpAction } from '../dist/icap/icap-worker-job.js';

function sendIcap(port, payload) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: '127.0.0.1', port }, () => {
      socket.write(payload);
    });
    let responseBuffer = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      responseBuffer = Buffer.concat([responseBuffer, chunk]);
    });
    socket.on('end', () => resolve(responseBuffer.toString('utf-8')));
    socket.on('error', reject);
  });
}

test('IcapServer — live TCP socket handles OPTIONS, clean 204 and DLP Block', async () => {
  const server = new IcapServer({
    enabled: true,
    port: 0,
    host: '127.0.0.1',
    action: 'BLOCK',
  });

  const violationsRecorded = [];
  server.onViolation((res) => {
    violationsRecorded.push(res);
  });

  const { port } = await server.start();
  assert.ok(port > 0, 'Server must bind to a valid dynamic port');

  try {
    const optionsRaw =
      'OPTIONS icap://127.0.0.1/sda-dlp ICAP/1.0\r\n' +
      'Host: 127.0.0.1\r\n' +
      'Encapsulated: null-body=0\r\n\r\n';
    const optRes = await sendIcap(port, optionsRaw);
    assert.ok(optRes.includes('ICAP/1.0 200 OK'));
    assert.ok(optRes.includes('Methods: RESPMOD, REQMOD'));

    const cleanHttp = 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n';
    const cleanBody = 'Báo cáo công khai thông thường không chứa bí mật.';
    const cleanHex = Buffer.byteLength(cleanBody, 'utf-8').toString(16);
    const cleanIcap =
      `RESPMOD icap://127.0.0.1/sda-dlp ICAP/1.0\r\n` +
      `Host: 127.0.0.1\r\n` +
      `Encapsulated: res-hdr=0, res-body=${Buffer.byteLength(cleanHttp)}\r\n\r\n` +
      cleanHttp +
      `${cleanHex}\r\n${cleanBody}\r\n0\r\n\r\n`;

    const res204 = await sendIcap(port, cleanIcap);
    assert.ok(res204.includes('ICAP/1.0 204 No modifications'));

    const leakHttp = 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n';
    const leakBody = 'DỮ LIỆU ĐẶC BIỆT: BÁO CÁO TUYỆT MẬT QUỐC GIA ĐƯỢC TRÍCH XUẤT.';
    const leakHex = Buffer.byteLength(leakBody, 'utf-8').toString(16);
    const leakIcap =
      `RESPMOD icap://127.0.0.1/sda-dlp ICAP/1.0\r\n` +
      `Host: 127.0.0.1\r\n` +
      `Encapsulated: res-hdr=0, res-body=${Buffer.byteLength(leakHttp)}\r\n\r\n` +
      leakHttp +
      `${leakHex}\r\n${leakBody}\r\n0\r\n\r\n`;

    const blockRes = await sendIcap(port, leakIcap);
    assert.ok(blockRes.includes('ICAP/1.0 200 OK'));
    assert.ok(blockRes.includes('HTTP/1.1 403 Forbidden'));
    assert.ok(blockRes.includes('X-DLP-Status: BLOCKED'));
    assert.ok(blockRes.includes('TRUY CẬP BỊ TỪ CHỐI BỞI HỆ THỐNG NETWORK DLP'));

    assert.equal(violationsRecorded.length, 1);
    assert.equal(violationsRecorded[0].action, 'BLOCK');
    assert.equal(violationsRecorded[0].violations[0].type, 'TOP_SECRET_CLASSIFICATION');

    const metrics = server.getMetrics();
    assert.equal(metrics.totalRequests, 3);
    assert.equal(metrics.optionsRequests, 1);
    assert.equal(metrics.respmodRequests, 2);
    assert.equal(metrics.cleanPassThrough, 1);
    assert.equal(metrics.blockedViolations, 1);
    assert.ok(metrics.scannedBytes > 0);
  } finally {
    await server.stop();
  }
});

test('IcapServer — buffers fragmented multi-chunk TCP streams and rejects malformed Encapsulated offsets/methods', async () => {
  const server = new IcapServer({
    enabled: true,
    port: 0,
    host: '127.0.0.1',
    action: 'BLOCK',
  });
  const { port } = await server.start();

  const sendRaw = (chunks) =>
    new Promise((resolve, reject) => {
      const socket = net.createConnection({ host: '127.0.0.1', port }, async () => {
        for (const chunk of chunks) {
          socket.write(chunk);
          await new Promise((r) => setTimeout(r, 15));
        }
      });
      let buf = Buffer.alloc(0);
      socket.on('data', (c) => {
        buf = Buffer.concat([buf, c]);
      });
      socket.on('end', () => resolve(buf.toString('utf-8')));
      socket.on('error', reject);
    });

  try {
    const unknownRes = await sendRaw([
      'FOOBAR icap://127.0.0.1/sda-dlp ICAP/1.0\r\nHost: 127.0.0.1\r\n\r\n',
    ]);
    assert.ok(unknownRes.includes('ICAP/1.0 405 Method Not Allowed'));

    const badOffsetRes = await sendRaw([
      'RESPMOD icap://127.0.0.1/sda-dlp ICAP/1.0\r\nHost: 127.0.0.1\r\nEncapsulated: res-hdr=-5, res-body=10\r\n\r\nHTTP/1.1 200 OK\r\n\r\n',
    ]);
    assert.ok(badOffsetRes.includes('ICAP/1.0 400 Bad Request'));

    const leakHttp = 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n';
    const leakBody = 'Trích xuất tài liệu NỘI DUNG TỐI MẬT QUỐC GIA qua nhiều gói tin TCP.';
    const leakHex = Buffer.byteLength(leakBody, 'utf-8').toString(16);
    const fullIcap = Buffer.from(
      `RESPMOD icap://127.0.0.1/sda-dlp ICAP/1.0\r\n` +
        `Host: 127.0.0.1\r\n` +
        `Encapsulated: res-hdr=0, res-body=${Buffer.byteLength(leakHttp)}\r\n\r\n` +
        leakHttp +
        `${leakHex}\r\n${leakBody}\r\n0\r\n\r\n`,
      'utf-8',
    );
    const fragmentedRes = await sendRaw([
      fullIcap.subarray(0, 110),
      fullIcap.subarray(110, 175),
      fullIcap.subarray(175),
    ]);
    assert.ok(fragmentedRes.includes('HTTP/1.1 403 Forbidden'));
    assert.ok(fragmentedRes.includes('X-DLP-Status: BLOCKED'));
  } finally {
    await server.stop();
  }
});

test('ICAP DLP Action — resolves AUDIT_ONLY and MONITOR alias and passes traffic with SOC callback', async () => {
  assert.equal(resolveIcapDlpAction(undefined), 'BLOCK');
  assert.equal(resolveIcapDlpAction('BLOCK'), 'BLOCK');
  assert.equal(resolveIcapDlpAction('AUDIT_ONLY'), 'AUDIT_ONLY');
  assert.equal(resolveIcapDlpAction('MONITOR'), 'AUDIT_ONLY');
  assert.equal(resolveIcapDlpAction('INVALID_TYPO'), 'BLOCK');

  const server = new IcapServer({
    enabled: true,
    port: 0,
    host: '127.0.0.1',
    action: resolveIcapDlpAction('AUDIT_ONLY'),
  });
  const auditedViolations = [];
  server.onViolation((scanResult) => {
    auditedViolations.push(scanResult);
  });

  const { port } = await server.start();
  try {
    const leakHttp = 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n';
    const leakBody = 'BÁO CÁO TUYỆT MẬT CẦN GIÁM SÁT CHẾ ĐỘ AUDIT_ONLY.';
    const leakHex = Buffer.byteLength(leakBody, 'utf-8').toString(16);
    const payload =
      `RESPMOD icap://127.0.0.1/sda-dlp ICAP/1.0\r\n` +
      `Host: 127.0.0.1\r\n` +
      `Encapsulated: res-hdr=0, res-body=${Buffer.byteLength(leakHttp)}\r\n\r\n` +
      leakHttp +
      `${leakHex}\r\n${leakBody}\r\n0\r\n\r\n`;

    const responseText = await sendIcap(port, payload);
    assert.ok(responseText.includes('ICAP/1.0 204 No modifications'));
    assert.equal(auditedViolations.length, 1);
    assert.equal(auditedViolations[0].action, 'AUDIT');
  } finally {
    await server.stop();
  }
});
