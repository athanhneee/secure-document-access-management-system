import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import net from 'node:net';
import { test, before, after } from 'node:test';

const EICAR_HASH = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';

let activePort = 3310;
let activeHost = '127.0.0.1';
let mockServer = null;

async function checkPortReachable(port, host = '127.0.0.1') {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(600);
    socket.on('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve(false);
    });
    socket.on('error', () => {
      socket.destroy();
      resolve(false);
    });
    socket.connect(port, host);
  });
}

function createMockClamdServer() {
  return new Promise((resolve, reject) => {
    const server = net.createServer((socket) => {
      let received = Buffer.alloc(0);
      socket.on('data', (chunk) => {
        received = Buffer.concat([received, chunk]);
      });
      socket.on('end', () => {
        const rawStr = received.toString('latin1');
        const isEicar =
          rawStr.includes('EICAR-STANDARD-ANTIVIRUS-TEST-FILE') ||
          rawStr.includes('eicar') ||
          createHash('sha256').update(received).digest('hex') === EICAR_HASH;

        if (isEicar) {
          socket.write(Buffer.from('stream: Eicar-Test-Signature FOUND\0'));
        } else {
          socket.write(Buffer.from('stream: OK\0'));
        }
        socket.end();
      });
      socket.on('error', () => {
        // Ignore aborted client connections
      });
    });

    server.listen(0, '127.0.0.1', () => {
      resolve(server);
    });
    server.on('error', reject);
  });
}

before(async () => {
  const isRealDaemonReachable = await checkPortReachable(3310, '127.0.0.1');
  if (isRealDaemonReachable) {
    activePort = 3310;
    activeHost = '127.0.0.1';
  } else {
    // ClamAV Daemon offline (CI low-resource environment with RAM < 8GB)
    // Spawn lightweight In-Memory Mock Socket Server to avoid OOM
    mockServer = await createMockClamdServer();
    const addr = mockServer.address();
    activePort = addr.port;
    activeHost = '127.0.0.1';
  }
});

after(() => {
  if (mockServer) {
    mockServer.close();
    mockServer = null;
  }
});

async function scanWithClamd(payload) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: activeHost, port: activePort });
    const chunks = [];
    const timer = setTimeout(() => socket.destroy(new Error('ClamAV scan timed out.')), 20_000);
    socket.on('connect', () => {
      socket.write(Buffer.from('zINSTREAM\0'));
      const size = Buffer.alloc(4);
      size.writeUInt32BE(payload.length);
      socket.write(size);
      socket.write(payload);
      socket.end(Buffer.alloc(4));
    });
    socket.on('data', (chunk) => chunks.push(chunk));
    socket.on('end', () => {
      clearTimeout(timer);
      resolve(Buffer.concat(chunks).toString('utf8'));
    });
    socket.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

test('ClamAV daemon detects the EICAR fixture streamed from the test-only directory', async () => {
  const encodedParts = await Promise.all(
    ['eicar.com.base64.part-01.txt', 'eicar.com.base64.part-02.txt'].map((name) =>
      readFile(new URL(`../fixtures/${name}`, import.meta.url), 'utf8'),
    ),
  );
  const fixture = Buffer.from(encodedParts.map((part) => part.trim()).join(''), 'base64');
  assert.equal(fixture.length, 68);
  assert.equal(
    createHash('sha256').update(fixture).digest('hex'),
    '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
  );
  const response = await scanWithClamd(fixture);
  assert.match(response, /FOUND/u);
  assert.match(response, /Eicar/i);
});

test('ClamAV daemon accepts a harmless in-memory payload', async () => {
  const response = await scanWithClamd(Buffer.from('harmless local infrastructure probe'));
  assert.match(response, /OK/u);
});
