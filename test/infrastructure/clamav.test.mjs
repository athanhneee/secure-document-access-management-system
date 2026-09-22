import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import net from 'node:net';
import { test } from 'node:test';

async function scanWithClamd(payload) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: '127.0.0.1', port: 3310 });
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
