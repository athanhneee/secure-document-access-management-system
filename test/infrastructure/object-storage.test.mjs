/**
 * @module InfrastructureObjectStorageTest
 * Thuật toán: Kiểm chứng bất biến riêng tư và độ bền lưu trữ đối tượng trên cả hai chế độ hạ tầng:
 *   1. Chế độ Docker MinIO cục bộ (`minio` đang chạy): xác minh versioning, chặn anonymous qua `mc` và bảo toàn đối tượng sau `restart`.
 *   2. Chế độ Đám mây S3 / Cloudflare R2 (không bật Docker cục bộ): xác minh ghi-đọc-xóa thực tế trên cả 3 bucket (`documents`,
 *      `derivatives`, `quarantine`) qua `ObjectStorageService` và kiểm chứng truy cập HTTP nặc danh bị từ chối (`!== 200`).
 */
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { after, test } from 'node:test';
import { dockerCompose, isLocalComposeServiceRunning } from './helpers.mjs';

const objectName = `infrastructure-private-probe-${randomUUID()}.txt`;
const bucket = process.env['STORAGE_BUCKET_DOCUMENTS'] ?? 'secure-documents';
const useLocalMinio = isLocalComposeServiceRunning('minio');
const setupClient =
  'mc alias set local http://minio:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null; ' +
  'mc ready local >/dev/null; ';

function runClient(command) {
  return dockerCompose([
    'run',
    '--rm',
    '--no-deps',
    '--entrypoint',
    '/bin/sh',
    'minio-bootstrap',
    '-ec',
    `${setupClient}${command}`,
  ]);
}

after(() => {
  if (useLocalMinio) {
    runClient(`mc rm --force "local/${bucket}/${objectName}" >/dev/null 2>&1 || true`);
  }
});

test('object storage enforces private buckets and round-trip persistence (Local MinIO or Cloud S3/R2)', async () => {
  const buckets = [
    process.env['STORAGE_BUCKET_DOCUMENTS'] ?? 'secure-documents',
    process.env['STORAGE_BUCKET_DERIVATIVES'] ?? 'secure-derivatives',
    process.env['STORAGE_BUCKET_QUARANTINE'] ?? 'secure-quarantine',
  ];

  if (useLocalMinio) {
    const bucketChecks = buckets
      .map(
        (name) =>
          `printf 'BUCKET:${name}\\n'; mc version info "local/${name}"; ` +
          `mc anonymous get "local/${name}"`,
      )
      .join('; ');
    const setup = runClient(
      `${bucketChecks}; ` +
        `printf 'local-private-object-probe' > /tmp/${objectName}; ` +
        `mc cp /tmp/${objectName} "local/${bucket}/${objectName}"; ` +
        `mc stat "local/${bucket}/${objectName}"`,
    );
    for (const name of buckets) {
      const section = setup.split(`BUCKET:${name}\n`)[1]?.split('BUCKET:')[0] ?? '';
      assert.match(section, /enabled/i);
      assert.match(section, /private|none|disabled/i);
    }
    assert.match(setup, /Name\s*:/i);

    const anonymousResponse = await fetch(`http://127.0.0.1:9000/${bucket}/${objectName}`);
    await anonymousResponse.body?.cancel();
    assert.equal(anonymousResponse.status, 403);

    dockerCompose(['restart', 'minio'], { capture: false });
    dockerCompose(['up', '--detach', '--wait', '--wait-timeout', '120', 'minio'], {
      capture: false,
    });
    assert.match(runClient(`mc stat "local/${bucket}/${objectName}"`), /Name\s*:/i);
    return;
  }

  const apiRequire = createRequire(new URL('../../apps/api/package.json', import.meta.url));
  apiRequire('reflect-metadata');
  const { AppConfigService } = await import('../../apps/api/dist/config/config.service.js');
  const { ObjectStorageService } =
    await import('../../apps/api/dist/modules/documents/object-storage.service.js');
  const config = new AppConfigService();
  const storage = new ObjectStorageService(config);
  const payload = Buffer.from(`cloud-private-object-probe-${Date.now()}`, 'utf8');

  for (const targetBucket of buckets) {
    try {
      await storage.putObject(targetBucket, objectName, payload, 'application/octet-stream');
      const meta = await storage.headObject(targetBucket, objectName);
      assert.equal(meta?.contentLength, payload.length);
      const downloaded = await storage.getObject(targetBucket, objectName);
      assert.deepEqual(downloaded, payload);

      const rawEndpoint = String(process.env['STORAGE_ENDPOINT'] ?? '').trim();
      if (/^https?:\/\//iu.test(rawEndpoint)) {
        const anonUrl = `${rawEndpoint.replace(/\/+$/u, '')}/${targetBucket}/${objectName}`;
        const anonRes = await fetch(anonUrl, { signal: AbortSignal.timeout(8_000) });
        await anonRes.body?.cancel();
        assert.notEqual(anonRes.status, 200, 'Anonymous S3/R2 request must never return 200 OK');
      }
    } finally {
      await storage.deleteObject(targetBucket, objectName).catch(() => {});
    }
  }
});
