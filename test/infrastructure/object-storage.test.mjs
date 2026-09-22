import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { dockerCompose } from './helpers.mjs';

const objectName = 'infrastructure-private-probe.txt';
const bucket = process.env['STORAGE_BUCKET_DOCUMENTS'] ?? 'secure-documents';
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
  runClient(`mc rm --force "local/${bucket}/${objectName}" >/dev/null 2>&1 || true`);
});

test('bootstrap creates private, versioned buckets and uploaded objects persist across restart', async () => {
  const buckets = [
    process.env['STORAGE_BUCKET_DOCUMENTS'] ?? 'secure-documents',
    process.env['STORAGE_BUCKET_DERIVATIVES'] ?? 'secure-derivatives',
    process.env['STORAGE_BUCKET_QUARANTINE'] ?? 'secure-quarantine',
  ];
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
  dockerCompose(['up', '--detach', '--wait', '--wait-timeout', '120', 'minio'], { capture: false });
  assert.match(runClient(`mc stat "local/${bucket}/${objectName}"`), /Name\s*:/i);
});
