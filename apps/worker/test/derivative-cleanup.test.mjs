import assert from 'node:assert/strict';
import { test } from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { cleanStaleTempFiles, startDerivativeCleanupJob } from '../dist/derivative-cleanup-job.js';

test('cleanStaleTempFiles — purges files older than TTL and preserves fresh files', async () => {
  const testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sda-test-clean-'));

  try {
    const staleFile = path.join(testDir, 'sda-stale-file.tmp');
    const freshFile = path.join(testDir, 'sda-fresh-file.tmp');
    const otherFile = path.join(testDir, 'other-file.txt');

    fs.writeFileSync(staleFile, 'stale derivative bytes');
    fs.writeFileSync(freshFile, 'fresh derivative bytes');
    fs.writeFileSync(otherFile, 'non-sda file');

    // Set stale file mtime to 2 hours ago (120 minutes)
    const twoHoursAgo = new Date(Date.now() - 120 * 60 * 1000);
    fs.utimesSync(staleFile, twoHoursAgo, twoHoursAgo);

    // Run cleanup with 60-minute TTL
    const purgedCount = await cleanStaleTempFiles(60, testDir);

    assert.equal(purgedCount, 1, 'Should have purged exactly 1 stale file');
    assert.equal(fs.existsSync(staleFile), false, 'Stale file must be removed');
    assert.equal(fs.existsSync(freshFile), true, 'Fresh file must be preserved');
    assert.equal(fs.existsSync(otherFile), true, 'Non-sda file must not be touched');
  } finally {
    fs.rmSync(testDir, { recursive: true, force: true });
  }
});

test('startDerivativeCleanupJob — starts and stops cleanly with AbortSignal', async () => {
  const controller = new AbortController();
  startDerivativeCleanupJob(600_000, 60, controller.signal);
  controller.abort();
  await new Promise((resolve) => setTimeout(resolve, 50));
});
