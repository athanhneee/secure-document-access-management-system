import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';

if (process.platform !== 'win32' || process.arch !== 'x64') {
  throw new Error(
    'This optional portable bootstrap supports Windows x64. Other platforms: install the Node version in .node-version and enable Corepack.',
  );
}
const nodeVersion = '24.21.0';
const pnpmVersion = '12.4.1';
async function download(url) {
  const response = await fetch(url, { signal: AbortSignal.timeout(120000) });
  if (!response.ok) throw new Error(`Download failed: ${response.status} ${url}`);
  return Buffer.from(await response.arrayBuffer());
}
await mkdir('.tools/pnpm', { recursive: true });
const base = `https://nodejs.org/dist/v${nodeVersion}`;
const sums = (await download(`${base}/SHASUMS256.txt`)).toString();
const expected = sums
  .split('\n')
  .find((line) => line.endsWith('  win-x64/node.exe'))
  ?.split(' ')[0];
if (!expected) throw new Error('Official Node checksum missing');
const node = await download(`${base}/win-x64/node.exe`);
if (createHash('sha256').update(node).digest('hex') !== expected)
  throw new Error('Node checksum mismatch');
await writeFile('.tools/node.exe', node);
const metadata = JSON.parse(
  (await download(`https://registry.npmjs.org/pnpm/${pnpmVersion}`)).toString(),
);
const archive = await download(metadata.dist.tarball);
const integrity = `sha512-${createHash('sha512').update(archive).digest('base64')}`;
if (integrity !== metadata.dist.integrity) throw new Error('pnpm registry integrity mismatch');
await writeFile('.tools/pnpm.tgz', archive);
const extraction = spawnSync(
  'tar',
  ['-xzf', '.tools/pnpm.tgz', '-C', '.tools/pnpm', '--strip-components', '1'],
  { stdio: 'inherit' },
);
if (extraction.status !== 0) throw new Error('pnpm extraction failed');
await writeFile('.tools/pnpm.cmd', '@"%~dp0node.exe" "%~dp0pnpm\\bin\\pnpm.mjs" %*\r\n');
console.log(
  `Verified portable Node ${nodeVersion} and pnpm ${pnpmVersion} installed under ignored .tools/.`,
);
