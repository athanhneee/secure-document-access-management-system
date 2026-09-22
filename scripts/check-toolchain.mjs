import { readFile } from 'node:fs/promises';

const manifest = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
const expectedNode = (await readFile(new URL('../.node-version', import.meta.url), 'utf8')).trim();
const parts = process.versions.node.split('.').map(Number);
const minimum = expectedNode.split('.').map(Number);
if (
  parts[0] !== 24 ||
  parts[1] < minimum[1] ||
  (parts[1] === minimum[1] && parts[2] < minimum[2])
) {
  throw new Error(
    `Node ${expectedNode}+ in the 24 LTS line is required; found ${process.versions.node}.`,
  );
}
const expectedPnpm = manifest.packageManager.replace('@', '/');
if (!process.env['npm_config_user_agent']?.startsWith(`${expectedPnpm} `)) {
  throw new Error(
    `Install with ${manifest.packageManager}; do not use npm or yarn for this workspace.`,
  );
}
