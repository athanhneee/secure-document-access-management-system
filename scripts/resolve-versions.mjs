import { mkdir, writeFile } from 'node:fs/promises';

const names = [
  'pnpm',
  'turbo',
  'typescript',
  'prettier',
  'oxlint',
  'husky',
  'lint-staged',
  '@commitlint/cli',
  '@commitlint/config-conventional',
  '@nestjs/common',
  '@nestjs/core',
  '@nestjs/platform-fastify',
  'fastify',
  'reflect-metadata',
  'rxjs',
  'next',
  'react',
  'react-dom',
  '@types/node',
  '@types/react',
  '@types/react-dom',
  '@electric-sql/pglite',
  '@playwright/test',
];
const entries = await Promise.all(
  names.map(async (name) => {
    const url = `https://registry.npmjs.org/${encodeURIComponent(name)}`;
    const response = await fetch(url, { signal: AbortSignal.timeout(30000) });
    if (!response.ok) throw new Error(`Registry ${name}: ${response.status}`);
    const data = await response.json();
    const major = name === '@types/node' ? 24 : undefined;
    const stable = Object.keys(data.versions).filter(
      (v) =>
        /^\d+\.\d+\.\d+$/.test(v) && (major === undefined || Number(v.split('.')[0]) === major),
    );
    stable.sort((a, b) => {
      const left = a.split('.').map(Number);
      const right = b.split('.').map(Number);
      return right[0] - left[0] || right[1] - left[1] || right[2] - left[2];
    });
    const version = stable[0];
    const selected = data.versions[version];
    if (selected.deprecated) throw new Error(`Deprecated ${name}@${version}`);
    return [
      name,
      {
        version,
        source: `${url}/${version}`,
        published: data.time[version],
        engines: selected.engines ?? {},
        peers: selected.peerDependencies ?? {},
      },
    ];
  }),
);
await mkdir('docs', { recursive: true });
const result = {
  checkedAt: new Date().toISOString(),
  node: { version: '24.21.0', source: 'https://nodejs.org/dist/index.json' },
  packages: Object.fromEntries(entries),
};
await writeFile('docs/toolchain-versions.json', `${JSON.stringify(result, null, 2)}\n`);
for (const [name, info] of entries) console.log(`${name} ${info.version}`);
