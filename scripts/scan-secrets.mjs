import { execFileSync } from 'node:child_process';
import { readFile, lstat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryRoot = fileURLToPath(new URL('../', import.meta.url));
const files = [
  ...new Set(
    execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], {
      cwd: repositoryRoot,
      encoding: 'utf8',
      maxBuffer: 20 * 1024 * 1024,
    })
      .split('\0')
      .filter(Boolean),
  ),
];

const pathRules = [
  ['real-environment-file', /(?:^|\/)\.env(?:\.[^/]+)?$/i],
  [
    'private-key-file',
    /(?:^|\/)(?:id_rsa|id_ed25519|id_ecdsa)(?:$|\.)|\.(?:pem|key|p12|pfx|jks|keystore)$/i,
  ],
  [
    'decrypted-document-path',
    /(?:^|\/)(?:decrypted|plaintext|secrets)(?:\/|$)|\.(?:decrypted|plaintext)$/i,
  ],
];
const contentRules = [
  ['private-key-material', /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/],
  ['github-token', /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\b/],
  ['aws-access-key', /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/],
  ['slack-token', /\bxox[baprs]-[A-Za-z0-9-]{20,255}\b/],
  ['npm-token', /\bnpm_[A-Za-z0-9]{36,255}\b/],
  ['openai-token', /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,255}\b/],
  [
    'credential-in-url',
    /\b(?:postgres(?:ql)?|mysql|redis(?:s)?|amqp(?:s)?):\/\/[^\s:/]+:([^\s@/]+)@/gi,
  ],
];
const assignment =
  /\b(?:password|passwd|client_secret|api_key|access_token|refresh_token|encryption_key|secret_key)\b\s*[:=]\s*(['"])([^'"\r\n]+)\1/gi;
const placeholder =
  /^(?:<[^>]+>|\$\{[^}]+\}|\$[A-Z_][A-Z0-9_]*|process\.env\.[A-Z_]+|(?:your|replace|change|example|placeholder|dummy|test|fixture|invalid|nonexistent)[-_ ].*|not-an-authentication-hash)$/i;
const findings = [];

for (const file of files) {
  const normalized = file.replaceAll('\\', '/');
  const absolute = path.resolve(repositoryRoot, file);
  const relative = path.relative(repositoryRoot, absolute);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    findings.push({ file: normalized, rule: 'path-outside-repository' });
    continue;
  }
  const stat = await lstat(absolute).catch((error) => {
    if (error.code === 'ENOENT') return undefined; // A tracked deletion has no content to scan.
    throw error;
  });
  if (!stat) continue;
  if (stat.isSymbolicLink()) {
    findings.push({ file: normalized, rule: 'symlink-requires-review' });
    continue;
  }
  if (!stat.isFile()) continue;
  for (const [rule, pattern] of pathRules) {
    if (
      pattern.test(normalized) &&
      !/\.env(?:\.[^/]+)?\.(?:example|sample|template)$/i.test(normalized)
    ) {
      findings.push({ file: normalized, rule });
    }
  }
  const content = await readFile(absolute);
  if (content.includes(0)) continue; // Binary payloads need a dedicated scanner before introduction.
  const source = content.toString('utf8');
  for (const [rule, pattern] of contentRules) {
    pattern.lastIndex = 0;
    const matches = pattern.global
      ? [...source.matchAll(pattern)]
      : [pattern.exec(source)].filter(Boolean);
    if (
      matches.some((match) => !(rule === 'credential-in-url' && placeholder.test(match[1] ?? '')))
    ) {
      findings.push({ file: normalized, rule });
    }
  }
  for (const match of source.matchAll(assignment)) {
    if (!placeholder.test(match[2])) {
      findings.push({ file: normalized, rule: 'literal-credential-assignment' });
      break;
    }
  }
}

if (findings.length > 0) {
  console.error('Secret hygiene check failed (paths and rule names only):');
  for (const finding of findings) console.error(`${finding.file}: ${finding.rule}`);
  process.exitCode = 1;
} else {
  console.log(
    `Secret hygiene check passed: ${files.length} tracked/nonignored files; no matching sensitive paths or credential patterns.`,
  );
}
