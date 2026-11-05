/**
 * SDA Dependency License & Software Bill of Materials (SBOM) Validator
 * Scans production dependencies across all monorepo packages, verifies licenses
 * against permissive allowlist, and generates CycloneDX 1.5 metadata inventory.
 *
 * Thuật toán: Quét Đồ Thị Phụ Thuộc Monorepo, Phân Tích Biểu Thức SPDX Nghiêm Ngặt & Kết Xuất CycloneDX 1.5 SBOM
 * Mục đích: Ngăn chặn đưa thư viện có giấy phép copyleft hoặc chưa xác định (`UNKNOWN`) vào bản dựng production
 *   và xuất hồ sơ SBOM chuẩn CycloneDX 1.5 kèm `urn:uuid:<RFC-4122>` hợp lệ.
 * Cơ chế hoạt động:
 *   - Thu thập hợp nhất toàn bộ phụ thuộc runtime trên 9 gói workspace (bao gồm `packages/config`, loại trừ `@sda/*`).
 *   - Phân giải `package.json` thực tế của từng phụ thuộc qua `createRequire` từ từng workspace và cây `node_modules/.pnpm`;
 *     nếu không tìm thấy giấy phép thì trả về `'UNKNOWN'` (Fail-Closed — tuyệt đối không gán mặc định `'MIT'`).
 *   - Phân tích biểu thức SPDX hợp chất (`OR`, `AND`, dấu ngoặc): biểu thức `A AND B` chỉ hợp lệ khi MỌI nhánh đều nằm trong `ALLOWED_LICENSES`;
 *     biểu thức `A OR B` hợp lệ khi CÓ ÍT NHẤT MỘT nhánh nằm trong `ALLOWED_LICENSES`.
 */

import crypto from 'node:crypto';
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');

const ALLOWED_LICENSES = new Set([
  'MIT',
  'MIT-0',
  'Apache-2.0',
  'BSD-2-Clause',
  'BSD-3-Clause',
  'ISC',
  '0BSD',
  'BlueOak-1.0.0',
  'CC0-1.0',
  'CC-BY-4.0',
  'Python-2.0',
  'Zlib',
  'Unlicense',
  'Public Domain',
]);

const PACKAGE_JSON_PATHS = [
  path.join(rootDir, 'package.json'),
  path.join(rootDir, 'apps/api/package.json'),
  path.join(rootDir, 'apps/web/package.json'),
  path.join(rootDir, 'apps/worker/package.json'),
  path.join(rootDir, 'packages/config/package.json'),
  path.join(rootDir, 'packages/contracts/package.json'),
  path.join(rootDir, 'packages/database/package.json'),
  path.join(rootDir, 'packages/security/package.json'),
  path.join(rootDir, 'packages/testing/package.json'),
];

/**
 * Thuật toán: Đánh Giá Đệ Quy Biểu Thức Giấy Phép SPDX (Boolean SPDX License Expression Evaluator)
 * Cơ chế hoạt động:
 *   - Tách biểu thức ngoài ngoặc theo toán tử ưu tiên thấp `OR` trước (thỏa mãn nếu `some` nhánh con hợp lệ),
 *     sau đó tách theo toán tử `AND` (thỏa mãn chỉ khi `every` nhánh con hợp lệ — chặn chặt kiểu `'GPL-3.0-only AND MIT'`).
 */
export function isPermissiveSpdxExpression(rawLicense) {
  if (typeof rawLicense !== 'string') return false;
  let expr = rawLicense.trim();
  if (!expr || expr === 'UNKNOWN' || expr === 'UNLICENSED') return false;

  while (expr.startsWith('(') && expr.endsWith(')')) {
    let depth = 0;
    let wrapsEntire = true;
    for (let i = 0; i < expr.length; i++) {
      if (expr[i] === '(') depth++;
      else if (expr[i] === ')') depth--;
      if (depth === 0 && i < expr.length - 1) {
        wrapsEntire = false;
        break;
      }
    }
    if (wrapsEntire) {
      expr = expr.slice(1, -1).trim();
    } else {
      break;
    }
  }

  const orParts = splitTopLevelSpdx(expr, 'OR');
  if (orParts.length > 1) {
    return orParts.some((part) => isPermissiveSpdxExpression(part));
  }

  const andParts = splitTopLevelSpdx(expr, 'AND');
  if (andParts.length > 1) {
    return andParts.every((part) => isPermissiveSpdxExpression(part));
  }

  return ALLOWED_LICENSES.has(expr);
}

function splitTopLevelSpdx(expr, operator) {
  const parts = [];
  let depth = 0;
  let lastIndex = 0;
  const token = ` ${operator} `;

  for (let i = 0; i < expr.length; i++) {
    if (expr[i] === '(') depth++;
    else if (expr[i] === ')') depth--;
    else if (depth === 0 && expr.slice(i, i + token.length) === token) {
      parts.push(expr.slice(lastIndex, i).trim());
      i += token.length - 1;
      lastIndex = i + 1;
    }
  }
  parts.push(expr.slice(lastIndex).trim());
  return parts;
}

function extractLicenseField(pkgContent) {
  const lic = pkgContent.license || (Array.isArray(pkgContent.licenses) && pkgContent.licenses[0]);
  if (!lic) return null;
  if (typeof lic === 'string') return lic.trim();
  if (typeof lic === 'object' && typeof lic.type === 'string') return lic.type.trim();
  return null;
}

/**
 * Thuật toán: Phân Giải Siêu Dữ Liệu Giấy Phép Phụ Thuộc Không Giả Định Mặc Định (Fail-Closed Package License Resolver)
 */
async function getDependencyLicense(depName, consumerPkgPaths) {
  for (const consumerPkgPath of consumerPkgPaths) {
    if (!existsSync(consumerPkgPath)) continue;
    try {
      const req = createRequire(consumerPkgPath);
      const resolvedPkgJson = req.resolve(`${depName}/package.json`);
      const content = JSON.parse(await readFile(resolvedPkgJson, 'utf-8'));
      const extracted = extractLicenseField(content);
      if (extracted) return extracted;
    } catch {
      // Package may not export ./package.json in exports map; try directory walk next
    }

    const directCandidate = path.join(
      path.dirname(consumerPkgPath),
      'node_modules',
      depName,
      'package.json',
    );
    if (existsSync(directCandidate)) {
      try {
        const content = JSON.parse(await readFile(directCandidate, 'utf-8'));
        const extracted = extractLicenseField(content);
        if (extracted) return extracted;
      } catch {
        // Continue probing pnpm virtual store
      }
    }
  }

  const pnpmStoreDir = path.join(rootDir, 'node_modules', '.pnpm');
  if (existsSync(pnpmStoreDir)) {
    const normalizedPrefix = `${depName.replace('/', '+')}@`;
    const entries = await readdir(pnpmStoreDir);
    const match = entries.find((entry) => entry.startsWith(normalizedPrefix));
    if (match) {
      const storePkgJson = path.join(pnpmStoreDir, match, 'node_modules', depName, 'package.json');
      if (existsSync(storePkgJson)) {
        try {
          const content = JSON.parse(await readFile(storePkgJson, 'utf-8'));
          const extracted = extractLicenseField(content);
          if (extracted) return extracted;
        } catch {
          // Fall through to UNKNOWN
        }
      }
    }
  }

  return 'UNKNOWN';
}

async function main() {
  console.log('='.repeat(78));
  console.log('SDA SOFTWARE BILL OF MATERIALS (SBOM) & LICENSE AUDIT');
  console.log('='.repeat(78));

  const allDependencies = new Map();

  for (const pkgPath of PACKAGE_JSON_PATHS) {
    if (!existsSync(pkgPath)) continue;
    const pkg = JSON.parse(await readFile(pkgPath, 'utf-8'));
    const deps = { ...pkg.dependencies };

    for (const [dep, ver] of Object.entries(deps)) {
      if (dep.startsWith('@sda/')) continue;
      const existing = allDependencies.get(dep);
      if (existing) {
        existing.consumers.push(pkgPath);
      } else {
        allDependencies.set(dep, { version: ver, consumers: [pkgPath] });
      }
    }
  }

  const sbomComponents = [];
  let violations = 0;

  for (const [dep, meta] of allDependencies.entries()) {
    const license = await getDependencyLicense(dep, [...meta.consumers, ...PACKAGE_JSON_PATHS]);
    const isAllowed = isPermissiveSpdxExpression(license);

    sbomComponents.push({
      name: dep,
      version: meta.version.replace(/^[\^~]/, ''),
      license,
      isPermissive: isAllowed,
    });

    if (!isAllowed) {
      console.error(`[VIOLATION] Disallowed or unknown license for ${dep}: ${license}`);
      violations++;
    }
  }

  const sbomDocument = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      component: {
        name: 'secure-document-access-system',
        version: '1.0.0',
        type: 'application',
      },
    },
    components: sbomComponents.map((c) => ({
      type: 'library',
      name: c.name,
      version: c.version,
      licenses: [{ license: { id: c.license } }],
    })),
  };

  const reportsDir = path.join(rootDir, '.reports');
  await mkdir(reportsDir, { recursive: true });
  const sbomPath = path.join(reportsDir, 'sbom-inventory.json');
  await writeFile(sbomPath, JSON.stringify(sbomDocument, null, 2), 'utf-8');

  console.log(`Audited ${allDependencies.size} production runtime dependencies:`);
  console.table(
    sbomComponents.slice(0, 15).map((c) => ({
      Dependency: c.name,
      Version: c.version,
      License: c.license,
      Status: c.isPermissive ? 'ALLOW' : 'DISALLOW',
    })),
  );
  if (sbomComponents.length > 15) {
    console.log(`... and ${sbomComponents.length - 15} more audited.`);
  }

  console.log(`\nSBOM exported successfully to: .reports/sbom-inventory.json`);

  if (violations > 0) {
    console.error(`\nFAILED: Found ${violations} dependencies with non-permissive licenses.`);
    process.exit(1);
  } else {
    console.log(
      '\nSUCCESS: 100% DEPENDENCIES HAVE VERIFIED PERMISSIVE LICENSES (NO UNKNOWN FALLBACKS).',
    );
    process.exit(0);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error('Fatal license audit error:', err);
    process.exit(1);
  });
}
