/**
 * SDA Dependency License & Software Bill of Materials (SBOM) Validator
 * Scans direct AND transitive production dependencies across all monorepo packages,
 * verifies licenses against permissive allowlist, and generates CycloneDX 1.5 metadata inventory.
 *
 * Thuật toán: Duyệt Đệ Quy Đồ Thị Phụ Thuộc Bắc Cầu Monorepo Qua `createRequire` & `node_modules/.pnpm`
 *   Kèm Phân Tích Biểu Thức SPDX Nghiêm Ngặt & Kết Xuất CycloneDX 1.5 SBOM (`BUG-126`)
 * Mục đích: Ngăn chặn đưa thư viện trực tiếp hoặc bắc cầu có giấy phép copyleft / chưa xác định (`UNKNOWN`)
 *   vào bản dựng production và xuất hồ sơ SBOM chuẩn CycloneDX 1.5 kèm `urn:uuid:<RFC-4122>` hợp lệ.
 * Cơ chế hoạt động:
 *   - Khởi tạo hàng đợi duyệt đồ thị từ toàn bộ `dependencies` trên 9 gói workspace (bỏ qua xuất `@sda/*` nội bộ ra SBOM).
 *   - Với mỗi gói, phân giải đường dẫn `package.json` thực tế qua `createRequire(resolverPath)` (kèm dò ngược từ điểm nhập chính nếu `exports` chặn `./package.json`), dò thư mục `node_modules` lân cận trong kho ảo `.pnpm`, hoặc đối sánh tiền tố trong `node_modules/.pnpm`.
 *   - Dùng `Set` đánh dấu các nút đã thăm (`realpath` của `package.json` và khóa `name@version`) để khử chu trình đồ thị trong `O(V + E)` và đệ quy vào `dependencies` của từng gói con.
 *   - Nếu không tìm thấy giấy phép thì trả về `'UNKNOWN'` (Fail-Closed — tuyệt đối không gán mặc định `'MIT'`).
 *   - Phân tích biểu thức SPDX hợp chất (`OR`, `AND`, dấu ngoặc): `A AND B` chỉ hợp lệ khi MỌI nhánh nằm trong `ALLOWED_LICENSES`; `A OR B` hợp lệ khi CÓ ÍT NHẤT MỘT nhánh nằm trong `ALLOWED_LICENSES`.
 */

import crypto from 'node:crypto';
import { mkdir, readdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');

const ALLOWED_LICENSES = new Set([
  'MIT',
  'MIT-0',
  'MIT/X11',
  'X11',
  'Apache-2.0',
  'BSD-2-Clause',
  'BSD-3-Clause',
  'ISC',
  '0BSD',
  'BlueOak-1.0.0',
  'CC0-1.0',
  'CC-BY-4.0',
  'CC-BY-3.0',
  'Artistic-2.0',
  'LGPL-3.0-or-later WITH LGPL-3.0-linking-exception',
  'PSF-2.0',
  'Python-2.0',
  'Zlib',
  'Unlicense',
  'Public Domain',
  'WTFPL',
]);

// Explicit version-pinned audit overrides for pre-SPDX npm tarballs (circa 2011) whose upstream repository is verified MIT/X11
// (`exceljs -> archiver/unzipper -> binary -> buffers@0.1.1`, https://github.com/substack/node-buffers).
// Unknown packages NOT in this pinned map remain strictly Fail-Closed ('UNKNOWN' -> exit 1).
const VERIFIED_LEGACY_PACKAGE_LICENSES = new Map([['buffers@0.1.1', 'MIT']]);

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
function isPermissiveSpdxExpression(rawLicense) {
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

/**
 * Thuật toán: Tách Chuỗi Biểu Thức SPDX Ở Mức Ngoài Ngoặc (Parenthesis-Aware Top-Level SPDX Tokenizer)
 * Duyệt tuyến tính với biến đếm độ sâu ngoặc `depth`, chỉ cắt chuỗi tại toán tử ` ${operator} ` khi `depth === 0`.
 */
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

/**
 * Thuật toán: Chuẩn Hóa Trường Giấy Phép Đa Định Dạng Trong `package.json` (`license` chuỗi/đối tượng hoặc mảng `licenses`).
 */
function extractLicenseField(pkgContent) {
  const lic = pkgContent.license;
  if (typeof lic === 'string' && lic.trim()) return lic.trim();
  if (lic && typeof lic === 'object' && typeof lic.type === 'string' && lic.type.trim()) {
    return lic.type.trim();
  }
  if (Array.isArray(pkgContent.licenses) && pkgContent.licenses.length > 0) {
    const types = pkgContent.licenses
      .map((entry) => (typeof entry === 'string' ? entry.trim() : entry?.type?.trim()))
      .filter(Boolean);
    if (types.length === 1) return types[0];
    if (types.length > 1) return `(${types.join(' OR ')})`;
  }
  return null;
}

/**
 * Thuật toán: Dò Ngược Cây Thư Mục Từ Điểm Nhập Module Đến `package.json` Chứa Đúng Tên Gói (`findEnclosingPackageJson`)
 * Xử lý các gói ESM hiện đại có trường `"exports"` không công bố `./package.json`.
 */
async function findEnclosingPackageJson(entryFilePath, expectedName) {
  let currentDir = path.dirname(entryFilePath);
  for (let depth = 0; depth < 10; depth++) {
    const candidate = path.join(currentDir, 'package.json');
    if (existsSync(candidate)) {
      try {
        const parsed = JSON.parse(await readFile(candidate, 'utf-8'));
        if (parsed.name === expectedName) {
          return { pkgJsonPath: candidate, pkgContent: parsed };
        }
      } catch {
        // Ignore unreadable intermediate package.json
      }
    }
    const parentDir = path.dirname(currentDir);
    if (parentDir === currentDir) break;
    currentDir = parentDir;
  }
  return null;
}

/**
 * Thuật toán: Phân Giải Đường Dẫn `package.json` Thực Tế Của Phụ Thuộc Trực Tiếp Hoặc Bắc Cầu
 * Qua `createRequire`, Thư Mục Đồng Cấp `.pnpm` Và Kho Ảo `node_modules/.pnpm` (`resolveDependencyPackage`).
 */
async function resolveDependencyPackage(depName, consumerPkgPaths, pnpmStoreEntries) {
  for (const consumerPkgPath of consumerPkgPaths) {
    if (!consumerPkgPath || !existsSync(consumerPkgPath)) continue;
    const req = createRequire(consumerPkgPath);

    try {
      const resolvedPkgJson = req.resolve(`${depName}/package.json`);
      const pkgContent = JSON.parse(await readFile(resolvedPkgJson, 'utf-8'));
      return { pkgJsonPath: resolvedPkgJson, pkgContent };
    } catch {
      // Exports map may block ./package.json; try main entry resolution next
    }

    try {
      const resolvedEntry = req.resolve(depName);
      const found = await findEnclosingPackageJson(resolvedEntry, depName);
      if (found) return found;
    } catch {
      // Package may have no main export (e.g., CSS/types/CLI-only); walk ancestor node_modules
    }

    let walkDir = path.dirname(consumerPkgPath);
    for (let up = 0; up < 6; up++) {
      const candidate = path.join(walkDir, 'node_modules', depName, 'package.json');
      if (existsSync(candidate)) {
        try {
          const pkgContent = JSON.parse(await readFile(candidate, 'utf-8'));
          return { pkgJsonPath: candidate, pkgContent };
        } catch {
          // Continue walking upward
        }
      }
      const parent = path.dirname(walkDir);
      if (parent === walkDir) break;
      walkDir = parent;
    }
  }

  if (pnpmStoreEntries.length > 0) {
    const normalizedPrefix = `${depName.replace('/', '+')}@`;
    const match = pnpmStoreEntries.find((entry) => entry.startsWith(normalizedPrefix));
    if (match) {
      const storePkgJson = path.join(
        rootDir,
        'node_modules',
        '.pnpm',
        match,
        'node_modules',
        depName,
        'package.json',
      );
      if (existsSync(storePkgJson)) {
        try {
          const pkgContent = JSON.parse(await readFile(storePkgJson, 'utf-8'));
          return { pkgJsonPath: storePkgJson, pkgContent };
        } catch {
          // Fall through to null
        }
      }
    }
  }

  return null;
}

/**
 * Thuật toán: Duyệt Chiều Rộng Có Tập Chống Chu Trình Toàn Bộ Đồ Thị Phụ Thuộc Runtime & Xuất CycloneDX 1.5 SBOM.
 */
async function main() {
  console.log('='.repeat(78));
  console.log('SDA TRANSITIVE SOFTWARE BILL OF MATERIALS (SBOM) & LICENSE AUDIT');
  console.log('='.repeat(78));

  const pnpmStoreDir = path.join(rootDir, 'node_modules', '.pnpm');
  const pnpmStoreEntries = existsSync(pnpmStoreDir) ? await readdir(pnpmStoreDir) : [];

  const queue = [];
  const visitedRealPaths = new Set();
  const auditedComponents = new Map();

  for (const pkgPath of PACKAGE_JSON_PATHS) {
    if (!existsSync(pkgPath)) continue;
    const pkg = JSON.parse(await readFile(pkgPath, 'utf-8'));
    const deps = pkg.dependencies ?? {};
    for (const [depName, versionSpec] of Object.entries(deps)) {
      if (depName.startsWith('@sda/')) continue;
      queue.push({ depName, versionSpec: String(versionSpec), resolverPath: pkgPath });
    }
  }

  while (queue.length > 0) {
    const { depName, versionSpec, resolverPath } = queue.shift();
    if (depName.startsWith('@sda/')) continue;

    const resolved = await resolveDependencyPackage(
      depName,
      [resolverPath, ...PACKAGE_JSON_PATHS],
      pnpmStoreEntries,
    );

    if (!resolved) {
      const fallbackKey = `${depName}@${versionSpec.replace(/^[\^~]/, '')}`;
      if (!auditedComponents.has(fallbackKey)) {
        auditedComponents.set(fallbackKey, {
          name: depName,
          version: versionSpec.replace(/^[\^~]/, ''),
          license: 'UNKNOWN',
          isPermissive: false,
        });
      }
      continue;
    }

    const canonicalPkgPath = await realpath(resolved.pkgJsonPath).catch(() => resolved.pkgJsonPath);
    if (visitedRealPaths.has(canonicalPkgPath)) {
      continue;
    }
    visitedRealPaths.add(canonicalPkgPath);

    const { pkgContent } = resolved;
    const resolvedName = typeof pkgContent.name === 'string' ? pkgContent.name : depName;
    const resolvedVersion =
      typeof pkgContent.version === 'string'
        ? pkgContent.version
        : versionSpec.replace(/^[\^~]/, '');
    const componentKey = `${resolvedName}@${resolvedVersion}`;

    if (!auditedComponents.has(componentKey)) {
      const license =
        extractLicenseField(pkgContent) ??
        VERIFIED_LEGACY_PACKAGE_LICENSES.get(componentKey) ??
        'UNKNOWN';
      const isPermissive = isPermissiveSpdxExpression(license);
      auditedComponents.set(componentKey, {
        name: resolvedName,
        version: resolvedVersion,
        license,
        isPermissive,
      });
    }

    const childDeps = pkgContent.dependencies ?? {};
    for (const [childName, childVersionSpec] of Object.entries(childDeps)) {
      if (childName.startsWith('@sda/')) continue;
      queue.push({
        depName: childName,
        versionSpec: String(childVersionSpec),
        resolverPath: canonicalPkgPath,
      });
    }
  }

  const sbomComponents = [...auditedComponents.values()].sort((a, b) =>
    a.name === b.name ? a.version.localeCompare(b.version) : a.name.localeCompare(b.name),
  );

  let violations = 0;
  for (const comp of sbomComponents) {
    if (!comp.isPermissive) {
      console.error(
        `[VIOLATION] Disallowed or unknown license for ${comp.name}@${comp.version}: ${comp.license}`,
      );
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

  console.log(
    `Audited ${sbomComponents.length} direct + transitive production runtime dependencies:`,
  );
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
      '\nSUCCESS: 100% DIRECT & TRANSITIVE DEPENDENCIES HAVE VERIFIED PERMISSIVE LICENSES.',
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
