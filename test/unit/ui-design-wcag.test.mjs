import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../..');
const webRoot = path.join(repoRoot, 'apps/web');

/**
 * Thuật toán: Duyệt Đệ quy Cây Mã nguồn Giao diện & Khử Nhiễu Chú thích Bảo toàn Số Dòng (`collectWebSourceFiles`, `stripCommentsPreservingLines`)
 * Mục đích: Quét toàn bộ tệp `.ts`, `.tsx`, `.css` trong `apps/web` (bỏ qua `node_modules`, `.next`, `dist`) và xóa nội dung chú thích mà vẫn giữ nguyên ký tự xuống dòng `\n` để báo cáo chính xác `file:line` khi kiểm toán chuẩn `rules/ui-design-system.md` và WCAG 2.1 AA.
 * Cơ chế hoạt động:
 *   - Duyệt chiều sâu thư mục trong thời gian tuyến tính `O(V)` theo tổng số nút tệp/thư mục `V`.
 *   - Thay thế mọi khối chú thích `/* ... * /` và dòng chú thích `// ...` bằng khoảng trắng có cùng số dòng mới.
 */
function collectWebSourceFiles(dir) {
  const results = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === '.next' || entry.name === 'dist') {
      continue;
    }
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...collectWebSourceFiles(fullPath));
    } else if (/\.(?:tsx?|css)$/.test(entry.name)) {
      results.push(fullPath);
    }
  }
  return results;
}

function stripCommentsPreservingLines(source) {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, (block) => block.replace(/[^\r\n]/g, ' '))
    .replace(/^\s*\/\/.*$/gm, '');
}

const sourceFiles = collectWebSourceFiles(webRoot);

describe('Design System Authority Synchronization (ui-design-system.md vs MASTER.md)', () => {
  // CONFLICT-RESOLVED: Xóa bỏ cờ skip cục bộ sau khi .gitignore đã theo dõi tường minh rules/ui-design-system.md và design-system/MASTER.md trên CI.
  const uiSpecPath = path.join(repoRoot, 'rules/ui-design-system.md');
  const masterSpecPath = path.join(repoRoot, 'design-system/MASTER.md');

  it('synchronizes Inter font, #FF385C accent, pill buttons, and flat staff-001 badges across both specs', () => {
    assert.ok(fs.existsSync(uiSpecPath), 'rules/ui-design-system.md must exist in repository');
    assert.ok(fs.existsSync(masterSpecPath), 'design-system/MASTER.md must exist in repository');
    const uiSpec = fs.readFileSync(uiSpecPath, 'utf8');
    const masterSpec = fs.readFileSync(masterSpecPath, 'utf8');
    for (const doc of [uiSpec, masterSpec]) {
      assert.match(doc, /Inter/);
      assert.match(doc, /#FF385C/i);
      assert.match(doc, /staff-001/);
      assert.match(doc, /9999px|40px/);
    }
    assert.doesNotMatch(masterSpec, /Plus Jakarta Sans/i);
    assert.doesNotMatch(masterSpec, /#0369A1/i);
  });
});

describe('UI Design System & WCAG 2.1 AA Static Regression Gates', () => {
  it('enforces @media (prefers-reduced-motion: reduce) in globals.css and surfaces.css', () => {
    const globalsCss = fs.readFileSync(path.join(webRoot, 'app/globals.css'), 'utf8');
    const surfacesCss = fs.readFileSync(path.join(webRoot, 'app/styles/surfaces.css'), 'utf8');
    assert.match(globalsCss, /@media\s*\(\s*prefers-reduced-motion:\s*reduce\s*\)/);
    assert.match(surfacesCss, /@media\s*\(\s*prefers-reduced-motion:\s*reduce\s*\)/);
  });

  it('enforces true modal .showModal(), Escape handling, and Tab focus trap in dialog.tsx', () => {
    const dialogTsx = fs.readFileSync(path.join(webRoot, 'components/ui/dialog.tsx'), 'utf8');
    assert.match(dialogTsx, /\.showModal\(\)/);
    assert.match(dialogTsx, /onCancel=/);
    assert.match(dialogTsx, /\b(?:e|event)\.key\s*[!=]==\s*'Escape'/);
    assert.match(dialogTsx, /\b(?:e|event)\.key\s*[!=]==\s*'Tab'/);
    assert.doesNotMatch(dialogTsx, /<dialog\b[^>]*\bopen\b/);
  });

  it('forbids raw browser window.confirm / window.alert calls across apps/web', () => {
    const violations = [];
    for (const file of sourceFiles) {
      if (file.endsWith('.css')) continue;
      const rel = path.relative(webRoot, file).replaceAll('\\', '/');
      const lines = stripCommentsPreservingLines(fs.readFileSync(file, 'utf8')).split(/\r?\n/);
      lines.forEach((line, idx) => {
        if (/\b(?:window\.)?(?:confirm|alert)\s*\(/.test(line)) {
          violations.push(`${rel}:${idx + 1}`);
        }
      });
    }
    assert.deepEqual(violations, []);
  });

  it('forbids off-palette Tailwind utilities, off-palette hex codes, inline style={{}}, and raw <svg>', () => {
    // CONFLICT-RESOLVED: Siết chặt bảng màu chuẩn đúng 13 mã hex chính thức (loại bỏ #E0294C, #E0285F, #007004, #A32B0F, #eeeeee) và cấm thuộc tính style={{}} nội tuyến trong .tsx.
    const allowedHex = new Set([
      '#ffffff',
      '#f7f7f7',
      '#ebebeb',
      '#dddddd',
      '#222222',
      '#717171',
      '#b0b0b0',
      '#ff385c',
      '#e31c5f',
      '#008a05',
      '#e07912',
      '#c13515',
      '#008489',
    ]);
    const violations = [];
    const twRegex =
      /\b(?:text|bg|border|ring|from|to|via)-(?:slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)-\d{2,3}(?:\/\d+)?\b/g;

    for (const file of sourceFiles) {
      if (file.endsWith('.css')) continue;
      const isTsx = file.endsWith('.tsx');
      const rel = path.relative(webRoot, file).replaceAll('\\', '/');
      const lines = stripCommentsPreservingLines(fs.readFileSync(file, 'utf8')).split(/\r?\n/);
      lines.forEach((line, idx) => {
        if (twRegex.test(line)) {
          violations.push(`${rel}:${idx + 1} (off-palette tailwind)`);
        }
        twRegex.lastIndex = 0;
        if (/<svg\b/.test(line)) {
          violations.push(`${rel}:${idx + 1} (raw svg)`);
        }
        if (isTsx && /\bstyle=\{\{/.test(line)) {
          violations.push(`${rel}:${idx + 1} (inline style={{)`);
        }
        const hexMatches = line.match(/#[0-9a-fA-F]{3,8}\b/g) ?? [];
        for (const hex of hexMatches) {
          if (!allowedHex.has(hex.toLowerCase())) {
            violations.push(`${rel}:${idx + 1} (off-palette hex ${hex})`);
          }
        }
      });
    }
    assert.deepEqual(violations, []);
  });

  it('enforces Lucide icon scale {16 | 20 | 24}, strokeWidth {1.75 | 2}, and htmlFor on every <label>', () => {
    const violations = [];
    for (const file of sourceFiles) {
      if (!file.endsWith('.tsx')) continue;
      const rel = path.relative(webRoot, file).replaceAll('\\', '/');
      const content = stripCommentsPreservingLines(fs.readFileSync(file, 'utf8'));

      const lucideNames = new Set();
      for (const match of content.matchAll(/import\s*\{([^}]+)\}\s*from\s*['"]lucide-react['"]/g)) {
        for (const part of match[1].split(',')) {
          const cleaned = part.replace(/\btype\b/g, '').trim();
          if (!cleaned) continue;
          const alias = cleaned.split(/\s+as\s+/);
          lucideNames.add((alias[1] || alias[0]).trim());
        }
      }

      for (const tag of content.matchAll(/<([A-Z][A-Za-z0-9_]*)\b([^>]*?)\/?>/gs)) {
        const [, name, attrs] = tag;
        if (!lucideNames.has(name)) continue;
        const sizeOk = /\bsize=\{(?:16|20|24|iconPixelSize)\}/.test(attrs);
        const strokeOk = /\bstrokeWidth=\{(?:1\.75|2)\}/.test(attrs);
        const badHw = /\b(?:h|w)-(?:2\.5|3|3\.5|7|8|9|10|11|12)\b/.test(attrs);
        if (!sizeOk || !strokeOk || badHw) {
          const ln = content.slice(0, tag.index).split(/\r?\n/).length;
          violations.push(`${rel}:${ln} (<${name}>)`);
        }
      }

      for (const labelTag of content.matchAll(/<label\b([^>]*)>/g)) {
        if (!/\bhtmlFor=/.test(labelTag[1])) {
          const ln = content.slice(0, labelTag.index).split(/\r?\n/).length;
          violations.push(`${rel}:${ln} (<label> missing htmlFor)`);
        }
      }
    }
    assert.deepEqual(violations, []);
  });
});
