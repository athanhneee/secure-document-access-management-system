# Design System Master File

<!-- // CONFLICT-RESOLVED: Phẳng hóa cấu trúc thư mục từ design-system/secure-document-access-system/MASTER.md về design-system/MASTER.md để loại bỏ lặp tên dự án cha (tuân thủ rule.md Mục 6), đồng thời đồng bộ hoàn toàn theo chuẩn thiết kế sản xuất tại rules/ui-design-system.md và apps/web/app/globals.css (font Inter hỗ trợ tiếng Việt, màu thương hiệu #FF385C, chữ #222222/#717171, nút pill 40px/9999px, badge phẳng staff-001, icon lucide-react). -->

> **CANONICAL SOURCE:** Tài liệu này được đồng bộ 100% với [`rules/ui-design-system.md`](../rules/ui-design-system.md) và [`apps/web/app/globals.css`](../apps/web/app/globals.css).
> Khi xây dựng trang cụ thể, kiểm tra `design-system/pages/[page-name].md` (nếu có) nhưng không được vi phạm các quy tắc cốt lõi của `rules/ui-design-system.md`.

---

**Project:** Secure Document Access System  
**Category:** Enterprise Security Governance & Zero-Trust Document Platform  
**Design Dials:** Variance 3/10 (Clean / Minimal) | Motion 2/10 (Subtle) | Density 8/10 (Focused / Workspace)

---

## Global Rules

### Color Palette (Light Theme)

| Role                        | Hex / RGB                        | CSS Variable                                    |
| --------------------------- | -------------------------------- | ----------------------------------------------- |
| Brand Accent / Primary      | `#FF385C`                        | `--color-primary` / `--accent-brand`            |
| On Primary                  | `#FFFFFF`                        | `--color-primary-foreground`                    |
| Primary Text (Foreground)   | `#222222` (`rgb(34, 34, 34)`)    | `--color-foreground` / `--text-primary`         |
| Secondary Text              | `#717171` (`rgb(113, 113, 113)`) | `--color-muted-foreground` / `--text-secondary` |
| Muted / Tertiary Text       | `#B0B0B0`                        | `--text-muted`                                  |
| Page Background             | `#FFFFFF`                        | `--color-background` / `--bg-primary`           |
| Secondary Surface / Hover   | `#F7F7F7`                        | `--color-muted` / `--bg-secondary`              |
| Subtle Border               | `#EBEBEB`                        | `--color-border` / `--border-subtle`            |
| Input / Default Border      | `#DDDDDD`                        | `--border-default`                              |
| Status Success              | `#008A05`                        | `--status-success`                              |
| Status Warning              | `#E07912`                        | `--status-warning`                              |
| Status Danger / Destructive | `#C13515`                        | `--status-danger`                               |
| Status Info                 | `#008489`                        | `--status-info`                                 |
| Status Neutral              | `#717171`                        | `--status-neutral`                              |

### Typography & Vietnamese Support

- **Single System Font:** `Inter` (cho toàn bộ tiêu đề `h1`–`h6`, nội dung, bảng biểu, nút bấm, biểu mẫu và hộp thoại).
- **Mandatory Next.js Loader (`next/font/google`):**
  ```ts
  // CONFLICT-RESOLVED: Chốt dùng duy nhất font Inter có subsets tiếng Việt theo rules/ui-design-system.md để chống lỗi nhảy font (Glyph Fallback).
  export const inter = Inter({
    subsets: ['vietnamese', 'latin', 'latin-ext'],
    weight: ['300', '400', '500', '600', '700', '800', '900'],
    display: 'swap',
    variable: '--font-inter',
  });
  ```
- **CSS Variables:** Cả `--font-sans` và `--font-display` đều trỏ về `var(--font-inter), 'Inter', system-ui, -apple-system, sans-serif`.
- **Prohibition:** Nghiêm cấm dùng font cục bộ `.otf`/`.ttf` thiếu bảng mã tiếng Việt gây hiện tượng lệch nét dấu tiếng Việt.

### Iconography (`lucide-react` Only)

- **Library:** Dùng duy nhất `lucide-react` trên toàn dự án.
- **Standard Sizes:** `16px` (inline, bảng, badge), `20px` (mặc định), `24px` (header/tiêu đề lớn — tối đa 24px).
- **Stroke Width & Color:** `strokeWidth={1.75}` hoặc `strokeWidth={2}`, màu `currentColor` kế thừa từ chữ cha.

### Spacing Variables

| Token         | Value              | Usage                                       |
| ------------- | ------------------ | ------------------------------------------- |
| `--space-xs`  | `2px` / `0.125rem` | Khoảng cách hẹp nội dòng                    |
| `--space-sm`  | `4px` / `0.25rem`  | Khoảng cách giữa icon và nhãn (`staff-001`) |
| `--space-md`  | `8px` / `0.5rem`   | Đệm tiêu chuẩn nhỏ                          |
| `--space-lg`  | `12px` / `0.75rem` | Đệm thành phần trung bình                   |
| `--space-xl`  | `16px` / `1rem`    | Khoảng cách khối                            |
| `--space-2xl` | `24px` / `1.5rem`  | Đệm thẻ và vùng làm việc                    |
| `--space-3xl` | `32px` / `2rem`    | Đệm vùng tiêu đề trang                      |

---

## Component Specs

### Buttons (Pill / Capsule Geometry)

```css
/* // CONFLICT-RESOLVED: Chốt đồng bộ nút bấm chuẩn pill 40px/9999px và màu thương hiệu #FF385C theo rules/ui-design-system.md. */
.btn-primary {
  background: radial-gradient(circle, rgb(255, 56, 92) 0%, rgb(227, 28, 95) 100%);
  color: #ffffff;
  padding: 10px 20px;
  border: none;
  border-radius: 40px;
  font-weight: 600;
  transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
  cursor: pointer;
}

.btn-secondary {
  background: #ffffff;
  color: #222222;
  border: 1px solid #dddddd;
  padding: 10px 20px;
  border-radius: 40px;
  font-weight: 600;
  transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
  cursor: pointer;
}
```

### Badges & Status Indicators (`staff-001` Flat Pattern)

```css
/* Flat text + icon/dot only — nghiêm cấm đóng hộp nền pastel hay bo viền capsule */
.staff-badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  background: transparent !important;
  border: none !important;
  padding: 0;
  font-weight: 600;
}
```

### Cards & Inputs

```css
.card {
  background: #ffffff;
  border: 1px solid #ebebeb;
  border-radius: 16px;
  padding: 24px;
  transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
}

.card:hover {
  background: #f7f7f7;
}

.input {
  padding: 10px 14px;
  border: 1px solid #dddddd;
  border-radius: 12px;
  color: #222222;
  background: #ffffff;
  font-size: 14px;
  transition: border-color 0.2s cubic-bezier(0.16, 1, 0.3, 1);
}

.input:focus {
  border-color: #222222;
  outline: none;
}
```

---

## Anti-Patterns (Do NOT Use)

- ❌ Dùng font khác ngoài `Inter` hoặc thiếu `subsets: ['vietnamese']`.
- ❌ Đóng hộp nền màu nhạt + viền bo tròn cho badge/tag trạng thái (vi phạm chuẩn phẳng `staff-001`).
- ❌ Dùng Emoji hoặc thư viện icon khác ngoài `lucide-react`, hoặc tô nền/gradient trên icon.
- ❌ Bỏ sót `cursor: pointer` hoặc trạng thái `:focus-visible` cho điều hướng bàn phím.
- ❌ Bỏ qua `@media (prefers-reduced-motion: reduce)` đối với chuyển động giao diện.
- ❌ Render `<dialog open>` phi phương thức thay vì gọi `.showModal()` kèm bẫy tiêu điểm bàn phím và phím `Escape`.
- ❌ Dùng hộp thoại trình duyệt thô `window.confirm` / `window.alert`, bỏ sót `htmlFor`/`id` trên `<label>` hoặc thiếu `aria-label` trên nút chỉ có icon.

---

## Pre-Delivery Checklist

- [ ] Tiếng Việt hiển thị đồng nhất 100% bằng `Inter`, không bị nhảy font dấu tiếng Việt.
- [ ] Mọi icon lấy từ `lucide-react` (`16px`–`24px`, `strokeWidth={1.75}`, `currentColor`).
- [ ] Badge/trạng thái tuân thủ mẫu phẳng `staff-001` (`background: transparent`, `border: none`, `padding: 0`).
- [ ] Nút bấm bo tròn chuẩn pill (`40px` / `9999px`) với màu nhấn `#FF385C` và chữ chính `#222222`.
- [ ] Tương phản chữ đạt tối thiểu WCAG AA (`4.5:1`) và hỗ trợ đầy đủ responsive `375px`–`1440px`.
