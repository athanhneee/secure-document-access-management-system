# UI & FRONTEND DESIGN SYSTEM RULES (BẮT BUỘC TUÂN THỦ)

<!-- // CONFLICT-RESOLVED: Giữ rules/ui-design-system.md làm chuẩn thiết kế giao diện duy nhất (Inter hỗ trợ tiếng Việt, #FF385C, nút pill 40px/9999px, badge phẳng staff-001) và đồng bộ ngược sang design-system/MASTER.md để triệt tiêu xung đột đặc tả UI. -->

> **Dành cho tất cả Lập trình viên và AI Assistants (Antigravity, Cursor, Copilot, Claude Code, Gemini)**:  
> Đây là quy chuẩn thiết kế giao diện tối cao của dự án. Mọi thay đổi, thêm mới trang, component hoặc chỉnh sửa CSS/TSX đều **PHẢI TUÂN THỦ TUYỆT ĐỐI** các quy tắc dưới đây. Không tự ý sáng tạo phá vỡ phong cách này.

---

## 1. TYPOGRAPHY & TIẾNG VIỆT (NGHIÊM CẤM LỖI FONT)

### Quy tắc cốt lõi:

- **Font duy nhất cho toàn bộ hệ thống là INTER**:
  - Toàn bộ nội dung: body, tiêu đề (`h1`, `h2`, `h3`), bảng biểu, form, nút bấm, modal, menu đều sử dụng **Inter**.
  - Font `Inter` bắt buộc phải được import qua `next/font/google` với đầy đủ cấu hình:
    ```ts
    export const inter = Inter({
      subsets: ['vietnamese', 'latin', 'latin-ext'],
      weight: ['300', '400', '500', '600', '700', '800', '900'],
      display: 'swap',
      variable: '--font-inter',
    });
    ```
- **CẤM TUYỆT ĐỐI**:
  - **Không** sử dụng font cục bộ (`.otf` / `.ttf`) chỉ hỗ trợ bộ mã Latin cơ bản (như bản gốc của Airbnb Cereal hay SF Pro không có dấu tiếng Việt).
  - Khi render tiếng Việt (ví dụ: `Hộp thư hỗ trợ`, `Người tham dự`), font thiếu bảng mã tiếng Việt sẽ bị hiện tượng **Glyph Fallback** (ký tự không dấu hiển thị 1 font, ký tự có dấu như `ộ, ư, ỗ, ợ, đ` nhảy sang Arial/Segoe UI, gây ra lỗi chữ đậm chữ nhạt, dấu ngã méo mó).
  - Cả `--font-sans` và `--font-display` trong CSS đều phải trỏ về `var(--font-inter), "Inter", ...`.

---

## 2. ICON SYSTEM (HỆ THỐNG BIỂU TƯỢNG)

### Thư viện mặc định:

- Dùng **`lucide-react`** làm thư viện icon duy nhất cho toàn dự án.

### Quy chuẩn kích thước & nét vẽ:

- **Kích thước chuẩn**:
  - Mặc định: `size={20}`
  - Trong dòng chữ, thẻ nhỏ, action bảng: `size={16}`
  - Tiêu đề lớn, Hero, Header icon: `size={24}` (tối đa 24px)
- **Độ dày nét (Stroke width)**: `strokeWidth={1.75}` hoặc `strokeWidth={2}`.
- **Màu sắc**: Luôn sử dụng `color="currentColor"` hoặc kế thừa màu của chữ cha.

### Điều cấm kỵ (STRICT PROHIBITIONS):

- ❌ **Không** dùng màu gradient trên icon.
- ❌ **Không** dùng Emoji thay cho icon.
- ❌ **Không** dùng hình vẽ minh họa (illustrations) làm icon.
- ❌ **Không** tô màu nền nhạt (pastel background) hay bọc icon trong ô vuông bo tròn to quá khổ.
- ❌ **Không** nhúng SVG tùy tiện, không vẽ icon thủ công lộn xộn.
- ❌ **Không** trộn lẫn các thư viện khác (FontAwesome, Material Icons, Feather...).
- ❌ **Không** dùng icon chỉ để trang trí vô nghĩa; icon phải truyền đạt thông tin chức năng rõ ràng.
- 💡 **Nguyên lý**: _Icon phải cư xử về mặt thị giác như một ký tự Typography, không phải tranh ảnh._

---

## 3. BADGE, TAG & TRẠNG THÁI (PHONG CÁCH "STAFF-001")

### Quy tắc cốt lõi:

- ❌ **TUYỆT ĐỐI KHÔNG ĐÓNG HỘP BO VIỀN (NO CAPSULE / PILL BOXES)**:
  - Không dùng kiểu bo viền tròn màu nền nhạt (`background: rgba(..., 0.08)` + `border: 1px solid rgba(..., 0.2)`). Kiểu đóng hộp này làm giao diện bị cộm, nặng nề và lỗi thời.
- ✅ **PHONG CÁCH CHỈ TÔ MÀU CHỮ & ICON (THE "staff-001" PATTERN)**:
  - `background: transparent !important;` (hoàn toàn không có màu nền).
  - `border: none !important;` (không có viền bo ngoài).
  - `padding: 0;` (không có khoảng đệm thừa).
  - **Chỉ tô màu chữ và icon / dot**.

### Cách áp dụng thực tế:

#### A. Đối với Định danh / Kênh truyền thông (Identity / Channels):

Hiển thị dạng `inline-flex` gồm: **Icon 16px + Tên có màu tương ứng**, không viền, không nền:

```tsx
/* Ví dụ: Nhân viên phụ trách (staff-001) */
<span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, color: 'var(--accent-primary)', fontSize: 'var(--text-xs)', fontWeight: 500 }}>
  <UserIcon size={16} />
  <span>staff-001</span>
</span>

/* Ví dụ: Kênh Email */
<span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, color: 'var(--accent-info)', fontSize: 'var(--text-xs)', fontWeight: 600 }}>
  <MailIcon size={16} />
  <span>EMAIL</span>
</span>

/* Ví dụ: Kênh SMS */
<span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, color: 'var(--accent-warning)', fontSize: 'var(--text-xs)', fontWeight: 600 }}>
  <SmartphoneIcon size={16} />
  <span>SMS</span>
</span>
```

#### B. Đối với Trạng thái (Statuses - Checked In, Open, Failed...):

Hiển thị dạng **Chấm tròn 6px (`.dot`) + Chữ in đậm cùng màu**:

- `success`: Xanh lá `#008A05`
- `warning`: Cam `#E07912`
- `danger`: Đỏ `#C13515`
- `info`: Xanh mòng két `#008489`
- `primary`: Hồng đỏ `#FF385C`
- `neutral`: Xám `#717171`

```tsx
/* Sử dụng component Badge chuẩn (đã được cấu hình phẳng, không viền, không nền): */
<AttendanceStatusBadge status="CHECKED_IN" />
<SupportStatusBadge status="OPEN" />
```

---

## 4. COLOR PALETTE & LIGHT THEME

- **Văn bản chính (Primary Text)**: `rgb(34, 34, 34)` (`#222222`).
- **Văn bản phụ (Secondary Text)**: `rgb(113, 113, 113)` (`#717171`).
- **Văn bản làm mờ (Muted/Tertiary Text)**: `#b0b0b0`.
- **Màu nhấn thương hiệu (Accent Brand)**: `#FF385C` (Airbnb Coral / Red-Pink).
- **Màu nền (Backgrounds)**:
  - Trang chính: `#ffffff`
  - Bề mặt phụ / Card hover: `#f7f7f7`
- **Đường kẻ phân cách (Borders)**: Mảnh tinh tế `1px solid #ebebeb` hoặc `#dddddd`.

---

## 5. BUTTONS & INTERACTIVE ELEMENTS

- **Bo góc nút bấm**: `border-radius: 40px` (hoặc `9999px`) tạo cảm giác mềm mại cao cấp.
- **Nút Primary**: Nền gradient tròn `radial-gradient(circle, rgb(255, 56, 92) 0%, rgb(227, 28, 95) 100%)` hoặc `#FF385C`, chữ trắng, không viền.
- **Nút Outline / Secondary**: Nền trắng hoặc trong suốt, viền mỏng `1px solid #222222` hoặc `#dddddd`, chữ đen/xám đậm.
- **Hiệu ứng hover**: Chuyển đổi mượt `transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1)`.

---

## 6. ACCESSIBILITY (WCAG 2.1 AA) & UX INTERACTION RULES

- **Chuyển động an toàn (`prefers-reduced-motion`)**: Bắt buộc khai báo `@media (prefers-reduced-motion: reduce)` trong `globals.css` để tắt `scroll-behavior: smooth`, đưa `animation-duration` / `transition-duration` về tối thiểu và dừng các hiệu ứng lặp vô hạn.
- **Hộp thoại phương thức chuẩn (`<dialog>` `.showModal()`)**: Mọi modal bắt buộc kích hoạt qua `.showModal()`, bẫy tiêu điểm bàn phím (`Tab` / `Shift+Tab`), đóng khi nhấn `Escape` (`cancel` event), hoàn trả tiêu điểm khi đóng và gắn `aria-labelledby` / `aria-describedby`.
- **Nghiêm cấm hộp thoại trình duyệt thô**: Tuyệt đối không gọi `window.confirm` hoặc `window.alert`; phải dùng thành phần `ConfirmDialog` hoặc `Alert` nội dòng.
- **Nhãn biểu mẫu & trợ năng bàn phím**: Mọi thẻ `<label>` phải liên kết tường minh `htmlFor` với `id` của trường nhập liệu; mọi nút bấm chỉ chứa icon bắt buộc có `aria-label` rõ nghĩa.

---

## 7. CHECKLIST KIỂM TRA TRƯỚC KHI COMMIT / HOÀN THÀNH

- [ ] Tiếng Việt hiển thị đồng nhất 100% bằng **Inter**, không có ký tự nào bị lệch nét hay nhảy font.
- [ ] Mọi icon đều lấy từ **`lucide-react`**, đúng thang kích thước `16px` / `20px` / `24px` (tối đa `24px`), có `strokeWidth={1.75 | 2}`, dùng `currentColor`, không bọc hộp nền màu/pastel.
- [ ] Không có badge nào có màu nền nhạt hay viền bo tròn capsule; tất cả status/kênh hiển thị phẳng theo mẫu `staff-001` với màu chữ và icon/dot tinh gọn.
- [ ] Mọi nút bấm tuân thủ bo tròn viên thuốc (`40px` / `9999px`), bảng màu chuẩn, hỗ trợ đầy đủ `prefers-reduced-motion`, modal `.showModal()`, không còn `window.confirm`/`window.alert`.
- [ ] Chạy `npm test` và `npm run build` không có bất kỳ lỗi biên dịch hay lint nào.
