import type { Metadata, Viewport } from 'next';
import type { ReactNode } from 'react';
import { headers } from 'next/headers';
import { Inter } from 'next/font/google';
import { AuthProvider } from '@/lib/auth-context';
import './globals.css';

/**
 * Thuật toán: Khởi Tạo Biến Phông Chữ Inter Tiếng Việt & Đồng Bộ Mã Nonce CSP Trên Khung Gốc (`RootLayout`)
 * Mục đích:
 *   - Nạp duy nhất họ phông `Inter` hỗ trợ đầy đủ bảng mã `vietnamese` tránh lỗi nhảy glyph, đồng thời đọc `x-nonce` từ `proxy.ts` để kích hoạt ngữ cảnh bảo mật nội dung theo từng yêu cầu.
 *   - Bật `suppressHydrationWarning` đúng 1 cấp trên thẻ gốc `<html>` và `<body>` (theo chuẩn Next.js App Router) nhằm miễn nhiễm lỗi lệch Hydration khi tiện ích mở rộng trình duyệt (như từ điển/dịch trang tự chèn `data-yd-metadata-content-site`) can thiệp thuộc tính DOM trước thời điểm React hydrate, nhưng vẫn giữ nguyên kiểm tra Hydration cho toàn bộ cây con bên trong.
 */
const inter = Inter({
  subsets: ['vietnamese', 'latin', 'latin-ext'],
  weight: ['300', '400', '500', '600', '700', '800', '900'],
  display: 'swap',
  variable: '--font-inter',
});

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  maximumScale: 5,
  themeColor: '#ffffff',
};

export const metadata: Metadata = {
  title: 'Secure Document | Hệ thống quản lý truy cập tài liệu mật',
  description:
    'Hệ thống quản lý truy cập tài liệu mật trong tổ chức. Quyền tối thiểu, phân tách trách nhiệm và kiểm toán toàn vẹn.',
  robots: { index: false, follow: false },
};

export default async function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  const nonce = (await headers()).get('x-nonce') ?? undefined;
  return (
    <html
      lang="vi"
      suppressHydrationWarning
      className={`${inter.variable}`}
      data-csp-nonce={nonce ? 'active' : undefined}
    >
      <body
        suppressHydrationWarning
        className={`${inter.className} min-h-screen bg-[#ffffff] font-sans text-[#222222] antialiased selection:bg-[#FF385C]/20 selection:text-[#E31C5F]`}
      >
        <AuthProvider>{children}</AuthProvider>
      </body>
    </html>
  );
}
