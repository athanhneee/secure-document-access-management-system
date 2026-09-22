import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import './globals.css';

export const metadata: Metadata = {
  title: 'Secure Document | Không gian tài liệu nội bộ',
  description: 'Hệ thống quản lý truy cập tài liệu mật trong tổ chức. Nền tảng đang được khởi tạo.',
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="vi">
      <body>{children}</body>
    </html>
  );
}
