import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import localFont from 'next/font/local';
import { AuthProvider } from '@/lib/auth-context';
import './globals.css';

const airbnbCereal = localFont({
  src: [
    { path: './fonts/AirbnbCereal_W_Lt.otf', weight: '300', style: 'normal' },
    { path: './fonts/AirbnbCereal_W_Bk.otf', weight: '400', style: 'normal' },
    { path: './fonts/AirbnbCereal_W_Md.otf', weight: '500', style: 'normal' },
    { path: './fonts/AirbnbCereal_W_Bd.otf', weight: '700', style: 'normal' },
    { path: './fonts/AirbnbCereal_W_XBd.otf', weight: '800', style: 'normal' },
    { path: './fonts/AirbnbCereal_W_Blk.otf', weight: '900', style: 'normal' },
  ],
  variable: '--font-cereal',
  fallback: [
    'system-ui',
    '-apple-system',
    'BlinkMacSystemFont',
    'Segoe UI',
    'Roboto',
    'sans-serif',
  ],
  display: 'swap',
});

export const metadata: Metadata = {
  title: 'Secure Document | Hệ thống quản lý truy cập tài liệu mật',
  description:
    'Hệ thống quản lý truy cập tài liệu mật trong tổ chức. Quyền tối thiểu, phân tách trách nhiệm và kiểm toán toàn vẹn.',
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="vi" className={`dark ${airbnbCereal.variable}`}>
      <body
        className={`min-h-screen bg-slate-950 font-sans text-slate-100 antialiased ${airbnbCereal.className}`}
      >
        <AuthProvider>{children}</AuthProvider>
      </body>
    </html>
  );
}
