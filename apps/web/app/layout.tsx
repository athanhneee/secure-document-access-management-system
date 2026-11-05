import type { Metadata, Viewport } from 'next';
import type { ReactNode } from 'react';
import { headers } from 'next/headers';
import { Inter } from 'next/font/google';
import { AuthProvider } from '@/lib/auth-context';
import './globals.css';

export const inter = Inter({
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
    <html lang="vi" className={`${inter.variable}`} data-csp-nonce={nonce ? 'active' : undefined}>
      <body
        className={`${inter.className} min-h-screen bg-[#ffffff] font-sans text-[#222222] antialiased selection:bg-[#FF385C]/20 selection:text-[#FF385C]`}
      >
        <AuthProvider>{children}</AuthProvider>
      </body>
    </html>
  );
}
