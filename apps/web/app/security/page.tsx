import { Suspense } from 'react';
import type { Metadata } from 'next';
import { SecurityWorkspace } from './security-workspace';

export const metadata: Metadata = {
  title: 'An ninh thông tin | SecureDocument',
  description:
    'Hàng đợi cảnh báo an ninh, truy vết watermark bảo mật, hồ sơ sự cố và giám sát hành vi bất thường.',
  robots: { index: false, follow: false },
};

export default function SecurityPage() {
  return (
    <Suspense fallback={null}>
      <SecurityWorkspace />
    </Suspense>
  );
}
