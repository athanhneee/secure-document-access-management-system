import type { Metadata } from 'next';
import { SecurityWorkspace } from './security-workspace';

export const metadata: Metadata = {
  title: 'An ninh thông tin | Secure Document',
  description:
    'Hàng đợi cảnh báo an ninh, điều tra watermark, báo cáo sự cố và giám sát bất thường.',
  robots: { index: false, follow: false },
};

export default function SecurityPage() {
  return <SecurityWorkspace />;
}
