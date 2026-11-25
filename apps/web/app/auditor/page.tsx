import type { Metadata } from 'next';
import { AuditorWorkspace } from './auditor-workspace';

export const metadata: Metadata = {
  title: 'Kiểm toán độc lập | SecureDocument',
  description:
    'Tra cứu nhật ký kiểm toán, kiểm tra tính toàn vẹn dữ liệu và xuất báo cáo tuân thủ ở chế độ chỉ đọc.',
  robots: { index: false, follow: false },
};

export default function AuditorPage() {
  return <AuditorWorkspace />;
}
