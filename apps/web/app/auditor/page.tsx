import type { Metadata } from 'next';
import { AuditorWorkspace } from './auditor-workspace';

export const metadata: Metadata = {
  title: 'Kiểm toán độc lập | Secure Document',
  description:
    'Nhật ký kiểm toán toàn vẹn, xác minh chuỗi băm HMAC-SHA256 và xuất báo cáo tuân thủ ở chế độ chỉ đọc.',
  robots: { index: false, follow: false },
};

export default function AuditorPage() {
  return <AuditorWorkspace />;
}
