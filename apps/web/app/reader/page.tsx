import type { Metadata } from 'next';
import { ReaderWorkspace } from './reader-workspace';

export const metadata: Metadata = {
  title: 'Người đọc tài liệu | Secure Document',
  description:
    'Tra cứu danh mục tài liệu, gửi yêu cầu cấp quyền, xem trước an toàn và tải bản sao có watermark.',
  robots: { index: false, follow: false },
};

export default function ReaderPage() {
  return <ReaderWorkspace />;
}
