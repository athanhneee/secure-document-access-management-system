import { Suspense } from 'react';
import type { Metadata } from 'next';
import { ReaderWorkspace } from './reader-workspace';

export const metadata: Metadata = {
  title: 'Người đọc tài liệu | SecureDocument',
  description:
    'Tra cứu danh mục tài liệu, gửi yêu cầu quyền truy cập, xem trước an toàn và tải bản sao có watermark bảo mật.',
  robots: { index: false, follow: false },
};

export default function ReaderPage() {
  return (
    <Suspense fallback={null}>
      <ReaderWorkspace />
    </Suspense>
  );
}
