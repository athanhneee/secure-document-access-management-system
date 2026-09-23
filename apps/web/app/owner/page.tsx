import type { Metadata } from 'next';
import { OwnerWorkspace } from './owner-workspace';

export const metadata: Metadata = {
  title: 'Chủ sở hữu tài liệu | Secure Document',
  description:
    'Không gian quản lý tài liệu, phân loại mật, duyệt yêu cầu và thu hồi quyền truy cập.',
  robots: { index: false, follow: false },
};

export default function OwnerPage() {
  return <OwnerWorkspace />;
}
