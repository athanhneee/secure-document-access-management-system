import type { Metadata } from 'next';
import { OwnerWorkspace } from './owner-workspace';

export const metadata: Metadata = {
  title: 'Chủ sở hữu tài liệu | SecureDocument',
  description:
    'Không gian quản lý tài liệu, phân loại mức độ mật, phê duyệt yêu cầu và quản lý quyền truy cập.',
  robots: { index: false, follow: false },
};

export default function OwnerPage() {
  return <OwnerWorkspace />;
}
