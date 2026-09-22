import type { Metadata } from 'next';
import { AdminWorkspace } from './workspace';

export const metadata: Metadata = {
  title: 'Quản trị truy cập | Secure Document',
  robots: { index: false, follow: false },
};

export default function AdminPage() {
  return <AdminWorkspace />;
}
