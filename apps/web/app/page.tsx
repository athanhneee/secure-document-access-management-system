/**
 * Thuật toán: Bố Cục Trang Chủ Công Khai Tối Ưu Tải Tĩnh & Trợ Năng Bàn Phím (`HomePage`)
 * Mục đích: Kết xuất Server Component không chặn mạng kèm liên kết `skip-to-content` và điều hướng phân hệ vai trò thích ứng màn hình di động `375px`.
 */
import { HomeHeader } from '@/components/navigation/home-header';
import { HeroSection } from '@/components/landing/hero-section';
import { RolePortalsSection } from '@/components/landing/role-portals-section';
import { SecurityPillarsSection } from '@/components/landing/security-pillars-section';

export default function HomePage() {
  return (
    <div className="flex min-h-screen flex-col bg-[#ffffff] text-[#222222] antialiased selection:bg-[#FF385C]/15 selection:text-[#E31C5F]">
      <a href="#main-content" className="skip-to-content">
        Chuyển đến nội dung chính
      </a>

      <HomeHeader />

      <main id="main-content" className="flex-1">
        <HeroSection />
        <RolePortalsSection />
        <SecurityPillarsSection />
      </main>

      <footer className="border-t border-[#ebebeb] bg-[#ffffff] py-5">
        <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-2 px-4 text-xs text-[#717171] sm:flex-row sm:px-6 lg:px-8">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-[#222222]">
              Secure<span className="text-[#E31C5F]">Document</span>
            </span>
            <span className="text-[#ebebeb]">·</span>
            <span>Hệ thống quản lý tài liệu mật nội bộ</span>
          </div>
          <div className="flex flex-wrap items-center justify-center gap-x-2.5 gap-y-1">
            <span>© 2026 SecureDocument</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
