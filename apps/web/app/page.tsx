/**
 * Thuật toán: Bố Cục Trang Chủ Công Khai Tối Ưu Tải Tĩnh & Trợ Năng Bàn Phím (`HomePage`)
 * Mục đích: Kết xuất Server Component không chặn mạng kèm liên kết `skip-to-content`, điều hướng phân hệ vai trò thích ứng màn hình di động `375px` và tái sử dụng thống nhất `AppFooter` (`V-32`).
 */
import { AppFooter } from '@/components/navigation/app-footer';
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

      <AppFooter />
    </div>
  );
}
