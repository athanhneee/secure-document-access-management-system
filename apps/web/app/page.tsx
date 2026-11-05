import { HomeHeader } from '@/components/navigation/home-header';
import { HeroSection } from '@/components/landing/hero-section';
import { RolePortalsSection } from '@/components/landing/role-portals-section';
import { SecurityPillarsSection } from '@/components/landing/security-pillars-section';

export default function HomePage() {
  return (
    <div className="flex min-h-screen flex-col bg-[#ffffff] text-[#222222] antialiased selection:bg-[#FF385C]/15 selection:text-[#FF385C]">
      <a href="#main-content" className="skip-to-content">
        Chuyển đến nội dung chính
      </a>

      <HomeHeader />

      <main id="main-content" className="flex-1">
        <HeroSection />
        <RolePortalsSection />
        <SecurityPillarsSection />
      </main>

      <footer className="border-t border-[#ebebeb] bg-[#ffffff] py-6 sm:py-10 pb-16 sm:pb-10">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col items-center sm:items-start md:flex-row md:items-start justify-between gap-4 sm:gap-6 text-center sm:text-left">
            <div className="space-y-1 sm:space-y-1.5 max-w-md">
              <div className="flex items-center justify-center sm:justify-start gap-2">
                <span className="text-xs font-bold tracking-tight text-[#222222]">
                  Secure<span className="text-[#FF385C]">Document</span> Access System
                </span>
                <span
                  className="staff-badge inline-flex items-center gap-1 text-[10px] font-bold text-[#008A05]"
                  style={{ background: 'transparent', border: 'none', padding: 0 }}
                >
                  <span className="dot dot-success" aria-hidden="true" />
                  <span>ONLINE</span>
                </span>
              </div>
              <p className="hidden sm:block text-xs text-[#717171] leading-relaxed">
                Nền tảng kiểm soát truy cập và bảo vệ tài liệu mật tổ chức theo kiến trúc Zero
                Trust, kiểm soát phân quyền tối thiểu (Least Privilege).
              </p>
            </div>

            <div className="flex flex-col items-center sm:items-start md:items-end gap-1.5 sm:gap-2 text-xs text-[#717171]">
              <div className="flex flex-wrap items-center justify-center sm:justify-start md:justify-end gap-x-2.5 sm:gap-x-3 gap-y-1 text-[11px]">
                <span>Enterprise v1.0</span>
                <span className="text-[#ebebeb]">·</span>
                <span>Bảo mật 2FA</span>
                <span className="text-[#ebebeb]">·</span>
                <span className="font-bold text-[#008A05]">STATUS: NORMAL</span>
              </div>
              <p className="hidden sm:block text-[10px] text-[#b0b0b0]">
                Mã hóa AES-256-GCM · Kiểm toán chuỗi bất biến HMAC-SHA256
              </p>
            </div>
          </div>

          <div className="mt-4 sm:mt-6 pt-4 sm:pt-6 border-t border-[#ebebeb] flex flex-col sm:flex-row items-center justify-between gap-1.5 sm:gap-2 text-[10px] sm:text-[11px] text-[#717171] text-center sm:text-left">
            <span>© 2026 Secure Document Access System.</span>
            <span className="hidden sm:inline text-[10px] text-[#717171]">
              Quyền tối thiểu · Trách nhiệm rõ ràng
            </span>
          </div>
        </div>
      </footer>
    </div>
  );
}
