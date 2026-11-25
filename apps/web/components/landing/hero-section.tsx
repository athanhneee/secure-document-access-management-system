'use client';

/**
 * Thuật toán: Khu Vực Giới Thiệu Đầu Trang Nhận Thức Phiên Đăng Nhập & Lưới Chỉ Số Mật Mã (`HeroSection`)
 * Mục đích: Trình bày thông điệp cốt lõi Zero-Trust và định tuyến nút kêu gọi hành động chính trực tiếp vào phân hệ được cấp quyền khi người dùng đã xác thực.
 */
import { resolveDefaultPortalForRoles, useAuth } from '@/lib/auth-context';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';

const HERO_METRICS = [
  {
    label: 'Phân loại',
    value: '5 Cấp độ mật',
    subtext: 'Từ Không mật đến Tuyệt mật',
    delay: 'delay-100',
  },
  {
    label: 'Mã hóa',
    value: 'AES-256-GCM',
    subtext: 'Envelope Encryption per file',
    delay: 'delay-150',
  },
  {
    label: 'Kiểm toán',
    value: 'HMAC-SHA256',
    subtext: 'Chuỗi hash bất biến liên kết',
    delay: 'delay-200',
  },
  {
    label: 'Truy vết',
    value: 'Watermark động',
    subtext: 'Định danh người xem tức thì',
    delay: 'delay-250',
  },
] as const;

export function HeroSection() {
  const { isAuthenticated, user } = useAuth();
  const primaryHref = isAuthenticated ? resolveDefaultPortalForRoles(user?.roles) : '/login';
  const primaryText = isAuthenticated ? 'Vào phân hệ làm việc' : 'Bắt đầu ngay';

  return (
    <section className="relative border-b border-[#ebebeb] bg-linear-to-b from-[#ffffff] to-[#f7f7f7] py-8 sm:py-12 lg:py-14">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12 lg:items-center lg:gap-10">
          <div className="lg:col-span-7">
            <div className="inline-flex items-center gap-2 text-xs font-bold text-[#008489] mb-2.5 sm:mb-3 select-none animate-fade-in-down">
              <span className="dot dot-info animate-pulse-subtle" aria-hidden="true" />
              <span className="sm:hidden">BẢO MẬT ĐA TẦNG</span>
              <span className="hidden sm:inline">KIỂM SOÁT TRUY CẬP TÀI LIỆU MẬT TỔ CHỨC</span>
            </div>
            <h1 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold tracking-tight text-[#222222] leading-[1.2] text-balance animate-fade-in-up">
              <span className="sm:hidden">Kiểm soát &amp; Bảo vệ Tài liệu Tối mật</span>
              <span className="hidden sm:inline">
                Bảo vệ tài liệu tối mật với kiến trúc phân quyền đa tầng.
              </span>
            </h1>
            <p className="mt-2.5 sm:mt-3 text-xs sm:text-sm text-[#717171] leading-relaxed max-w-xl animate-fade-in-up delay-75">
              Phân quyền tối thiểu RBAC/ABAC, mã hóa phong bì số AES-256-GCM và kiểm toán chuỗi băm
              bất biến HMAC-SHA256.
            </p>

            <div className="mt-5 sm:mt-6 flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5 animate-fade-in-up delay-100">
              <InteractiveHoverButton
                href={primaryHref}
                variant="solid"
                text={primaryText}
                className="w-full sm:w-auto px-5"
              />
              <InteractiveHoverButton
                href="#vai-tro"
                variant="outline"
                text="Chọn phân hệ"
                className="w-full sm:w-auto px-5"
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-2.5 sm:gap-3 lg:col-span-5">
            {HERO_METRICS.map((metric) => (
              <div
                key={metric.label}
                className={`rounded-[16px] sm:rounded-[20px] border border-[#ebebeb] bg-[#ffffff] p-3.5 sm:p-4 shadow-[0_2px_10px_rgba(0,0,0,0.03)] hover-card animate-fade-in-up ${metric.delay}`}
              >
                <div className="text-[11px] font-semibold text-[#717171] uppercase tracking-wider truncate">
                  {metric.label}
                </div>
                <div className="mt-1 text-sm sm:text-base font-bold text-[#222222] truncate">
                  {metric.value}
                </div>
                <div className="hidden sm:block mt-0.5 text-xs text-[#717171] truncate">
                  {metric.subtext}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
