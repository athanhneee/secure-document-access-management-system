'use client';

/**
 * Thuật toán: Khu Vực Giới Thiệu Đầu Trang Nhận Thức Phiên Đăng Nhập & Lưới Chỉ Số Mật Mã (`HeroSection`)
 * Mục đích: Trình bày thông điệp cốt lõi Zero-Trust đúng thực tế 4 cấp độ mật (`V-23`), định tuyến nút chính vào phân hệ được cấp và ẩn nút "Chọn phân hệ" khi người dùng đã đăng nhập với duy nhất 1 phân hệ (`V-32`).
 */
import { resolveDefaultPortalForRoles, useAuth } from '@/lib/auth-context';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';

const HERO_METRICS = [
  {
    label: 'Phân loại',
    value: '4 cấp độ mật',
    subtext: 'Từ Nội bộ đến Tuyệt mật',
    delay: 'delay-100',
  },
  {
    label: 'Mã hóa',
    value: 'Mã hóa riêng từng tệp',
    subtext: 'Khóa bảo vệ độc lập theo tài liệu',
    delay: 'delay-150',
  },
  {
    label: 'Kiểm toán',
    value: 'Nhật ký bất biến',
    subtext: 'Lưu vết và đối soát toàn vẹn liên tục',
    delay: 'delay-200',
  },
  {
    label: 'Truy vết',
    value: 'Watermark bảo mật',
    subtext: 'Gắn định danh người xem theo từng phiên',
    delay: 'delay-250',
  },
] as const;

export function HeroSection() {
  const { isAuthenticated, user, accessiblePortals } = useAuth();
  const primaryHref = isAuthenticated ? resolveDefaultPortalForRoles(user) : '/login';
  const primaryText = isAuthenticated ? 'Vào phân hệ làm việc' : 'Bắt đầu ngay';
  const showPortalChooser = !isAuthenticated || accessiblePortals.length > 1;

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
              <span className="sm:hidden">Kiểm soát và bảo vệ tài liệu mật</span>
              <span className="hidden sm:inline">
                Bảo vệ tài liệu tối mật với kiến trúc phân quyền đa tầng
              </span>
            </h1>
            <p className="mt-2.5 sm:mt-3 text-xs sm:text-sm text-[#717171] leading-relaxed max-w-xl animate-fade-in-up delay-75">
              Kiểm soát truy cập chặt chẽ theo vai trò và ngữ cảnh, mã hóa riêng từng tài liệu và
              lưu vết nhật ký kiểm toán toàn vẹn.
            </p>

            <div className="mt-5 sm:mt-6 flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5 animate-fade-in-up delay-100">
              <InteractiveHoverButton
                href={primaryHref}
                variant="solid"
                text={primaryText}
                className="w-full sm:w-auto px-5"
              />
              {showPortalChooser && (
                <InteractiveHoverButton
                  href="#vai-tro"
                  variant="outline"
                  text="Chọn phân hệ"
                  className="w-full sm:w-auto px-5"
                />
              )}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-2.5 sm:gap-3 lg:col-span-5">
            {HERO_METRICS.map((metric) => (
              <div
                key={metric.label}
                className={`rounded-[16px] sm:rounded-[20px] border border-[#ebebeb] bg-[#ffffff] p-3.5 sm:p-4 shadow-[0_2px_10px_rgba(0,0,0,0.03)] hover-card animate-fade-in-up ${metric.delay}`}
              >
                <div className="text-xs font-semibold text-[#717171] uppercase tracking-wider truncate">
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
