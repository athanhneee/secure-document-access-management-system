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
  return (
    <section className="relative border-b border-[#ebebeb] bg-linear-to-b from-[#ffffff] via-[#ffffff] to-[#f7f7f7] py-8 sm:py-16 lg:py-20">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="max-w-3xl">
          <div className="inline-flex items-center gap-2 text-[11px] sm:text-xs font-bold text-[#008489] mb-3 sm:mb-5 select-none animate-fade-in-down">
            <span className="dot dot-info animate-pulse-subtle" aria-hidden="true" />
            <span className="sm:hidden">BẢO MẬT ĐA TẦNG</span>
            <span className="hidden sm:inline">KIỂM SOÁT TRUY CẬP TÀI LIỆU MẬT TỔ CHỨC</span>
          </div>
          <h1 className="text-2xl sm:text-4xl lg:text-5xl font-extrabold tracking-tight text-[#222222] leading-[1.25] sm:leading-tight text-balance animate-fade-in-up">
            <span className="sm:hidden">Kiểm soát &amp; Bảo vệ Tài liệu Tối mật</span>
            <span className="hidden sm:inline">
              Bảo vệ tài liệu tối mật với kiến trúc phân quyền đa tầng.
            </span>
          </h1>
          <p className="mt-2.5 sm:mt-4 text-xs sm:text-base text-[#717171] leading-relaxed max-w-2xl text-balance animate-fade-in-up delay-100">
            <span className="sm:hidden">
              Phân quyền Zero-Trust, mã hóa phong bì số và kiểm toán chuỗi băm bất biến.
            </span>
            <span className="hidden sm:inline">
              Nền tảng kiểm soát tài liệu nhạy cảm theo nguyên tắc quyền tối thiểu (Least
              Privilege), mã hóa phong bì số AES-256-GCM, thực thi chính sách ABAC tại biên và kiểm
              toán chuỗi băm bất biến HMAC-SHA256.
            </span>
          </p>

          <div className="mt-5 sm:mt-8 flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5 sm:gap-3 animate-fade-in-up delay-200">
            <InteractiveHoverButton
              href="/login"
              variant="solid"
              text="Bắt đầu ngay"
              className="w-full sm:w-auto px-6 py-2.5 shadow-xs text-xs sm:text-sm font-semibold"
            />
            <InteractiveHoverButton
              href="#vai-tro"
              variant="outline"
              text="Chọn vai trò"
              className="w-full sm:w-auto px-6 py-2.5 text-xs sm:text-sm font-semibold"
            />
          </div>
        </div>

        <div className="mt-6 sm:mt-14 grid grid-cols-2 gap-2 sm:gap-4 sm:grid-cols-4 pt-5 sm:pt-8 border-t border-[#ebebeb]">
          {HERO_METRICS.map((metric) => (
            <div
              key={metric.label}
              className={`rounded-[16px] sm:rounded-[24px] border border-[#ebebeb] bg-[#ffffff] p-2.5 sm:p-5 shadow-[0_2px_12px_rgba(0,0,0,0.02)] hover-card animate-fade-in-up ${metric.delay}`}
            >
              <div className="text-[10px] sm:text-[11px] font-medium text-[#717171] uppercase tracking-wider truncate">
                {metric.label}
              </div>
              <div className="mt-0.5 sm:mt-1 text-xs sm:text-base font-bold text-[#222222] truncate">
                {metric.value}
              </div>
              <div className="hidden sm:block mt-0.5 text-[11px] text-[#717171] leading-tight line-clamp-2">
                {metric.subtext}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
