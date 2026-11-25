/**
 * Thuật toán: Trình Bày 4 Trụ Cột Kiến Trúc An Ninh & Khung Tiêu Chuẩn Tuân Thủ (`SecurityPillarsSection`)
 * Mục đích: Biểu diễn trực quan cơ chế AES-256-GCM, PEP/ABAC, chuỗi băm HMAC-SHA256 và Watermark pháp chứng đạt độ tương phản chữ WCAG 2.1 AA (`>= 4.5:1`).
 */
import { Lock, Hash, Fingerprint, CheckCircle2, Layers } from 'lucide-react';

const securityPillars = [
  {
    icon: Lock,
    title: 'Mã hóa bảo vệ tệp',
    mobileTitle: 'Mã hóa tệp độc lập',
    description: 'Mã hóa riêng từng tệp tài liệu bằng khóa độc lập để bảo vệ dữ liệu lưu trữ.',
    badge: 'Mã hóa',
  },
  {
    icon: Layers,
    title: 'Kiểm soát truy cập đa tầng',
    mobileTitle: 'Phân quyền đa tầng',
    description: 'Đánh giá đồng thời vai trò, cấp thẩm quyền, phòng ban và ngữ cảnh truy cập.',
    badge: 'Phân quyền',
  },
  {
    icon: Hash,
    title: 'Nhật ký kiểm toán toàn vẹn',
    mobileTitle: 'Nhật ký toàn vẹn',
    description: 'Liên kết mọi sự kiện nhạy cảm vào chuỗi nhật ký chống chỉnh sửa trái phép.',
    badge: 'Kiểm toán',
  },
  {
    icon: Fingerprint,
    title: 'Watermark bảo mật',
    mobileTitle: 'Watermark bảo mật',
    description:
      'Gắn động thông tin định danh người xem và thời điểm truy cập trên từng trang tài liệu.',
    badge: 'Truy vết',
  },
] as const;

const COMPLIANCE_STANDARDS = [
  {
    title: 'ISO/IEC 27001:2022',
    subtitle: 'Tham chiếu kiểm soát truy cập và bảo vệ dữ liệu',
  },
  {
    title: 'NIST SP 800-53 Rev. 5',
    subtitle: 'Tham chiếu phân quyền theo thuộc tính và nhật ký toàn vẹn',
  },
  {
    title: 'Quy chế bảo vệ bí mật nội bộ',
    subtitle: 'Phân loại 4 mức độ mật và kiểm soát bàn giao có truy vết',
  },
] as const;

export function SecurityPillarsSection() {
  return (
    <>
      <section id="kien-truc" className="py-8 sm:py-12 border-b border-[#ebebeb] bg-[#f7f7f7]">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="mb-5 sm:mb-7">
            <p className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-[#222222]">
              <span className="dot dot-info" aria-hidden="true" />
              <span>KIẾN TRÚC KỸ THUẬT</span>
            </p>
            <h2 className="text-lg sm:text-2xl font-bold tracking-tight text-[#222222] mt-0.5">
              Bảo vệ toàn vẹn dữ liệu ở mọi tầng xử lý
            </h2>
          </div>

          <div className="grid grid-cols-2 gap-2.5 sm:hidden">
            {securityPillars.map((pillar) => {
              const IconComp = pillar.icon;
              return (
                <div
                  key={pillar.title}
                  className="rounded-[16px] border border-[#ebebeb] bg-[#ffffff] p-3 shadow-[0_2px_8px_rgba(0,0,0,0.02)] flex flex-col justify-between"
                >
                  <div className="min-w-0">
                    <div className="mb-1.5">
                      <span className="staff-badge bg-transparent border-0 p-0 inline-flex max-w-full items-center gap-1.5 text-xs font-bold text-[#008489] uppercase">
                        <IconComp
                          size={16}
                          strokeWidth={1.75}
                          className="shrink-0"
                          aria-hidden="true"
                        />
                        <span className="truncate">{pillar.badge}</span>
                      </span>
                    </div>
                    <div className="text-xs font-bold text-[#222222] leading-snug">
                      {pillar.mobileTitle}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          <div className="hidden sm:grid sm:grid-cols-2 lg:grid-cols-4 gap-3.5 sm:gap-4">
            {securityPillars.map((pillar, idx) => {
              const IconComp = pillar.icon;
              const delays = ['delay-75', 'delay-100', 'delay-150', 'delay-200'];
              return (
                <div
                  key={pillar.title}
                  className={`rounded-[20px] border border-[#ebebeb] bg-[#ffffff] p-4 sm:p-5 shadow-[0_2px_10px_rgba(0,0,0,0.03)] hover-card flex flex-col justify-between animate-fade-in-up ${delays[idx % delays.length]}`}
                >
                  <div>
                    <div className="mb-2">
                      <span className="staff-badge bg-transparent border-0 p-0 inline-flex items-center gap-1.5 text-xs font-bold text-[#008489]">
                        <IconComp
                          size={16}
                          strokeWidth={1.75}
                          className="shrink-0"
                          aria-hidden="true"
                        />
                        <span>{pillar.badge}</span>
                      </span>
                    </div>
                    <h3 className="text-sm font-bold text-[#222222]">{pillar.title}</h3>
                    <p className="mt-1 text-xs text-[#717171] leading-relaxed">
                      {pillar.description}
                    </p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      <section id="tieu-chuan" className="py-8 sm:py-12 bg-[#ffffff]">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-4 sm:p-6">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 mb-4">
              <div>
                <p className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-[#222222]">
                  <span className="dot dot-info" aria-hidden="true" />
                  <span>ĐỊNH HƯỚNG TUÂN THỦ</span>
                </p>
                <h2 className="text-base sm:text-xl font-bold text-[#222222] mt-0.5">
                  Thiết kế tham chiếu các chuẩn an toàn thông tin
                </h2>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 sm:gap-3">
              {COMPLIANCE_STANDARDS.map((item) => (
                <div
                  key={item.title}
                  className="flex items-center sm:items-start gap-2.5 rounded-[16px] border border-[#ebebeb] bg-[#ffffff] p-3 sm:p-3.5 shadow-2xs"
                >
                  <CheckCircle2
                    size={16}
                    strokeWidth={1.75}
                    className="text-[#008A05] shrink-0 sm:mt-0.5"
                    aria-hidden="true"
                  />
                  <div>
                    <div className="text-xs font-semibold text-[#222222]">{item.title}</div>
                    <div className="hidden sm:block text-xs text-[#717171] mt-0.5">
                      {item.subtitle}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>
    </>
  );
}
