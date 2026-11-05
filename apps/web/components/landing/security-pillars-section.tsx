import { Lock, Hash, Fingerprint, CheckCircle2, Layers } from 'lucide-react';

const securityPillars = [
  {
    icon: Lock,
    title: 'Mã hóa phong bì số (Envelope Encryption)',
    mobileTitle: 'Mã hóa Envelope',
    description:
      'Tài liệu lưu trữ được mã hóa xác thực bằng AES-256-GCM với khóa mã hóa dữ liệu (DEK) độc lập cho từng tệp. Khóa DEK được bọc bởi Key Encryption Key (KEK) và không bao giờ lưu trữ dạng văn bản thô.',
    badge: 'AES-256-GCM',
  },
  {
    icon: Layers,
    title: 'Kiểm soát truy cập Zero Trust & ABAC',
    mobileTitle: 'Zero-Trust & ABAC',
    description:
      'Kết hợp RBAC và ABAC tại Policy Enforcement Point (PEP) phía máy chủ. Mọi yêu cầu truy cập đều đánh giá đồng thời: vai trò, độ bảo mật tài liệu, phòng ban, thời gian và phạm vi quyền.',
    badge: 'PEP / Engine',
  },
  {
    icon: Hash,
    title: 'Nhật ký kiểm toán chuỗi băm bất biến',
    mobileTitle: 'Chuỗi băm HMAC',
    description:
      'Mọi sự kiện nghiệp vụ và truy cập nhạy cảm được nối vào chuỗi băm HMAC-SHA256 liên kết (tamper-evident log chain). Kiểm toán viên có thể phát hiện ngay lập tức bất kỳ sửa đổi hoặc xóa nhật ký.',
    badge: 'HMAC-SHA256',
  },
  {
    icon: Fingerprint,
    title: 'Watermark định danh pháp chứng động',
    mobileTitle: 'Watermark pháp chứng',
    description:
      'Khi người đọc xem trước hoặc tải tài liệu, hệ thống tự động nhúng watermark chứa mã băm phiên, định danh người dùng, địa chỉ IP và dấu thời gian nhằm ngăn ngừa rò rỉ dữ liệu ngoài ý muốn.',
    badge: 'Watermark',
  },
] as const;

const COMPLIANCE_STANDARDS = [
  {
    title: 'ISO/IEC 27001:2022',
    subtitle: 'Kiểm soát truy cập và bảo vệ mật mã dữ liệu',
  },
  {
    title: 'NIST SP 800-53 Rev. 5',
    subtitle: 'Phân quyền ABAC và ghi vết kiểm toán chuỗi băm',
  },
  {
    title: 'Quy chế Bảo vệ Bí mật',
    subtitle: 'Tuân thủ 5 cấp phân loại mật và quy trình bàn giao',
  },
] as const;

export function SecurityPillarsSection() {
  return (
    <>
      <section
        id="kien-truc"
        className="py-8 sm:py-16 lg:py-20 border-b border-[#ebebeb] bg-[#f7f7f7]"
      >
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="max-w-2xl mb-5 sm:mb-12">
            <p className="text-[11px] sm:text-xs font-semibold uppercase tracking-wider text-[#008489]">
              KIẾN TRÚC KỸ THUẬT
            </p>
            <h2 className="text-lg sm:text-2xl lg:text-3xl font-bold tracking-tight text-[#222222] mt-0.5 sm:mt-1">
              <span className="sm:hidden">Kiến trúc an ninh đa tầng</span>
              <span className="hidden sm:inline">
                Bảo vệ toàn vẹn và bảo mật dữ liệu ở mức cao nhất
              </span>
            </h2>
            <p className="hidden sm:block text-xs text-[#717171] mt-2 leading-relaxed">
              Được thiết kế dựa trên các tiêu chuẩn bảo mật quốc tế và quy định quản lý thông tin
              mật tổ chức, loại trừ mọi điểm lỗi đơn lẻ.
            </p>
          </div>

          <div className="grid grid-cols-2 gap-2 sm:hidden">
            {securityPillars.map((pillar) => {
              const IconComp = pillar.icon;
              return (
                <div
                  key={pillar.title}
                  className="rounded-[16px] border border-[#ebebeb] bg-[#ffffff] p-3 shadow-[0_2px_8px_rgba(0,0,0,0.02)] flex flex-col justify-between"
                >
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <IconComp
                        size={20}
                        strokeWidth={1.75}
                        className="text-[#008489]"
                        aria-hidden="true"
                      />
                      <span className="text-[9px] font-bold text-[#008489] uppercase">
                        {pillar.badge}
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

          <div className="hidden sm:grid sm:grid-cols-2 gap-3.5 sm:gap-6">
            {securityPillars.map((pillar, idx) => {
              const IconComp = pillar.icon;
              const delays = ['delay-75', 'delay-150', 'delay-200', 'delay-250'];
              return (
                <div
                  key={pillar.title}
                  className={`rounded-[20px] sm:rounded-[28px] border border-[#ebebeb] bg-[#ffffff] p-4 sm:p-6 shadow-[0_4px_16px_rgba(0,0,0,0.03)] hover-card flex flex-col justify-between animate-fade-in-up ${delays[idx % delays.length]}`}
                >
                  <div>
                    <div className="flex items-center justify-between mb-2.5 sm:mb-3">
                      <IconComp
                        size={20}
                        strokeWidth={1.75}
                        className="text-[#008489]"
                        aria-hidden="true"
                      />
                      <span
                        className="staff-badge inline-flex items-center gap-1.5 text-xs font-bold text-[#008489]"
                        style={{ background: 'transparent', border: 'none', padding: 0 }}
                      >
                        <span className="dot dot-info" aria-hidden="true" />
                        <span>{pillar.badge}</span>
                      </span>
                    </div>
                    <h3 className="text-sm font-bold text-[#222222]">{pillar.title}</h3>
                    <p className="mt-1.5 text-xs text-[#717171] leading-relaxed">
                      {pillar.description}
                    </p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      <section id="tieu-chuan" className="py-8 sm:py-16 lg:py-20 bg-[#ffffff]">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="rounded-[20px] sm:rounded-[28px] border border-[#ebebeb] bg-[#f7f7f7] p-4 sm:p-6 lg:p-8 shadow-[0_4px_16px_rgba(0,0,0,0.03)] hover-card animate-fade-in-up delay-150">
            <div className="max-w-2xl">
              <p className="text-[11px] sm:text-xs font-semibold uppercase tracking-wider text-[#008489]">
                TIÊU CHUẨN TUÂN THỦ
              </p>
              <h2 className="text-base sm:text-xl lg:text-2xl font-bold text-[#222222] mt-0.5 sm:mt-1">
                Sẵn sàng kiểm định an toàn thông tin
              </h2>
              <p className="hidden sm:block text-xs text-[#717171] mt-2 leading-relaxed">
                Kiến trúc hệ thống đáp ứng các yêu cầu kiểm soát bảo vệ thông tin tổ chức, bảo vệ bí
                mật nhà nước theo phân cấp và sẵn sàng cho các đợt rà soát an ninh độc lập.
              </p>
            </div>

            <div className="mt-3.5 sm:mt-8 grid grid-cols-1 sm:grid-cols-3 gap-2 sm:gap-4">
              {COMPLIANCE_STANDARDS.map((item) => (
                <div
                  key={item.title}
                  className="flex items-center sm:items-start gap-2.5 sm:gap-3 rounded-[16px] sm:rounded-[20px] border border-[#ebebeb] bg-[#ffffff] p-3 sm:p-4 shadow-2xs hover-lift"
                >
                  <CheckCircle2
                    size={16}
                    strokeWidth={1.75}
                    className="text-[#008A05] shrink-0"
                    aria-hidden="true"
                  />
                  <div>
                    <div className="text-xs font-semibold text-[#222222]">{item.title}</div>
                    <div className="hidden sm:block text-[11px] text-[#717171] mt-0.5 leading-relaxed">
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
