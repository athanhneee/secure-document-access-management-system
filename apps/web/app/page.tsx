import Link from 'next/link';
import {
  Lock,
  FileText,
  Eye,
  ShieldAlert,
  ClipboardCheck,
  Settings,
  Hash,
  Fingerprint,
  CheckCircle2,
  Layers,
  Laptop,
  ChevronRight,
} from 'lucide-react';
import { HomeHeader } from '@/components/navigation/home-header';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';

const rolePortals = [
  {
    role: 'DOCUMENT_OWNER',
    roleShort: 'OWNER',
    title: 'Chủ sở hữu tài liệu',
    description:
      'Tải lên tệp đã mã hóa, thiết lập chính sách truy cập ABAC và phê duyệt yêu cầu cấp quyền.',
    shortDesc: 'Mã hóa tệp, cấu hình ABAC & duyệt cấp quyền.',
    path: '/owner',
    icon: FileText,
    badgeColor: 'text-[#008489]',
    dotClass: 'dot-info',
  },
  {
    role: 'DOCUMENT_READER',
    roleShort: 'READER',
    title: 'Người đọc tài liệu',
    description:
      'Tìm kiếm theo danh mục phân loại mật, gửi yêu cầu đọc và xem tài liệu có nhúng watermark định danh.',
    shortDesc: 'Tra cứu danh mục, xin cấp quyền & xem tài liệu.',
    path: '/reader',
    icon: Eye,
    badgeColor: 'text-[#008A05]',
    dotClass: 'dot-success',
  },
  {
    role: 'SECURITY_OFFICER',
    roleShort: 'SOC',
    title: 'Sĩ quan an ninh SOC',
    description:
      'Giám sát cảnh báo vi phạm chính sách theo thời gian thực, điều tra truy cập bất thường và truy vết watermark.',
    shortDesc: 'Giám sát cảnh báo & điều tra truy vết watermark.',
    path: '/security',
    icon: ShieldAlert,
    badgeColor: 'text-[#E07912]',
    dotClass: 'dot-warning',
  },
  {
    role: 'AUDITOR',
    roleShort: 'AUDITOR',
    title: 'Kiểm toán viên an ninh',
    description:
      'Xác thực tính toàn vẹn chuỗi nhật ký HMAC-SHA256, phát hiện xâm nhập và xuất hồ sơ tuân thủ.',
    shortDesc: 'Xác thực chuỗi băm HMAC & xuất hồ sơ tuân thủ.',
    path: '/auditor',
    icon: ClipboardCheck,
    badgeColor: 'text-[#008489]',
    dotClass: 'dot-info',
  },
  {
    role: 'SYSTEM_ADMIN',
    roleShort: 'ADMIN',
    title: 'Quản trị viên hệ thống',
    description:
      'Quản trị định danh người dùng, phòng ban, cấu hình chính sách truy cập RBAC và theo dõi tình trạng dịch vụ.',
    shortDesc: 'Quản trị tài khoản, phân quyền RBAC & dịch vụ.',
    path: '/admin',
    icon: Settings,
    badgeColor: 'text-[#FF385C]',
    dotClass: 'dot-primary',
  },
  {
    role: 'DEVICE_SESSIONS',
    roleShort: 'SESSIONS',
    title: 'Quản lý phiên & thiết bị',
    description:
      'Giám sát các phiên làm việc HttpOnly đang hoạt động, phòng chống CSRF và thu hồi phiên truy cập từ xa.',
    shortDesc: 'Giám sát phiên làm việc & thu hồi từ xa.',
    path: '/sessions',
    icon: Laptop,
    badgeColor: 'text-[#717171]',
    dotClass: 'dot-neutral',
  },
] as const;

const securityPillars = [
  {
    icon: Lock,
    title: 'Mã hóa phong bì số (Envelope Encryption)',
    mobileTitle: 'Mã hóa Envelope',
    description:
      'Tài liệu lưu trữ được mã hóa xác thực bằng AES-256-GCM với khóa mã hóa dữ liệu (DEK) độc lập cho từng tệp. Khóa DEK được bọc bởi Key Encryption Key (KEK) và không bao giờ lưu trữ dạng văn bản thô.',
    shortDesc: 'Khóa DEK/KEK độc lập từng tệp, bảo mật AES-256-GCM.',
    badge: 'AES-256-GCM',
  },
  {
    icon: Layers,
    title: 'Kiểm soát truy cập Zero Trust & ABAC',
    mobileTitle: 'Zero-Trust & ABAC',
    description:
      'Kết hợp RBAC và ABAC tại Policy Enforcement Point (PEP) phía máy chủ. Mọi yêu cầu truy cập đều đánh giá đồng thời: vai trò, độ bảo mật tài liệu, phòng ban, thời gian và phạm vi quyền.',
    shortDesc: 'Xác thực đa yếu tố tại máy chủ theo ngữ cảnh truy cập.',
    badge: 'PEP / Engine',
  },
  {
    icon: Hash,
    title: 'Nhật ký kiểm toán chuỗi băm bất biến',
    mobileTitle: 'Chuỗi băm HMAC',
    description:
      'Mọi sự kiện nghiệp vụ và truy cập nhạy cảm được nối vào chuỗi băm HMAC-SHA256 liên kết (tamper-evident log chain). Kiểm toán viên có thể phát hiện ngay lập tức bất kỳ sửa đổi hoặc xóa nhật ký.',
    shortDesc: 'Nhật ký liên kết chuỗi băm HMAC-SHA256 chống sửa đổi.',
    badge: 'HMAC-SHA256',
  },
  {
    icon: Fingerprint,
    title: 'Watermark định danh pháp chứng động',
    mobileTitle: 'Watermark pháp chứng',
    description:
      'Khi người đọc xem trước hoặc tải tài liệu, hệ thống tự động nhúng watermark chứa mã băm phiên, định danh người dùng, địa chỉ IP và dấu thời gian nhằm ngăn ngừa rò rỉ dữ liệu ngoài ý muốn.',
    shortDesc: 'Tự động nhúng IP, người dùng và mã phiên lên tài liệu.',
    badge: 'Watermark',
  },
] as const;

export default function HomePage() {
  return (
    <div className="flex min-h-screen flex-col bg-[#ffffff] text-[#222222] antialiased selection:bg-[#FF385C]/15 selection:text-[#FF385C]">
      {/* Skip to Content for A11y */}
      <a href="#main-content" className="skip-to-content">
        Chuyển đến nội dung chính
      </a>

      {/* Enterprise Top Navigation (Fully Responsive with Mobile Hamburger Drawer) */}
      <HomeHeader />

      {/* Main Content Area */}
      <main id="main-content" className="flex-1">
        {/* Hero Section */}
        <section className="relative border-b border-[#ebebeb] bg-linear-to-b from-[#ffffff] via-[#ffffff] to-[#f7f7f7] py-8 sm:py-16 lg:py-20">
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
            <div className="max-w-3xl">
              <div className="inline-flex items-center gap-2 text-[11px] sm:text-xs font-bold text-[#008489] mb-3 sm:mb-5 select-none animate-fade-in-down">
                <span className="dot dot-info animate-pulse-subtle" aria-hidden="true" />
                <span className="sm:hidden">BẢO MẬT ĐA TẦNG</span>
                <span className="hidden sm:inline">KIỂM SOÁT TRUY CẬP TÀI LIỆU MẬT TỔ CHỨC</span>
              </div>
              <h1 className="text-2xl sm:text-4xl lg:text-5xl font-extrabold tracking-tight text-[#222222] leading-[1.25] sm:leading-tight text-balance animate-fade-in-up">
                <span className="sm:hidden">Kiểm soát & Bảo vệ Tài liệu Tối mật</span>
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
                  Privilege), mã hóa phong bì số AES-256-GCM, thực thi chính sách ABAC tại biên và
                  kiểm toán chuỗi băm bất biến HMAC-SHA256.
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

            {/* Quick Metrics Bar (Minimalist on Mobile, Full on Desktop) */}
            <div className="mt-6 sm:mt-14 grid grid-cols-2 gap-2 sm:gap-4 sm:grid-cols-4 pt-5 sm:pt-8 border-t border-[#ebebeb]">
              <div className="rounded-[16px] sm:rounded-[24px] border border-[#ebebeb] bg-[#ffffff] p-2.5 sm:p-5 shadow-[0_2px_12px_rgba(0,0,0,0.02)] hover-card animate-fade-in-up delay-100">
                <div className="text-[10px] sm:text-[11px] font-medium text-[#717171] uppercase tracking-wider truncate">
                  Phân loại
                </div>
                <div className="mt-0.5 sm:mt-1 text-xs sm:text-base font-bold text-[#222222] truncate">
                  5 Cấp độ mật
                </div>
                <div className="hidden sm:block mt-0.5 text-[11px] text-[#717171] leading-tight line-clamp-2">
                  Từ Không mật đến Tuyệt mật
                </div>
              </div>
              <div className="rounded-[16px] sm:rounded-[24px] border border-[#ebebeb] bg-[#ffffff] p-2.5 sm:p-5 shadow-[0_2px_12px_rgba(0,0,0,0.02)] hover-card animate-fade-in-up delay-150">
                <div className="text-[10px] sm:text-[11px] font-medium text-[#717171] uppercase tracking-wider truncate">
                  Mã hóa
                </div>
                <div className="mt-0.5 sm:mt-1 text-xs sm:text-base font-bold text-[#222222] truncate">
                  AES-256-GCM
                </div>
                <div className="hidden sm:block mt-0.5 text-[11px] text-[#717171] leading-tight line-clamp-2">
                  Envelope Encryption per file
                </div>
              </div>
              <div className="rounded-[16px] sm:rounded-[24px] border border-[#ebebeb] bg-[#ffffff] p-2.5 sm:p-5 shadow-[0_2px_12px_rgba(0,0,0,0.02)] hover-card animate-fade-in-up delay-200">
                <div className="text-[10px] sm:text-[11px] font-medium text-[#717171] uppercase tracking-wider truncate">
                  Kiểm toán
                </div>
                <div className="mt-0.5 sm:mt-1 text-xs sm:text-base font-bold text-[#222222] truncate">
                  HMAC-SHA256
                </div>
                <div className="hidden sm:block mt-0.5 text-[11px] text-[#717171] leading-tight line-clamp-2">
                  Chuỗi hash bất biến liên kết
                </div>
              </div>
              <div className="rounded-[16px] sm:rounded-[24px] border border-[#ebebeb] bg-[#ffffff] p-2.5 sm:p-5 shadow-[0_2px_12px_rgba(0,0,0,0.02)] hover-card animate-fade-in-up delay-250">
                <div className="text-[10px] sm:text-[11px] font-medium text-[#717171] uppercase tracking-wider truncate">
                  Truy vết
                </div>
                <div className="mt-0.5 sm:mt-1 text-xs sm:text-base font-bold text-[#222222] truncate">
                  Watermark động
                </div>
                <div className="hidden sm:block mt-0.5 text-[11px] text-[#717171] leading-tight line-clamp-2">
                  Định danh người xem tức thì
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Role Portals Section */}
        <section
          id="vai-tro"
          className="py-8 sm:py-16 lg:py-20 border-b border-[#ebebeb] bg-[#ffffff]"
        >
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
            <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 mb-5 sm:mb-10">
              <div>
                <p className="text-[11px] sm:text-xs font-semibold uppercase tracking-wider text-[#008489]">
                  KHÔNG GIAN LÀM VIỆC CHUYÊN BIỆT
                </p>
                <h2 className="text-lg sm:text-2xl lg:text-3xl font-bold tracking-tight text-[#222222] mt-0.5 sm:mt-1 text-balance">
                  Đúng vai trò · Đúng nhiệm vụ · Đúng phạm vi
                </h2>
              </div>
              <p className="hidden md:block text-xs text-[#717171] max-w-md leading-relaxed text-balance">
                Hệ thống tách biệt hoàn toàn giao diện và quyền hạn giữa các nhóm người dùng, đảm
                bảo nguyên tắc Phân quyền Tối thiểu (Least Privilege).
              </p>
            </div>

            {/* Mobile View: Sleek, Compact Tappable Directory (Eliminates Text Wall) */}
            <div className="grid grid-cols-1 gap-2 sm:hidden">
              {rolePortals.map((portal) => {
                const IconComponent = portal.icon;
                return (
                  <Link
                    key={portal.role}
                    href={portal.path}
                    className="group flex items-center justify-between p-3.5 rounded-[18px] border border-[#ebebeb] bg-[#ffffff] shadow-[0_2px_8px_rgba(0,0,0,0.02)] active:scale-[0.98] transition-all hover:border-[#dddddd]"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-[#f7f7f7] text-[#222222] group-hover:bg-[#FF385C]/10 group-hover:text-[#FF385C] transition-colors">
                        <IconComponent size={18} strokeWidth={1.75} />
                      </div>
                      <div className="min-w-0">
                        <div className="text-xs font-bold text-[#222222] truncate">
                          {portal.title}
                        </div>
                        <div className="flex items-center gap-1.5 mt-0.5">
                          <span className={`dot ${portal.dotClass}`} aria-hidden="true" />
                          <span className={`text-[10px] font-bold ${portal.badgeColor}`}>
                            {portal.roleShort}
                          </span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center text-[#b0b0b0] group-hover:text-[#222222] group-hover:translate-x-0.5 transition-all">
                      <ChevronRight size={16} strokeWidth={2} />
                    </div>
                  </Link>
                );
              })}
            </div>

            {/* Desktop / Tablet View: Rich Detailed Cards */}
            <div className="hidden sm:grid sm:grid-cols-2 lg:grid-cols-3 gap-3.5 sm:gap-5">
              {rolePortals.map((portal, idx) => {
                const IconComponent = portal.icon;
                const delays = [
                  'delay-75',
                  'delay-100',
                  'delay-150',
                  'delay-200',
                  'delay-250',
                  'delay-300',
                ];
                return (
                  <article
                    key={portal.role}
                    className={`flex flex-col justify-between rounded-[20px] sm:rounded-[28px] border border-[#ebebeb] bg-[#ffffff] p-4 sm:p-6 shadow-[0_4px_20px_rgba(0,0,0,0.04)] hover-card animate-fade-in-up ${delays[idx % delays.length]}`}
                  >
                    <div>
                      <div className="flex items-center justify-between mb-3 sm:mb-4">
                        <IconComponent
                          size={20}
                          strokeWidth={1.75}
                          className="text-[#222222]"
                          aria-hidden="true"
                        />
                        <span
                          className={`staff-badge inline-flex items-center gap-1.5 text-xs font-bold ${portal.badgeColor}`}
                          style={{ background: 'transparent', border: 'none', padding: 0 }}
                        >
                          <span className={`dot ${portal.dotClass}`} aria-hidden="true" />
                          <span>{portal.role}</span>
                        </span>
                      </div>
                      <h3 className="text-sm sm:text-base font-bold text-[#222222]">
                        {portal.title}
                      </h3>
                      <p className="mt-1.5 text-xs text-[#717171] leading-relaxed">
                        {portal.description}
                      </p>
                    </div>

                    <div className="mt-4 sm:mt-6 pt-3 sm:pt-4 border-t border-[#ebebeb]">
                      <InteractiveHoverButton
                        href={portal.path}
                        text="Truy cập không gian"
                        className="w-full text-xs h-8.5 sm:h-9.5"
                      />
                    </div>
                  </article>
                );
              })}
            </div>
          </div>
        </section>

        {/* Security Architecture Pillars */}
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

            {/* Mobile View: 2x2 Feature Matrix (Compact, Zero Wall of Text) */}
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
                          size={18}
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

            {/* Desktop View: Full Architectural Details */}
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

        {/* Compliance & Standards */}
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
                  Kiến trúc hệ thống đáp ứng các yêu cầu kiểm soát bảo vệ thông tin tổ chức, bảo vệ
                  bí mật nhà nước theo phân cấp và sẵn sàng cho các đợt rà soát an ninh độc lập.
                </p>
              </div>

              <div className="mt-3.5 sm:mt-8 grid grid-cols-1 sm:grid-cols-3 gap-2 sm:gap-4">
                <div className="flex items-center sm:items-start gap-2.5 sm:gap-3 rounded-[16px] sm:rounded-[20px] border border-[#ebebeb] bg-[#ffffff] p-3 sm:p-4 shadow-2xs hover-lift">
                  <CheckCircle2 className="h-4 w-4 text-[#008A05] shrink-0" />
                  <div>
                    <div className="text-xs font-semibold text-[#222222]">ISO/IEC 27001:2022</div>
                    <div className="hidden sm:block text-[11px] text-[#717171] mt-0.5 leading-relaxed">
                      Kiểm soát truy cập và bảo vệ mật mã dữ liệu
                    </div>
                  </div>
                </div>

                <div className="flex items-center sm:items-start gap-2.5 sm:gap-3 rounded-[16px] sm:rounded-[20px] border border-[#ebebeb] bg-[#ffffff] p-3 sm:p-4 shadow-2xs hover-lift">
                  <CheckCircle2 className="h-4 w-4 text-[#008A05] shrink-0" />
                  <div>
                    <div className="text-xs font-semibold text-[#222222]">
                      NIST SP 800-53 Rev. 5
                    </div>
                    <div className="hidden sm:block text-[11px] text-[#717171] mt-0.5 leading-relaxed">
                      Phân quyền ABAC và ghi vết kiểm toán chuỗi băm
                    </div>
                  </div>
                </div>

                <div className="flex items-center sm:items-start gap-2.5 sm:gap-3 rounded-[16px] sm:rounded-[20px] border border-[#ebebeb] bg-[#ffffff] p-3 sm:p-4 shadow-2xs hover-lift">
                  <CheckCircle2 className="h-4 w-4 text-[#008A05] shrink-0" />
                  <div>
                    <div className="text-xs font-semibold text-[#222222]">
                      Quy chế Bảo vệ Bí mật
                    </div>
                    <div className="hidden sm:block text-[11px] text-[#717171] mt-0.5 leading-relaxed">
                      Tuân thủ 5 cấp phân loại mật và quy trình bàn giao
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>
      </main>

      {/* Standardized Enterprise Footer (Fully Mobile-First Responsive) */}
      <footer className="border-t border-[#ebebeb] bg-[#ffffff] py-6 sm:py-10 pb-16 sm:pb-10">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col items-center sm:items-start md:flex-row md:items-start justify-between gap-4 sm:gap-6 text-center sm:text-left">
            {/* Left: Brand Identity & Policy Tagline */}
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

            {/* Right: Operational Status & Security Standards */}
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

          {/* Bottom Copyright & Security Notice */}
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
