import Link from 'next/link';
import {
  FileText,
  Eye,
  ShieldAlert,
  ClipboardCheck,
  Settings,
  Laptop,
  ChevronRight,
} from 'lucide-react';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';

const rolePortals = [
  {
    role: 'DOCUMENT_OWNER',
    roleShort: 'OWNER',
    title: 'Chủ sở hữu tài liệu',
    description:
      'Tải lên tệp đã mã hóa, thiết lập chính sách truy cập ABAC và phê duyệt yêu cầu cấp quyền.',
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
    path: '/sessions',
    icon: Laptop,
    badgeColor: 'text-[#717171]',
    dotClass: 'dot-neutral',
  },
] as const;

const STAGGER_DELAYS = [
  'delay-75',
  'delay-100',
  'delay-150',
  'delay-200',
  'delay-250',
  'delay-300',
] as const;

export function RolePortalsSection() {
  return (
    <section id="vai-tro" className="py-8 sm:py-16 lg:py-20 border-b border-[#ebebeb] bg-[#ffffff]">
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
            Hệ thống tách biệt hoàn toàn giao diện và quyền hạn giữa các nhóm người dùng, đảm bảo
            nguyên tắc Phân quyền Tối thiểu (Least Privilege).
          </p>
        </div>

        {/* Mobile View: Sleek, Compact Tappable Directory */}
        <div className="grid grid-cols-1 gap-2 sm:hidden">
          {rolePortals.map((portal) => {
            const IconComponent = portal.icon;
            return (
              <Link
                key={portal.role}
                href={portal.path}
                className="group flex items-center justify-between px-4 py-3.5 rounded-full border border-[#ebebeb] bg-[#ffffff] shadow-[0_2px_8px_rgba(0,0,0,0.02)] active:scale-[0.98] transition-all hover:border-[#dddddd]"
              >
                <div className="flex items-center gap-3 min-w-0">
                  {/* // CONFLICT-RESOLVED: Loại bỏ hộp tròn nền màu/pastel bọc quanh icon theo quy tắc Icon System (rules/ui-design-system.md). */}
                  <IconComponent
                    size={20}
                    strokeWidth={1.75}
                    className="shrink-0 text-[#222222] group-hover:text-[#FF385C] transition-colors"
                    aria-hidden="true"
                  />
                  <div className="min-w-0">
                    <div className="text-xs font-bold text-[#222222] truncate">{portal.title}</div>
                    <div className="flex items-center gap-1.5 mt-0.5">
                      <span className={`dot ${portal.dotClass}`} aria-hidden="true" />
                      <span className={`text-[10px] font-bold ${portal.badgeColor}`}>
                        {portal.roleShort}
                      </span>
                    </div>
                  </div>
                </div>
                <div className="flex items-center text-[#b0b0b0] group-hover:text-[#222222] group-hover:translate-x-0.5 transition-all">
                  <ChevronRight size={16} strokeWidth={2} aria-hidden="true" />
                </div>
              </Link>
            );
          })}
        </div>

        {/* Desktop / Tablet View: Rich Detailed Cards */}
        <div className="hidden sm:grid sm:grid-cols-2 lg:grid-cols-3 gap-3.5 sm:gap-5">
          {rolePortals.map((portal, idx) => {
            const IconComponent = portal.icon;
            return (
              <article
                key={portal.role}
                className={`flex flex-col justify-between rounded-[20px] sm:rounded-[28px] border border-[#ebebeb] bg-[#ffffff] p-4 sm:p-6 shadow-[0_4px_20px_rgba(0,0,0,0.04)] hover-card animate-fade-in-up ${STAGGER_DELAYS[idx % STAGGER_DELAYS.length]}`}
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
                    >
                      <span className={`dot ${portal.dotClass}`} aria-hidden="true" />
                      <span>{portal.role}</span>
                    </span>
                  </div>
                  <h3 className="text-sm sm:text-base font-bold text-[#222222]">{portal.title}</h3>
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
  );
}
