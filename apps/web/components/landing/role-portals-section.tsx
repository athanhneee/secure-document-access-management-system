'use client';

/**
 * Thuật toán: Danh Mục Điều Hướng Không Gian Vai Trò Có Lọc Theo Quyền Phiên Hiện Tại (`RolePortalsSection`)
 * Mục đích:
 *   - Với khách chưa đăng nhập: giới thiệu tổng quan kiến trúc 6 không gian vai trò (bấm vào sẽ qua bước xác thực `/login`).
 *   - Với người dùng đã đăng nhập: chỉ hiển thị đúng các không gian làm việc mà tài khoản được cấp quyền (`user.roles`) cùng mục quản lý phiên cá nhân (`DEVICE_SESSIONS`), ẩn hoàn toàn các phân hệ không thuộc thẩm quyền.
 */
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
import { useAuth } from '@/lib/auth-context';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';

const rolePortals = [
  {
    role: 'DOCUMENT_OWNER',
    roleShort: 'Tài liệu',
    title: 'Chủ sở hữu tài liệu',
    description: 'Tải lên, phân loại mức độ mật và phê duyệt yêu cầu quyền truy cập.',
    path: '/owner',
    icon: FileText,
    badgeColor: 'text-[#008489]',
    dotClass: 'dot-info',
  },
  {
    role: 'DOCUMENT_READER',
    roleShort: 'Tra cứu',
    title: 'Người đọc tài liệu',
    description:
      'Tra cứu danh mục, gửi yêu cầu quyền truy cập và xem tài liệu có watermark bảo mật.',
    path: '/reader',
    icon: Eye,
    badgeColor: 'text-[#008A05]',
    dotClass: 'dot-success',
  },
  {
    role: 'SECURITY_OFFICER',
    roleShort: 'An ninh',
    title: 'An ninh thông tin',
    description: 'Giám sát cảnh báo theo thời gian thực, xử lý sự cố và truy vết rò rỉ tài liệu.',
    path: '/security',
    icon: ShieldAlert,
    badgeColor: 'text-[#222222]',
    dotClass: 'dot-warning',
  },
  {
    role: 'AUDITOR',
    roleShort: 'Kiểm toán',
    title: 'Kiểm toán độc lập',
    description: 'Tra cứu nhật ký kiểm toán, kiểm tra tính toàn vẹn và xuất báo cáo tuân thủ.',
    path: '/auditor',
    icon: ClipboardCheck,
    badgeColor: 'text-[#008489]',
    dotClass: 'dot-info',
  },
  {
    role: 'SYSTEM_ADMIN',
    roleShort: 'Quản trị',
    title: 'Quản trị hệ thống',
    description: 'Quản lý tài khoản, phòng ban, vai trò và chính sách kiểm soát truy cập.',
    path: '/admin',
    icon: Settings,
    badgeColor: 'text-[#E31C5F]',
    dotClass: 'dot-primary',
  },
  {
    role: 'DEVICE_SESSIONS',
    roleShort: 'Thiết bị',
    title: 'Phiên & thiết bị',
    description: 'Theo dõi thiết bị đang đăng nhập, đăng ký khóa bảo mật và thu hồi phiên từ xa.',
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
  const { isAuthenticated, user } = useAuth();

  const visiblePortals =
    isAuthenticated && user
      ? rolePortals.filter(
          (portal) => portal.role === 'DEVICE_SESSIONS' || user.roles.includes(portal.role),
        )
      : rolePortals;

  return (
    <section id="vai-tro" className="py-8 sm:py-12 border-b border-[#ebebeb] bg-[#ffffff]">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="mb-5 sm:mb-7">
          <p className="text-xs font-semibold uppercase tracking-wider text-[#008489]">
            {isAuthenticated ? 'PHÂN HỆ ĐƯỢC CẤP QUYỀN' : 'KHÔNG GIAN LÀM VIỆC CHUYÊN BIỆT'}
          </p>
          <h2 className="text-lg sm:text-2xl font-bold tracking-tight text-[#222222] mt-0.5">
            Đúng vai trò · Đúng nhiệm vụ · Đúng phạm vi
          </h2>
        </div>

        <div className="grid grid-cols-1 gap-2 sm:hidden">
          {visiblePortals.map((portal) => {
            const IconComponent = portal.icon;
            return (
              <Link
                key={portal.role}
                href={portal.path}
                className="group flex items-center justify-between px-4 py-3 rounded-full border border-[#ebebeb] bg-[#ffffff] shadow-[0_2px_8px_rgba(0,0,0,0.02)] active:scale-[0.98] transition-all hover:border-[#dddddd]"
              >
                <div className="flex items-center gap-3 min-w-0">
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
                      <span className={`text-[11px] font-bold ${portal.badgeColor}`}>
                        {portal.roleShort}
                      </span>
                    </div>
                  </div>
                </div>
                <div className="flex items-center text-[#717171] group-hover:text-[#222222] group-hover:translate-x-0.5 transition-all">
                  <ChevronRight size={16} strokeWidth={2} aria-hidden="true" />
                </div>
              </Link>
            );
          })}
        </div>

        <div className="hidden sm:grid sm:grid-cols-2 lg:grid-cols-3 gap-3.5 sm:gap-4">
          {visiblePortals.map((portal, idx) => {
            const IconComponent = portal.icon;
            return (
              <article
                key={portal.role}
                className={`flex flex-col justify-between rounded-[20px] border border-[#ebebeb] bg-[#ffffff] p-4 sm:p-5 shadow-[0_2px_10px_rgba(0,0,0,0.03)] hover-card animate-fade-in-up ${STAGGER_DELAYS[idx % STAGGER_DELAYS.length]}`}
              >
                <div>
                  <div className="flex items-center justify-between mb-2.5">
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
                      <span>{portal.roleShort}</span>
                    </span>
                  </div>
                  <h3 className="text-sm font-bold text-[#222222]">{portal.title}</h3>
                  <p className="mt-1 text-xs text-[#717171] leading-relaxed">
                    {portal.description}
                  </p>
                </div>

                <div className="mt-4 pt-3 border-t border-[#ebebeb]">
                  <InteractiveHoverButton
                    href={portal.path}
                    size="sm"
                    text="Mở phân hệ"
                    className="w-full"
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
