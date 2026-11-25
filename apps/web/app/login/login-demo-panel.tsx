'use client';

/**
 * Thuật toán: Cổng Bật Tắt Tường Minh Bảng Tài Khoản Kiểm Thử (`LoginDemoPanel`)
 * Mục đích: Chỉ hiển thị danh sách tài khoản `*.demo` khi biến môi trường `NEXT_PUBLIC_ENABLE_DEMO_ACCOUNTS === 'true'`, tránh gây nhầm lẫn trong môi trường mặc định nơi các tài khoản mẫu đã bị khóa `DISABLED`.
 */
const SHOW_DEMO_ACCOUNTS = process.env['NEXT_PUBLIC_ENABLE_DEMO_ACCOUNTS'] === 'true';

const DEMO_ACCOUNTS = [
  { label: 'Quản trị viên', user: 'admin.demo', dot: 'dot-success' },
  { label: 'Chủ sở hữu tài liệu', user: 'owner.demo', dot: 'dot-warning' },
  { label: 'Người đọc', user: 'reader.demo', dot: 'dot-info' },
  { label: 'An ninh thông tin', user: 'security.demo', dot: 'dot-danger' },
  { label: 'Kiểm toán viên', user: 'auditor.demo', dot: 'dot-neutral' },
] as const;

interface LoginDemoPanelProps {
  onSelectAccount: (username: string) => void;
}

export function LoginDemoPanel({ onSelectAccount }: LoginDemoPanelProps) {
  return (
    <>
      {SHOW_DEMO_ACCOUNTS && (
        <div className="rounded-[28px] border border-[#ebebeb] bg-[#ffffff] p-4 sm:p-5 space-y-3 shadow-[0_6px_20px_rgba(0,0,0,0.03)] animate-fade-in-up delay-200 hover-card">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-[#222222]">
              <span className="sm:hidden">Tài khoản Demo</span>
              <span className="hidden sm:inline">Tài khoản kiểm thử nhanh (Demo)</span>
            </span>
            <span className="text-xs text-[#717171] font-bold">Nhấp để điền tài khoản</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {DEMO_ACCOUNTS.map((item) => (
              <button
                key={item.user}
                type="button"
                onClick={() => onSelectAccount(item.user)}
                className="group flex items-center justify-between px-3.5 py-2.5 rounded-full border border-[#ebebeb] bg-[#f7f7f7] hover:border-[#FF385C]/30 hover:bg-[#ffffff] hover:shadow-[0_4px_12px_rgba(0,0,0,0.05)] hover:-translate-y-0.5 active:scale-[0.98] text-xs transition-all duration-200 ease-[cubic-bezier(0.16,1,0.3,1)] cursor-pointer text-left shadow-2xs"
              >
                <span className="staff-badge bg-transparent border-0 p-0 inline-flex items-center gap-1.5 font-medium text-[#222222]">
                  <span
                    className={`dot ${item.dot} transition-transform duration-200 group-hover:scale-125`}
                    aria-hidden="true"
                  />
                  <span>{item.label}</span>
                </span>
                <span className="text-xs text-[#717171] font-bold transition-colors group-hover:text-[#E31C5F]">
                  {item.user}
                </span>
              </button>
            ))}
          </div>
        </div>
      )}

      <p className="text-center text-xs text-[#717171]">
        Dành riêng cho nhân sự được cấp thẩm quyền truy cập.
      </p>
    </>
  );
}
