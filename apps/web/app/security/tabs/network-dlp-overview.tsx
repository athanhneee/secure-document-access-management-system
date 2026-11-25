'use client';

import { Activity, Cpu, ShieldAlert, ShieldCheck } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import type { NetworkDlpStatus } from '../types';

interface NetworkDlpOverviewProps {
  dlpStatus?: NetworkDlpStatus | undefined;
}

/**
 * Thuật toán: Phản Ánh Trung Thực Chế Độ Thực Thi DLP Thực Tế Từ Worker (`NetworkDlpOverview`)
 * Mục đích: Loại bỏ toàn bộ chuỗi hardcode phóng đại ("Tự động chặn & cảnh báo") khi Worker đang tắt hoặc chạy chế độ `AUDIT_ONLY`, đồng thời không rò rỉ cổng/URL nội bộ (#06).
 */
export function NetworkDlpOverview({ dlpStatus }: NetworkDlpOverviewProps) {
  const mode = dlpStatus?.enforcementMode ?? 'OFFLINE';
  const isBlocking = mode === 'BLOCK';
  const isAuditOnly = mode === 'AUDIT_ONLY';
  const isOnline = dlpStatus?.gatewayHealth === 'ONLINE' && dlpStatus.icapListening;

  const violationActionLabel = isBlocking
    ? 'Tự động chặn & cảnh báo'
    : isAuditOnly
      ? 'Chỉ ghi nhận & cảnh báo'
      : mode === 'DISABLED'
        ? 'Đã tắt kiểm tra DLP'
        : 'Chưa kết nối dịch vụ DLP';

  const violationActionColor = isBlocking
    ? 'text-[#C13515]'
    : isAuditOnly
      ? 'text-[#222222]'
      : 'text-[#717171]';

  const inspectionModeLabel = isOnline
    ? 'Phân tích thời gian thực'
    : dlpStatus?.workerReachable
      ? 'Đang gián đoạn lắng nghe'
      : 'Ngoại tuyến';

  return (
    <>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-0.5">
          <div className="flex items-center justify-between text-xs text-[#717171]">
            <span>Phạm vi giám sát</span>
            <Cpu size={16} strokeWidth={1.75} className="text-[#008489]" aria-hidden="true" />
          </div>
          <div className="text-sm font-bold text-[#222222]">Luồng dữ liệu ra ngoài</div>
        </div>

        <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-0.5">
          <div className="flex items-center justify-between text-xs text-[#717171]">
            <span>Chế độ kiểm tra</span>
            <Activity
              size={16}
              strokeWidth={1.75}
              className={isOnline ? 'text-[#008A05]' : 'text-[#717171]'}
              aria-hidden="true"
            />
          </div>
          <div className="text-sm font-bold text-[#222222]">{inspectionModeLabel}</div>
        </div>

        <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-0.5">
          <div className="flex items-center justify-between text-xs text-[#717171]">
            <span>Khi phát hiện vi phạm</span>
            <ShieldAlert
              size={16}
              strokeWidth={1.75}
              className={isBlocking ? 'text-[#C13515]' : 'text-[#E07912]'}
              aria-hidden="true"
            />
          </div>
          <div className={`text-sm font-bold ${violationActionColor}`}>{violationActionLabel}</div>
        </div>

        <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-0.5">
          <div className="flex items-center justify-between text-xs text-[#717171]">
            <span>Khi dữ liệu hợp lệ</span>
            <ShieldCheck
              size={16}
              strokeWidth={1.75}
              className={isOnline ? 'text-[#008A05]' : 'text-[#717171]'}
              aria-hidden="true"
            />
          </div>
          <div className={`text-sm font-bold ${isOnline ? 'text-[#008A05]' : 'text-[#717171]'}`}>
            {isOnline ? 'Cho phép lưu thông' : 'Chưa kích hoạt kiểm soát'}
          </div>
        </div>
      </div>

      <div className="space-y-2.5">
        <h3 className="text-xs font-bold text-[#222222] uppercase tracking-wider">
          Chính sách kiểm tra nội dung
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
          <div className="rounded-[16px] border border-[#ebebeb] p-3 space-y-1 bg-[#ffffff]">
            <div className="flex items-center justify-between gap-2">
              <span className="font-semibold text-[#222222]">Nhãn phân loại mật</span>
              <Badge variant={isBlocking ? 'danger' : 'warning'}>
                {isBlocking ? 'Bắt buộc chặn' : isAuditOnly ? 'Giám sát' : 'Chờ kích hoạt'}
              </Badge>
            </div>
            <p className="text-xs text-[#717171]">
              Kiểm soát truyền tải tài liệu mang dấu hiệu phân loại Mật, Tối mật hoặc Tuyệt mật ra
              ngoài phạm vi cho phép.
            </p>
          </div>

          <div className="rounded-[16px] border border-[#ebebeb] p-3 space-y-1 bg-[#ffffff]">
            <div className="flex items-center justify-between gap-2">
              <span className="font-semibold text-[#222222]">Watermark bảo mật</span>
              <Badge variant="primary">Truy vết</Badge>
            </div>
            <p className="text-xs text-[#717171]">
              Phát hiện tệp tài liệu chứa mã watermark bảo mật đi qua cổng kiểm soát mạng và ghi
              nhận cảnh báo SOC.
            </p>
          </div>

          <div className="rounded-[16px] border border-[#ebebeb] p-3 space-y-1 bg-[#ffffff]">
            <div className="flex items-center justify-between gap-2">
              <span className="font-semibold text-[#222222]">Khóa bí mật và mã xác thực</span>
              <Badge variant="warning">Bảo vệ khóa</Badge>
            </div>
            <p className="text-xs text-[#717171]">
              Ngăn ngừa rò rỉ khóa bảo mật riêng tư, khóa truy cập dịch vụ đám mây và mã xác thực hệ
              thống.
            </p>
          </div>

          <div className="rounded-[16px] border border-[#ebebeb] p-3 space-y-1 bg-[#ffffff]">
            <div className="flex items-center justify-between gap-2">
              <span className="font-semibold text-[#222222]">Thông tin định danh cá nhân</span>
              <Badge variant="info">Dữ liệu cá nhân</Badge>
            </div>
            <p className="text-xs text-[#717171]">
              Kiểm tra và cảnh báo số thẻ thanh toán cùng số căn cước công dân trong luồng dữ liệu
              truyền ra ngoài.
            </p>
          </div>
        </div>
      </div>
    </>
  );
}

export function NetworkDlpBlueprint() {
  return (
    <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3.5 space-y-1.5 text-xs">
      <div className="font-bold text-[#222222] flex items-center gap-1.5">
        <Cpu size={16} strokeWidth={1.75} className="text-[#008489]" aria-hidden="true" />
        <span>Tích hợp cổng kiểm soát biên mạng</span>
      </div>
      <p className="text-xs text-[#717171] leading-relaxed">
        Trạng thái trên phản ánh trực tiếp tiến trình giám sát luồng dữ liệu ra ngoài (Worker DLP).
        Mọi sự kiện vi phạm chính sách sẽ tự động đồng bộ về bảng cảnh báo ở trên để đội ngũ an ninh
        thông tin xử lý.
      </p>
    </div>
  );
}
