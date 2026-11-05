'use client';

import { AlertTriangle, CheckCircle2, Hash, Shield } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import type { ChainVerificationReport } from '../types';

interface ChainIntegrityTabProps {
  verificationReport: ChainVerificationReport | null;
  isVerifyingChain: boolean;
  onVerifyHashChain: () => void;
}

export function ChainIntegrityTab({
  verificationReport,
  isVerifyingChain,
  onVerifyHashChain,
}: ChainIntegrityTabProps) {
  return (
    <div className="grid gap-6 md:grid-cols-2">
      <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
        <CardHeader>
          <CardTitle className="text-base text-[#222222]">
            Kiểm tra tính toàn vẹn chuỗi băm HMAC
          </CardTitle>
          <CardDescription className="text-xs text-[#717171]">
            Tự động tính toán lại chữ ký HMAC-SHA256 từng bản ghi để phát hiện mọi hành vi sửa, xóa
            hoặc chèn trái phép
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4 text-xs">
          <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-2 text-[#222222]">
            <div className="flex justify-between">
              <span className="text-[#717171]">Phân vùng chuỗi (Partition):</span>
              {/* CONFLICT-RESOLVED: Chuẩn hóa màu tên phân vùng sang màu info chính thức #008489 theo rules/ui-design-system.md §5 */}
              <span className="font-bold text-[#008489]">GLOBAL_CHAIN</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#717171]">Thuật toán băm:</span>
              <span className="font-bold text-[#222222]">HMAC-SHA-256</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#717171]">Khóa toàn vẹn:</span>
              <span className="font-bold text-[#008A05]">Lưu trữ bên ngoài CSDL (KMS/Vault)</span>
            </div>
          </div>

          <InteractiveHoverButton
            variant="primary"
            size="md"
            text="Tiến hành xác minh toàn bộ chuỗi"
            icon={<Hash size={16} strokeWidth={1.75} aria-hidden="true" />}
            isLoading={isVerifyingChain}
            disabled={isVerifyingChain}
            onClick={onVerifyHashChain}
            className="w-full"
          />
        </CardContent>
      </Card>

      <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)] flex flex-col justify-between">
        <CardHeader className="pb-3">
          <CardTitle className="text-base text-[#222222]">
            Báo cáo xác minh toàn vẹn mật mã
          </CardTitle>
          <CardDescription className="text-xs text-[#717171]">
            Kết quả kiểm chứng liên kết previous_hash và sequence
          </CardDescription>
        </CardHeader>
        <CardContent className="flex-1 flex flex-col justify-center text-xs">
          {verificationReport ? (
            verificationReport.isChainValid ? (
              <div className="space-y-3 rounded-[24px] border border-[#008A05]/20 bg-[#008A05]/5 p-4">
                <div className="flex items-center gap-2 text-[#008A05] font-semibold border-b border-[#008A05]/15 pb-2">
                  <CheckCircle2 size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Chuỗi băm toàn vẹn · Không phát hiện giả mạo</span>
                </div>
                <div className="space-y-1.5 text-[#222222]">
                  <div className="flex justify-between">
                    <span className="text-[#717171]">Số bản ghi đã duyệt:</span>
                    <span className="font-bold text-[#222222]">
                      {verificationReport.totalEntriesChecked} entries
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#717171]">Hành vi chỉnh sửa/xóa:</span>
                    <span className="text-[#008A05] font-semibold">0 (Không có)</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#717171]">Thời điểm xác minh:</span>
                    <span className="font-bold text-[#222222]">
                      {new Date(verificationReport.verifiedAt).toLocaleTimeString('vi-VN')}
                    </span>
                  </div>
                </div>
              </div>
            ) : (
              <div className="space-y-3 rounded-[24px] border border-[#C13515]/30 bg-[#C13515]/5 p-4">
                <div className="flex items-center gap-2 text-[#C13515] font-semibold border-b border-[#C13515]/20 pb-2">
                  <AlertTriangle
                    size={16}
                    strokeWidth={1.75}
                    className="shrink-0"
                    aria-hidden="true"
                  />
                  <span>Cảnh báo: Phát hiện sai lệch / giả mạo chuỗi băm!</span>
                </div>
                <div className="space-y-1.5 text-[#222222]">
                  <div className="flex justify-between">
                    <span className="text-[#717171]">Số bản ghi đã duyệt:</span>
                    <span className="font-bold text-[#222222]">
                      {verificationReport.totalEntriesChecked} entries
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#717171]">Số điểm đứt gãy / sai lệch:</span>
                    <span className="text-[#C13515] font-bold">
                      {verificationReport.brokenSequences.length} vi phạm
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[#717171]">Thời điểm xác minh:</span>
                    <span className="font-bold text-[#222222]">
                      {new Date(verificationReport.verifiedAt).toLocaleTimeString('vi-VN')}
                    </span>
                  </div>
                  {verificationReport.brokenSequences.length > 0 && (
                    <ul className="mt-2 max-h-28 overflow-y-auto space-y-1 border-t border-[#C13515]/15 pt-2 text-xs text-[#C13515]">
                      {verificationReport.brokenSequences.map((violation, idx) => (
                        <li key={idx}>• {String(violation)}</li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            )
          ) : (
            <div className="flex flex-col items-center justify-center text-center p-8 text-[#717171] space-y-2">
              {/* // CONFLICT-RESOLVED: Giới hạn kích thước icon Shield về mức tối đa 24px (thay cho h-10 w-10 = 40px) theo rules/ui-design-system.md. */}
              <Shield size={24} strokeWidth={1.75} className="text-[#b0b0b0]" aria-hidden="true" />
              <p>
                Bấm nút xác minh ở bên trái để kích hoạt thuật toán rà soát liên kết cryptographic
                chain
              </p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
