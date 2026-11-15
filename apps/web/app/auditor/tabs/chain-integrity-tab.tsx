'use client';

import { AlertTriangle, CheckCircle2, Hash, Shield } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
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
  const partitionName = verificationReport?.chainPartition || 'GLOBAL';

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm sm:text-base text-[#222222]">
            Xác minh chuỗi băm HMAC-SHA256
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3.5 text-xs">
          <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3.5 space-y-2 text-[#222222]">
            <div className="flex justify-between gap-2">
              <span className="text-[#717171]">Phân vùng chuỗi</span>
              <span className="font-mono text-[#008489] text-right">{partitionName}</span>
            </div>
            <div className="flex justify-between gap-2">
              <span className="text-[#717171]">Thuật toán băm</span>
              <span className="font-mono text-[#222222] text-right">HMAC-SHA-256</span>
            </div>
            <div className="flex justify-between gap-2">
              <span className="text-[#717171]">Khóa toàn vẹn</span>
              <span className="font-semibold text-[#008A05] text-right">
                Lưu trữ độc lập CSDL (KMS/Vault)
              </span>
            </div>
          </div>

          <InteractiveHoverButton
            variant="primary"
            size="md"
            text="Xác minh toàn bộ chuỗi"
            icon={<Hash size={16} strokeWidth={1.75} aria-hidden="true" />}
            isLoading={isVerifyingChain}
            disabled={isVerifyingChain}
            onClick={onVerifyHashChain}
            className="w-full"
          />
        </CardContent>
      </Card>

      <Card className="flex flex-col justify-between">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm sm:text-base text-[#222222]">
            Kết quả đối soát mật mã
          </CardTitle>
        </CardHeader>
        <CardContent className="flex-1 flex flex-col justify-center text-xs">
          {verificationReport ? (
            verificationReport.isChainValid ? (
              <div className="space-y-3 rounded-[18px] border border-[#008A05]/20 bg-[#008A05]/5 p-4">
                <div className="flex items-center gap-2 text-[#008A05] font-semibold border-b border-[#008A05]/15 pb-2">
                  <CheckCircle2 size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>
                    {verificationReport.totalEntriesChecked === 0
                      ? 'CHƯA CÓ BẢN GHI / HỢP LỆ'
                      : 'Chuỗi băm toàn vẹn · Không phát hiện giả mạo'}
                  </span>
                </div>
                <div className="space-y-1.5 text-[#222222]">
                  <div className="flex justify-between gap-2">
                    <span className="text-[#717171]">Phân vùng đối soát:</span>
                    <span className="font-bold text-[#008489] text-right">{partitionName}</span>
                  </div>
                  <div className="flex justify-between gap-2">
                    <span className="text-[#717171]">Số bản ghi đã duyệt:</span>
                    <span className="font-bold text-[#222222]">
                      {verificationReport.totalEntriesChecked} entries
                    </span>
                  </div>
                  <div className="flex justify-between gap-2">
                    <span className="text-[#717171]">Hành vi chỉnh sửa/xóa:</span>
                    <span className="text-[#008A05] font-semibold">0 (Không có)</span>
                  </div>
                  <div className="flex justify-between gap-2">
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
                  <div className="flex justify-between gap-2">
                    <span className="text-[#717171]">Phân vùng đối soát:</span>
                    <span className="font-bold text-[#008489] text-right">{partitionName}</span>
                  </div>
                  <div className="flex justify-between gap-2">
                    <span className="text-[#717171]">Số bản ghi đã duyệt:</span>
                    <span className="font-bold text-[#222222]">
                      {verificationReport.totalEntriesChecked} entries
                    </span>
                  </div>
                  <div className="flex justify-between gap-2">
                    <span className="text-[#717171]">Số điểm đứt gãy / sai lệch:</span>
                    <span className="text-[#C13515] font-bold">
                      {verificationReport.brokenSequences.length} vi phạm
                    </span>
                  </div>
                  <div className="flex justify-between gap-2">
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
            <div className="flex flex-col items-center justify-center text-center py-6 px-4 text-[#717171] space-y-2">
              <Shield size={24} strokeWidth={1.75} className="text-[#717171]" aria-hidden="true" />
              <p>Bấm nút xác minh bên trái để rà soát liên kết chuỗi băm</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
