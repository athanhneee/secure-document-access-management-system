'use client';

import { useState, type FormEvent } from 'react';
import { AlertTriangle, CheckCircle2, QrCode, Search } from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { mapWatermarkVerifyDto } from '../helpers';
import type { WatermarkProvenance, WatermarkVerifyDto } from '../types';

interface WatermarkForensicsTabProps {
  onClearError: () => void;
  onMessage: (message: string) => void;
  onError: (errorMessage: string) => void;
}

export function WatermarkForensicsTab({
  onClearError,
  onMessage,
  onError,
}: WatermarkForensicsTabProps) {
  const [wmInputToken, setWmInputToken] = useState('');
  const [wmTraceResult, setWmTraceResult] = useState<WatermarkProvenance | null>(null);
  const [isTracingWm, setIsTracingWm] = useState(false);

  /**
   * Thuật toán: Đối soát Chứng cứ Truy nguyên Thủy vân Mật mã Chế độ Fail-Closed (`handleTraceWatermark`)
   * Mục đích: Xác định chính xác tài liệu gốc, người nhận, mã nhân viên, IP phiên đọc và thời điểm cấp phát từ mã thủy vân `WM-...` thu được trên bản sao rò rỉ.
   * Cơ chế hoạt động: Mã hóa URI tham số `wmInputToken`, truy vấn điểm cuối `/watermarks/verify/:token`, kiểm chứng nghiêm ngặt `provenance.verified === true` và từ chối mọi phản hồi thiếu cờ xác thực.
   */
  async function handleTraceWatermark(e: FormEvent) {
    e.preventDefault();
    if (!wmInputToken.trim()) return;

    setIsTracingWm(true);
    onClearError();
    setWmTraceResult(null);

    try {
      const res = await apiClient<WatermarkVerifyDto>(
        `/watermarks/verify/${encodeURIComponent(wmInputToken.trim())}`,
      );
      const provenance = mapWatermarkVerifyDto(res);
      setWmTraceResult(provenance);
      if (provenance.verified) {
        onMessage('Đã hoàn tất đối soát chứng cứ dấu bản quyền.');
      } else {
        onError('Phản hồi đối soát không có cờ xác thực hợp lệ (Fail-Closed).');
      }
    } catch (err) {
      if (err instanceof ApiError) {
        onError(err.message || 'Mã watermark không tồn tại hoặc không hợp lệ.');
      } else {
        onError('Không thể đối soát mã watermark.');
      }
    } finally {
      setIsTracingWm(false);
    }
  }

  return (
    <div className="grid gap-6 md:grid-cols-2">
      <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
        <CardHeader>
          <CardTitle className="text-base text-[#222222]">
            Tra cứu dấu bản quyền (Watermark Forensic)
          </CardTitle>
          <CardDescription className="text-xs text-[#717171]">
            UC28: Nhập mã token trên tài liệu rò rỉ để đối chiếu xuất xứ, thời điểm và người nhận
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4 text-xs">
          <form onSubmit={handleTraceWatermark} className="space-y-3">
            <div className="space-y-1">
              <label htmlFor="wm-token-input" className="font-medium text-[#222222]">
                Mã Token Watermark (Dạng WM-...)
              </label>
              <Input
                id="wm-token-input"
                value={wmInputToken}
                onChange={(e) => setWmInputToken(e.target.value)}
                placeholder="Ví dụ: WM-8f3a9b2c1e7d4410"
                className="h-9 font-bold text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#008A05] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
              />
            </div>

            <InteractiveHoverButton
              type="submit"
              variant="primary"
              size="md"
              text="Đối soát xuất xứ tài liệu"
              icon={<Search size={16} strokeWidth={1.75} aria-hidden="true" />}
              isLoading={isTracingWm}
              disabled={isTracingWm || !wmInputToken.trim()}
              className="w-full"
            />
          </form>

          <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-1.5 text-[#717171] text-[11px] leading-relaxed">
            <p>
              <strong>Nguyên lý:</strong> Mỗi lần người dùng bấm xem hoặc tải tài liệu, hệ thống
              sinh ra một Watermark Instance gắn với phiên Access Session và Document Version cụ
              thể.
            </p>
            <p>
              Token được tạo ngẫu nhiên bằng CSPRNG, tuyệt đối không suy đoán được và liên kết chặt
              chẽ vào nhật ký kiểm toán HMAC-SHA256.
            </p>
          </div>
        </CardContent>
      </Card>

      <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)] flex flex-col justify-between">
        <CardHeader className="pb-3">
          <CardTitle className="text-base text-[#222222]">Kết quả đối soát bằng chứng</CardTitle>
          <CardDescription className="text-xs text-[#717171]">
            Thông tin truy nguyên người chịu trách nhiệm phát tán
          </CardDescription>
        </CardHeader>
        <CardContent className="flex-1 flex flex-col justify-center text-xs">
          {wmTraceResult ? (
            wmTraceResult.verified ? (
              <div className="space-y-3 rounded-[24px] border border-[#008A05]/20 bg-[#008A05]/5 p-4">
                <div className="flex items-center gap-2 text-[#008A05] font-semibold border-b border-[#008A05]/15 pb-2">
                  <CheckCircle2 size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Đối soát thành công · Bằng chứng hợp lệ</span>
                </div>
                <div className="grid grid-cols-2 gap-2 text-[#222222]">
                  <span className="text-[#717171]">Tài liệu:</span>
                  <span className="font-semibold text-[#222222]">
                    {wmTraceResult.documentTitle}
                  </span>

                  <span className="text-[#717171]">Mã số tài liệu:</span>
                  <span className="font-bold text-[#222222]">{wmTraceResult.documentCode}</span>

                  <span className="text-[#717171]">Mức độ mật:</span>
                  <span className="font-semibold text-[#C13515]">
                    {wmTraceResult.classificationName}
                  </span>

                  <span className="text-[#717171]">Người nhận cấp quyền:</span>
                  <span className="font-semibold text-[#222222]">
                    {wmTraceResult.recipientName}
                  </span>

                  <span className="text-[#717171]">Mã nhân viên (EMP):</span>
                  <span className="font-bold text-[#008A05]">{wmTraceResult.employeeCode}</span>

                  <span className="text-[#717171]">Địa chỉ IP phiên:</span>
                  <span className="font-bold text-[#222222]">{wmTraceResult.ipAddress}</span>

                  <span className="text-[#717171]">Thời điểm tạo phiên:</span>
                  <span className="font-bold text-[#222222]">{wmTraceResult.generatedAtUtc}</span>

                  <span className="text-[#717171]">Session ID:</span>
                  <span className="font-bold text-[10px] text-[#717171]">
                    {wmTraceResult.sessionId}
                  </span>
                </div>
              </div>
            ) : (
              <div className="space-y-2 rounded-[24px] border border-[#C13515]/20 bg-[#C13515]/5 p-4 text-[#C13515]">
                <div className="flex items-center gap-2 font-semibold">
                  <AlertTriangle size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Chưa xác thực · Không đủ căn cứ pháp chứng</span>
                </div>
                <p className="text-[#717171] text-[11px]">
                  Phản hồi không chứa xác nhận mật mã hợp lệ từ sổ cái đối soát. Hệ thống từ chối
                  hiển thị thông tin quy kết (Fail-Closed).
                </p>
              </div>
            )
          ) : (
            <div className="flex flex-col items-center justify-center text-center p-8 text-[#717171] space-y-2">
              {/* CONFLICT-RESOLVED: Giới hạn icon QrCode tối đa 24px chuẩn strokeWidth 1.75 thay cho 40px (rules/ui-design-system.md §2) */}
              <QrCode size={24} strokeWidth={1.75} className="text-[#b0b0b0]" aria-hidden="true" />
              <p>Nhập mã token ở bên trái và bấm đối soát để hiển thị thông tin chứng cứ</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
