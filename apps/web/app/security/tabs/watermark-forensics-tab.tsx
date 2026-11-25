'use client';

import { useState, type FormEvent } from 'react';
import { AlertTriangle, CheckCircle2, QrCode, Search } from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { mapWatermarkVerifyDto, normalizeWatermarkTokenInput } from '../helpers';
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
  const [validationError, setValidationError] = useState<string | null>(null);
  const [wmTraceResult, setWmTraceResult] = useState<WatermarkProvenance | null>(null);
  const [isTracingWm, setIsTracingWm] = useState(false);

  /**
   * Thuật toán: Chuẩn Hóa Token Watermark Phía Client & Đối Soát Chứng Cứ Fail-Closed (`handleTraceWatermark`)
   * Mục đích: Tự động ghép tiền tố `WM-` khi chuyên viên SOC dán chuỗi hex `12..48` ký tự từ PDF thiếu `WM-`; từ chối sớm trên form nếu sai định dạng, sau đó truy vấn `/watermarks/verify/:token` và bắt buộc `provenance.verified === true`.
   */
  async function handleTraceWatermark(e: FormEvent) {
    e.preventDefault();
    onClearError();

    const normalized = normalizeWatermarkTokenInput(wmInputToken);
    if (!normalized.valid) {
      setValidationError(normalized.error);
      setWmTraceResult(null);
      return;
    }

    setValidationError(null);
    setWmInputToken(normalized.token);
    setIsTracingWm(true);
    setWmTraceResult(null);

    try {
      const res = await apiClient<WatermarkVerifyDto>(
        `/watermarks/verify/${encodeURIComponent(normalized.token)}`,
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
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm sm:text-base text-[#222222]">
            Tra cứu dấu bản quyền (Watermark Forensic)
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3.5 text-xs">
          <form onSubmit={handleTraceWatermark} className="space-y-3" noValidate>
            <div className="space-y-1.5">
              <label htmlFor="wm-token-input" className="font-medium text-[#222222]">
                Mã Token Watermark (12–48 ký tự hex)
              </label>
              <Input
                id="wm-token-input"
                value={wmInputToken}
                onChange={(e) => {
                  setWmInputToken(e.target.value);
                  if (validationError) setValidationError(null);
                }}
                placeholder="Ví dụ: WM-2e59958fa6c7 hoặc WM-<48-hex>"
                aria-invalid={Boolean(validationError)}
                className="min-h-11 sm:h-9 font-mono text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#008A05] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
              />
              {validationError && (
                <p role="alert" className="text-xs font-medium text-[#C13515] pt-0.5">
                  {validationError}
                </p>
              )}
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

          <p className="rounded-[14px] border border-[#ebebeb] bg-[#f7f7f7] px-3 py-2 text-[#717171] text-xs leading-relaxed">
            Hỗ trợ dán mã <code>WM-...</code> hoặc chuỗi hex 12–48 ký tự trích xuất trực tiếp từ lớp
            watermark PDF để truy nguyên phiên đọc/tải.
          </p>
        </CardContent>
      </Card>

      <Card className="flex flex-col justify-between">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm sm:text-base text-[#222222]">
            Kết quả đối soát bằng chứng
          </CardTitle>
        </CardHeader>
        <CardContent className="flex-1 flex flex-col justify-center text-xs">
          {wmTraceResult ? (
            wmTraceResult.verified ? (
              <div className="space-y-3 rounded-[18px] border border-[#008A05]/20 bg-[#008A05]/5 p-4">
                <div className="flex items-center gap-2 text-[#008A05] font-semibold border-b border-[#008A05]/15 pb-2">
                  <CheckCircle2 size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Đối soát thành công · Bằng chứng hợp lệ</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-2.5 text-[#222222]">
                  <div className="min-w-0">
                    <div className="text-[#717171]">Tài liệu</div>
                    <div className="font-semibold text-[#222222] break-words">
                      {wmTraceResult.documentTitle}
                    </div>
                  </div>
                  <div className="min-w-0">
                    <div className="text-[#717171]">Mã tài liệu</div>
                    <div className="font-mono text-[#222222] break-all">
                      {wmTraceResult.documentCode}
                    </div>
                  </div>
                  <div className="min-w-0">
                    <div className="text-[#717171]">Mức độ mật</div>
                    <div className="font-semibold text-[#C13515]">
                      {wmTraceResult.classificationName}
                    </div>
                  </div>
                  <div className="min-w-0">
                    <div className="text-[#717171]">Người nhận</div>
                    <div className="font-semibold text-[#222222]">
                      {wmTraceResult.recipientName}
                    </div>
                  </div>
                  <div className="min-w-0">
                    <div className="text-[#717171]">Mã nhân viên</div>
                    <div className="font-mono text-[#008A05]">{wmTraceResult.employeeCode}</div>
                  </div>
                  <div className="min-w-0">
                    <div className="text-[#717171]">Địa chỉ IP</div>
                    <div className="font-mono text-[#222222]">{wmTraceResult.ipAddress}</div>
                  </div>
                  <div className="min-w-0">
                    <div className="text-[#717171]">Thời điểm tạo</div>
                    <div className="font-semibold text-[#222222]">
                      {wmTraceResult.generatedAtUtc}
                    </div>
                  </div>
                  <div className="min-w-0">
                    <div className="text-[#717171]">Session ID</div>
                    <div className="font-mono text-[#717171] break-all">
                      {wmTraceResult.sessionId}
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="space-y-2 rounded-[18px] border border-[#C13515]/20 bg-[#C13515]/5 p-4 text-[#C13515]">
                <div className="flex items-center gap-2 font-semibold">
                  <AlertTriangle size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Chưa xác thực · Không đủ căn cứ pháp chứng</span>
                </div>
                <p className="text-[#717171] text-xs">
                  Phản hồi không chứa xác nhận mật mã hợp lệ từ sổ cái đối soát (Fail-Closed).
                </p>
              </div>
            )
          ) : (
            <div className="flex flex-col items-center justify-center text-center py-6 px-4 text-[#717171] space-y-2">
              <QrCode size={24} strokeWidth={1.75} className="text-[#717171]" aria-hidden="true" />
              <p>Nhập mã token bên trái và bấm đối soát để xem kết quả</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
