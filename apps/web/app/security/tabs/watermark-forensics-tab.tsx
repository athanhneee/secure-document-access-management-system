'use client';

import { useState, type FormEvent } from 'react';
import { Check, CheckCircle2, Copy, FilePlus2, QrCode, RotateCcw, Search } from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import { formatSafeDateVi } from '@/lib/ui-labels';
import { mapWatermarkVerifyDto, normalizeWatermarkTokenInput } from '../helpers';
import type { IncidentDraftPrefill, WatermarkProvenance, WatermarkVerifyDto } from '../types';

interface WatermarkForensicsTabProps {
  canCreateIncident?: boolean | undefined;
  onCreateIncidentFromWatermark?: ((prefill: IncidentDraftPrefill) => void) | undefined;
  onClearError: () => void;
  onMessage: (message: string) => void;
  onError: (errorMessage: string) => void;
}

/**
 * Thuật toán: Truy Vết Watermark Pháp Chứng Hỗ Trợ Dán QR JSON & Hiển Thị Đủ 8 Trường Bằng Chứng (`WatermarkForensicsTab`)
 * Mục đích:
 *   - Cho phép nhập `WM-<12..64hex>`, dán chuỗi QR JSON `{"token":"WM-..."}` hoặc dải chữ PDF (N14, #47).
 *   - Hiển thị đầy đủ mã băm `outputSha256Hash`, `originalSha256Hash`, `renderedText`, `userAgent`, `recipientEmail`, `configSummary` và loại bỏ nhánh chết `verified === false` (#21, #34, #41).
 */
export function WatermarkForensicsTab({
  canCreateIncident = false,
  onCreateIncidentFromWatermark,
  onClearError,
  onMessage,
  onError,
}: WatermarkForensicsTabProps) {
  const [wmInputToken, setWmInputToken] = useState('');
  const [validationError, setValidationError] = useState<string | null>(null);
  const [wmTraceResult, setWmTraceResult] = useState<WatermarkProvenance | null>(null);
  const [isTracingWm, setIsTracingWm] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  async function handleCopyValue(value: string, key: string) {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey((prev) => (prev === key ? null : prev)), 2000);
    } catch {
      onError('Không thể sao chép tự động. Vui lòng chọn và sao chép thủ công.');
    }
  }

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
      if (provenance.verified) {
        setWmTraceResult(provenance);
        onMessage('Đã hoàn tất đối soát thông tin watermark bảo mật.');
      } else {
        onError('Không thể xác nhận tính hợp lệ của mã watermark này.');
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
            Truy vết watermark bảo mật
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3.5 text-xs">
          <form onSubmit={handleTraceWatermark} className="space-y-3" noValidate>
            <div className="space-y-1.5">
              <label htmlFor="wm-token-input" className="font-medium text-[#222222]">
                Mã truy vết watermark hoặc nội dung mã QR
              </label>
              <Input
                id="wm-token-input"
                value={wmInputToken}
                onChange={(e) => {
                  setWmInputToken(e.target.value);
                  if (validationError) setValidationError(null);
                }}
                placeholder="VD: WM-2e59958fa6c7 hoặc dán chuỗi JSON quét từ mã QR"
                aria-invalid={Boolean(validationError)}
                className="min-h-11 sm:h-9 font-mono text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#008A05] placeholder:text-[#717171] focus-visible:border-[#FF385C]"
              />
              {validationError && (
                <p role="alert" className="text-xs font-medium text-[#C13515] pt-0.5">
                  {validationError}
                </p>
              )}
            </div>

            <div className="flex flex-col sm:flex-row gap-2">
              <InteractiveHoverButton
                type="submit"
                variant="primary"
                size="md"
                text="Đối soát nguồn gốc tài liệu"
                icon={<Search size={16} strokeWidth={1.75} aria-hidden="true" />}
                isLoading={isTracingWm}
                disabled={isTracingWm || !wmInputToken.trim()}
                className="flex-1"
              />
              {(wmInputToken || wmTraceResult) && (
                <InteractiveHoverButton
                  type="button"
                  variant="secondary"
                  size="md"
                  text="Đặt lại"
                  icon={<RotateCcw size={16} strokeWidth={1.75} aria-hidden="true" />}
                  onClick={() => {
                    setWmInputToken('');
                    setValidationError(null);
                    setWmTraceResult(null);
                    onClearError();
                  }}
                />
              )}
            </div>
          </form>

          <p className="rounded-[14px] border border-[#ebebeb] bg-[#f7f7f7] px-3 py-2 text-[#717171] text-xs leading-relaxed">
            Hỗ trợ nhập mã rút gọn <code>WM-&lt;12-hex&gt;</code> in trên trang PDF, mã đầy đủ 48 ký
            tự hex, hoặc dán trực tiếp chuỗi JSON quét từ mã QR góc trang để truy xuất bằng chứng
            pháp chứng.
          </p>
        </CardContent>
      </Card>

      <Card className="flex flex-col justify-between">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm sm:text-base text-[#222222]">
            Kết quả truy vết nguồn gốc
          </CardTitle>
        </CardHeader>
        <CardContent className="flex-1 flex flex-col justify-center text-xs">
          {wmTraceResult ? (
            <div className="space-y-3 rounded-[18px] border border-[#008A05]/20 bg-[#008A05]/5 p-4">
              <div className="flex flex-wrap items-center justify-between gap-2 text-[#008A05] font-semibold border-b border-[#008A05]/15 pb-2">
                <div className="flex items-center gap-2">
                  <CheckCircle2 size={16} strokeWidth={1.75} aria-hidden="true" />
                  <span>Đối soát thành công · Mã watermark hợp lệ</span>
                </div>
                {canCreateIncident && onCreateIncidentFromWatermark && (
                  <InteractiveHoverButton
                    type="button"
                    size="sm"
                    variant="secondary"
                    text="Lập hồ sơ sự cố"
                    icon={<FilePlus2 size={16} strokeWidth={1.75} aria-hidden="true" />}
                    onClick={() =>
                      onCreateIncidentFromWatermark({
                        title: `Truy vết rò rỉ tài liệu ${wmTraceResult.documentCode}`,
                        summary: `Đối soát mã watermark ${wmTraceResult.watermarkToken} xác định bản sao của tài liệu "${wmTraceResult.documentTitle}" (${wmTraceResult.classificationName}) được cấp cho ${wmTraceResult.recipientName} (${wmTraceResult.employeeCode}) từ IP ${wmTraceResult.ipAddress} trong phiên ${wmTraceResult.sessionId}.`,
                      })
                    }
                  />
                )}
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-2.5 text-[#222222]">
                <div className="min-w-0">
                  <div className="text-[#717171]">Tài liệu</div>
                  <div className="font-semibold text-[#222222] break-words">
                    {wmTraceResult.documentTitle}
                  </div>
                </div>
                <div className="min-w-0">
                  <div className="text-[#717171]">Mã tài liệu &amp; phiên bản</div>
                  <div className="font-mono text-[#222222] break-all">
                    {wmTraceResult.documentCode}
                    {wmTraceResult.versionNo !== null ? ` · v${wmTraceResult.versionNo}` : ''}
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
                  <div className="font-semibold text-[#222222]">{wmTraceResult.recipientName}</div>
                  <div className="text-[#717171] break-all">{wmTraceResult.recipientEmail}</div>
                </div>
                <div className="min-w-0">
                  <div className="text-[#717171]">Mã nhân viên</div>
                  <div className="font-mono text-[#008A05]">{wmTraceResult.employeeCode}</div>
                </div>
                <div className="min-w-0">
                  <div className="text-[#717171]">Địa chỉ IP &amp; Thiết bị</div>
                  <div className="font-mono text-[#222222]">{wmTraceResult.ipAddress}</div>
                  <div className="text-[#717171] truncate" title={wmTraceResult.userAgent}>
                    {wmTraceResult.userAgent}
                  </div>
                </div>
                <div className="min-w-0">
                  <div className="text-[#717171]">Thời điểm đóng dấu</div>
                  <div className="font-semibold text-[#222222]">
                    {formatSafeDateVi(wmTraceResult.generatedAtUtc, { includeTime: true })}
                  </div>
                </div>
                <div className="min-w-0">
                  <div className="text-[#717171]">Cấu hình watermark</div>
                  <div className="text-[#222222] break-words">{wmTraceResult.configSummary}</div>
                </div>
                <div className="min-w-0 sm:col-span-2">
                  <div className="text-[#717171]">Mã phiên đọc</div>
                  <div className="font-mono text-[#717171] break-all">
                    {wmTraceResult.sessionId}
                  </div>
                </div>
                <div className="min-w-0 sm:col-span-2">
                  <div className="text-[#717171]">Chuỗi văn bản watermark đã đóng dấu</div>
                  <div className="font-mono text-[#222222] break-all rounded-[10px] bg-[#ffffff] border border-[#ebebeb] px-2.5 py-1.5 mt-0.5">
                    {wmTraceResult.renderedText}
                  </div>
                </div>
                <div className="min-w-0 sm:col-span-2 space-y-1.5 pt-1 border-t border-[#008A05]/15">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[#717171]">SHA-256 tệp đầu ra (có watermark)</span>
                    <button
                      type="button"
                      onClick={() => void handleCopyValue(wmTraceResult.outputSha256Hash, 'out')}
                      aria-label="Sao chép mã băm SHA-256 tệp có watermark"
                      className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium text-[#222222] hover:bg-[#ffffff] cursor-pointer"
                    >
                      {copiedKey === 'out' ? (
                        <Check
                          size={16}
                          strokeWidth={2}
                          className="text-[#008A05]"
                          aria-hidden="true"
                        />
                      ) : (
                        <Copy size={16} strokeWidth={1.75} aria-hidden="true" />
                      )}
                      <span>{copiedKey === 'out' ? 'Đã chép' : 'Sao chép'}</span>
                    </button>
                  </div>
                  <div className="font-mono text-[#222222] break-all">
                    {wmTraceResult.outputSha256Hash}
                  </div>
                  <div className="text-[#717171] pt-1">SHA-256 tệp tài liệu gốc</div>
                  <div className="font-mono text-[#717171] break-all">
                    {wmTraceResult.originalSha256Hash}
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center text-center py-6 px-4 text-[#717171] space-y-2">
              <QrCode size={24} strokeWidth={1.75} className="text-[#717171]" aria-hidden="true" />
              <p>
                Nhập mã watermark hoặc dán chuỗi QR và bấm đối soát để xem bằng chứng pháp chứng.
              </p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
