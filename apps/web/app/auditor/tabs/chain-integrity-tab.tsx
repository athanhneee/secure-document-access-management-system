'use client';

import { AlertTriangle, Anchor, CheckCircle2, Download, Hash, Shield } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { formatAuditPartitionLabel, formatSafeDateVi } from '@/lib/ui-labels';
import { AUDIT_PARTITION_OPTIONS, downloadVerificationReportJson } from '../helpers';
import type { AuditAnchorItem, ChainVerificationReport } from '../types';

interface ChainIntegrityTabProps {
  verificationReport: ChainVerificationReport | null;
  anchors: AuditAnchorItem[];
  verifyPartition: string;
  isVerifyingChain: boolean;
  onVerifyPartitionChange: (partition: string) => void;
  onVerifyHashChain: () => Promise<void>;
}

/**
 * Thuật toán: Giao Diện Kiểm Chứng Toàn Vẹn Chuỗi Băm Đa Phân Vùng, Biên Bản JSON & Danh Mục Điểm Neo Chữ Ký (`ChainIntegrityTab`)
 * Mục đích: Cho phép kiểm toán viên chọn đối soát toàn hệ thống hoặc từng phân vùng, hiển thị trung thực phạm vi điểm neo, số thứ tự vi phạm `#sequence`, xuất biên bản JSON và xem danh sách điểm neo HMAC ở chế độ chỉ đọc.
 */
export function ChainIntegrityTab({
  verificationReport,
  anchors,
  verifyPartition,
  isVerifyingChain,
  onVerifyPartitionChange,
  onVerifyHashChain,
}: ChainIntegrityTabProps) {
  const partitionName = verificationReport
    ? verificationReport.chainPartition
    : verifyPartition === 'ALL'
      ? 'Toàn hệ thống'
      : formatAuditPartitionLabel(verifyPartition);

  const scopeDescription = verificationReport
    ? verificationReport.resumedFromAnchors
      ? 'Đối soát điểm neo HMAC + số lượng bản ghi trước điểm neo + toàn bộ mắt xích mới'
      : 'Quét toàn phần từ mắt xích khởi đầu (#1)'
    : 'Đối soát chữ ký HMAC-SHA256, liên kết mắt xích và điểm neo toàn vẹn';

  return (
    <div className="space-y-4">
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm sm:text-base text-[#222222]">
              Kiểm tra tính toàn vẹn nhật ký
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3.5 text-xs">
            <div className="space-y-1.5">
              <label htmlFor="auditor-verify-partition" className="font-medium text-[#222222]">
                Phạm vi phân vùng đối soát
              </label>
              <select
                id="auditor-verify-partition"
                value={verifyPartition}
                onChange={(e) => onVerifyPartitionChange(e.target.value)}
                disabled={isVerifyingChain}
                className="min-h-11 sm:h-9 w-full rounded-full border border-[#dddddd] bg-[#ffffff] px-3.5 text-xs text-[#222222] focus:border-[#FF385C] focus:outline-none cursor-pointer disabled:opacity-60"
              >
                <option value="ALL">Tất cả phân vùng kiểm toán</option>
                {AUDIT_PARTITION_OPTIONS.filter((p) => p !== 'ALL').map((partition) => (
                  <option key={partition} value={partition}>
                    {formatAuditPartitionLabel(partition)}
                  </option>
                ))}
              </select>
            </div>

            <div className="rounded-[20px] border border-[#ebebeb] bg-[#f7f7f7] p-3.5 space-y-2 text-[#222222]">
              <div className="flex justify-between gap-2">
                <span className="text-[#717171]">Phân vùng dữ liệu</span>
                <span className="font-semibold text-[#008489] text-right">{partitionName}</span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-[#717171]">Cơ chế kiểm chứng</span>
                <span className="font-medium text-[#222222] text-right">
                  Chuỗi băm RFC 8785 (HMAC-SHA256)
                </span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-[#717171]">Phạm vi đối soát</span>
                <span className="font-semibold text-[#008A05] text-right">{scopeDescription}</span>
              </div>
            </div>

            <InteractiveHoverButton
              variant="primary"
              size="md"
              text="Kiểm tra tính toàn vẹn"
              icon={<Hash size={16} strokeWidth={1.75} aria-hidden="true" />}
              isLoading={isVerifyingChain}
              disabled={isVerifyingChain}
              onClick={onVerifyHashChain}
              className="w-full"
            />
          </CardContent>
        </Card>

        <Card className="flex flex-col justify-between">
          <CardHeader className="pb-3 flex flex-row items-center justify-between gap-2">
            <CardTitle className="text-sm sm:text-base text-[#222222]">
              Kết quả kiểm tra toàn vẹn
            </CardTitle>
            {verificationReport && (
              <InteractiveHoverButton
                type="button"
                size="sm"
                variant="secondary"
                text="Tải biên bản JSON"
                icon={<Download size={16} strokeWidth={1.75} aria-hidden="true" />}
                onClick={() => downloadVerificationReportJson(verificationReport)}
              />
            )}
          </CardHeader>
          <CardContent className="flex-1 flex flex-col justify-center text-xs">
            {verificationReport ? (
              verificationReport.isChainValid ? (
                <div className="space-y-3 rounded-[20px] border border-[#008A05]/20 bg-[#008A05]/5 p-4">
                  <div className="flex items-center gap-2 text-[#008A05] font-semibold border-b border-[#008A05]/15 pb-2">
                    <CheckCircle2 size={16} strokeWidth={1.75} aria-hidden="true" />
                    <span>
                      {verificationReport.totalEntriesChecked === 0
                        ? 'Chưa có bản ghi kiểm toán nào'
                        : 'Chuỗi nhật ký toàn vẹn · Không phát hiện sai lệch'}
                    </span>
                  </div>
                  <div className="space-y-1.5 text-[#222222]">
                    <div className="flex justify-between gap-2">
                      <span className="text-[#717171]">Phân vùng đối soát:</span>
                      <span className="font-semibold text-[#008489] text-right">
                        {partitionName}
                      </span>
                    </div>
                    <div className="flex justify-between gap-2">
                      <span className="text-[#717171]">Số bản ghi đã kiểm tra:</span>
                      <span className="font-semibold text-[#222222] tabular-nums">
                        {verificationReport.totalEntriesChecked} bản ghi
                      </span>
                    </div>
                    <div className="flex justify-between gap-2">
                      <span className="text-[#717171]">Điểm neo chữ ký đã đối soát:</span>
                      <span className="font-semibold text-[#222222] tabular-nums">
                        {verificationReport.totalAnchorsChecked} điểm neo
                      </span>
                    </div>
                    <div className="flex justify-between gap-2">
                      <span className="text-[#717171]">Dấu hiệu chỉnh sửa / xóa:</span>
                      <span className="text-[#008A05] font-semibold">0 (Không phát hiện)</span>
                    </div>
                    <div className="flex justify-between gap-2">
                      <span className="text-[#717171]">Thời điểm kiểm tra:</span>
                      <span className="font-medium text-[#222222] tabular-nums">
                        {formatSafeDateVi(verificationReport.verifiedAt, { includeTime: true })}
                      </span>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="space-y-3 rounded-[20px] border border-[#C13515]/30 bg-[#C13515]/5 p-4">
                  <div className="flex items-center gap-2 text-[#C13515] font-semibold border-b border-[#C13515]/20 pb-2">
                    <AlertTriangle
                      size={16}
                      strokeWidth={1.75}
                      className="shrink-0"
                      aria-hidden="true"
                    />
                    <span>Cảnh báo: Phát hiện sai lệch tính toàn vẹn nhật ký</span>
                  </div>
                  <div className="space-y-1.5 text-[#222222]">
                    <div className="flex justify-between gap-2">
                      <span className="text-[#717171]">Phân vùng đối soát:</span>
                      <span className="font-semibold text-[#008489] text-right">
                        {partitionName}
                      </span>
                    </div>
                    <div className="flex justify-between gap-2">
                      <span className="text-[#717171]">Số bản ghi đã kiểm tra:</span>
                      <span className="font-semibold text-[#222222] tabular-nums">
                        {verificationReport.totalEntriesChecked} bản ghi
                      </span>
                    </div>
                    <div className="flex justify-between gap-2">
                      <span className="text-[#717171]">Điểm neo chữ ký đã đối soát:</span>
                      <span className="font-semibold text-[#222222] tabular-nums">
                        {verificationReport.totalAnchorsChecked} điểm neo
                      </span>
                    </div>
                    <div className="flex justify-between gap-2">
                      <span className="text-[#717171]">Số điểm đứt gãy / sai lệch:</span>
                      <span className="text-[#C13515] font-semibold tabular-nums">
                        {verificationReport.brokenSequences.length} vị trí
                      </span>
                    </div>
                    <div className="flex justify-between gap-2">
                      <span className="text-[#717171]">Thời điểm kiểm tra:</span>
                      <span className="font-medium text-[#222222] tabular-nums">
                        {formatSafeDateVi(verificationReport.verifiedAt, { includeTime: true })}
                      </span>
                    </div>
                    {verificationReport.brokenSequences.length > 0 && (
                      <ol className="mt-2 max-h-36 overflow-y-auto space-y-1 border-t border-[#C13515]/15 pt-2 text-xs text-[#C13515] list-decimal list-inside">
                        {verificationReport.brokenSequences.map((violation, idx) => (
                          <li key={idx}>{violation}</li>
                        ))}
                      </ol>
                    )}
                  </div>
                </div>
              )
            ) : (
              <div className="flex flex-col items-center justify-center text-center py-6 px-4 text-[#717171] space-y-2">
                <Shield
                  size={24}
                  strokeWidth={1.75}
                  className="text-[#717171]"
                  aria-hidden="true"
                />
                <p>Bấm nút kiểm tra để rà soát tính toàn vẹn của chuỗi nhật ký kiểm toán.</p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm sm:text-base text-[#222222] flex items-center gap-2">
            <Anchor size={16} strokeWidth={1.75} className="text-[#008489]" aria-hidden="true" />
            <span>Điểm neo chữ ký mật mã (Chỉ đọc · {anchors.length})</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <div className="md:hidden divide-y divide-[#ebebeb]">
            {anchors.length === 0 ? (
              <div className="px-4 py-6 text-center text-xs text-[#717171]">
                Chưa có điểm neo chữ ký HMAC nào được khởi tạo.
              </div>
            ) : (
              anchors.map((a) => (
                <div key={a.id} className="p-3.5 space-y-1.5 text-xs">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-[#222222]">
                      {formatAuditPartitionLabel(a.chainPartition)} · #{a.anchorSequence}
                    </span>
                    <Badge variant={a.status === 'INVALID' ? 'destructive' : 'success'}>
                      {a.status === 'INVALID' ? 'Sai lệch' : 'Hợp lệ'}
                    </Badge>
                  </div>
                  <div className="font-mono text-[#717171] truncate">{a.entryHash}</div>
                  <div className="text-[#717171] tabular-nums">
                    Khóa {a.signerKeyId || 'v1'} ·{' '}
                    {formatSafeDateVi(a.anchoredAt, { includeTime: true })}
                  </div>
                </div>
              ))
            )}
          </div>

          <div className="hidden md:block">
            <Table>
              <caption className="sr-only">
                Danh sách điểm neo chữ ký HMAC của các phân vùng kiểm toán
              </caption>
              <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
                <TableRow>
                  <TableHead className="text-xs text-[#717171]">Phân vùng</TableHead>
                  <TableHead className="text-xs text-[#717171]">Số thứ tự neo</TableHead>
                  <TableHead className="text-xs text-[#717171]">Mã băm bản ghi</TableHead>
                  <TableHead className="text-xs text-[#717171]">Khóa ký</TableHead>
                  <TableHead className="text-xs text-[#717171]">Thời điểm neo</TableHead>
                  <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {anchors.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="py-6 text-center text-xs text-[#717171]">
                      Chưa có điểm neo chữ ký HMAC nào được khởi tạo.
                    </TableCell>
                  </TableRow>
                ) : (
                  anchors.map((a) => (
                    <TableRow key={a.id} className="border-b border-[#ebebeb]">
                      <TableCell className="font-semibold text-xs text-[#222222]">
                        {formatAuditPartitionLabel(a.chainPartition)}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-[#222222]">
                        #{a.anchorSequence}
                      </TableCell>
                      <TableCell title={a.entryHash} className="font-mono text-xs text-[#717171]">
                        {a.entryHash.slice(0, 20)}…
                      </TableCell>
                      <TableCell className="font-mono text-xs text-[#717171]">
                        {a.signerKeyId || 'v1'}
                      </TableCell>
                      <TableCell className="text-xs text-[#717171] whitespace-nowrap tabular-nums">
                        {formatSafeDateVi(a.anchoredAt, { includeTime: true })}
                      </TableCell>
                      <TableCell>
                        <Badge variant={a.status === 'INVALID' ? 'destructive' : 'success'}>
                          {a.status === 'INVALID' ? 'Sai lệch' : 'Hợp lệ'}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
