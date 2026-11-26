'use client';

import { useState, type FormEvent } from 'react';
import { AlertCircle, Play, Server } from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { parseAddress } from './cidr-matcher';
import type { SimulationEnvironment } from './simulator-evaluator';
import {
  ServerSimulatorResultCard,
  type ServerSimulationResponse,
} from './server-simulator-result';

interface ServerSimulatorPanelProps {
  defaultEnvironment: SimulationEnvironment;
}

const MAX_PG_BIGINT = 9223372036854775807n;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const NIL_UUID = '00000000-0000-0000-0000-000000000000';

/**
 * Thuật toán: Kiểm Định Định Danh Số Nguyên Dương PostgreSQL `BIGINT` & UUID Tài Liệu (`isValidPositiveBigInt`, `isValidResourceDocumentIdentifier`)
 * Mục đích: Từ chối định danh `"0"`, số âm, tràn số `> 9223372036854775807` hoặc UUID rỗng trước khi gửi yêu cầu `POST /abac/simulate`.
 */
export function isValidPositiveBigInt(raw: string): boolean {
  const trimmed = raw.trim();
  if (!/^[1-9]\d*$/u.test(trimmed) || trimmed.length > 19) return false;
  try {
    const val = BigInt(trimmed);
    return val >= 1n && val <= MAX_PG_BIGINT;
  } catch {
    return false;
  }
}

export function isValidResourceDocumentIdentifier(raw: string): boolean {
  const trimmed = raw.trim();
  if (!trimmed) return false;
  return UUID_PATTERN.test(trimmed) && trimmed.toLowerCase() !== NIL_UUID;
}

export function isValidSimulationIpAddress(raw: string): boolean {
  const trimmed = raw.trim();
  if (!trimmed || trimmed.includes('/')) return false;
  return parseAddress(trimmed) !== null;
}

function formatInitialLocalDateTime(rawCurrentTime?: string): string {
  const base =
    rawCurrentTime && rawCurrentTime.includes('T') ? new Date(rawCurrentTime) : new Date();
  const safeDate = Number.isNaN(base.getTime()) ? new Date() : base;
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${safeDate.getFullYear()}-${pad(safeDate.getMonth() + 1)}-${pad(safeDate.getDate())}T${pad(safeDate.getHours())}:${pad(safeDate.getMinutes())}`;
}

/**
 * Thuật toán: Điều Phối Giả Lập Quyết Định Chính Sách Có Ghi Vết Kiểm Toán Phía Máy Chủ (`ServerSimulatorPanel`)
 * Mục đích: Kiểm định chặt `PositiveBigInt` (`1..9223372036854775807`), UUID tài liệu, địa chỉ IPv4/IPv6 nguồn và thời điểm mô phỏng `datetime-local` trước khi gửi `POST /abac/simulate`.
 */
export function ServerSimulatorPanel({ defaultEnvironment }: ServerSimulatorPanelProps) {
  const [subjectUserId, setSubjectUserId] = useState('1');
  const [resourceDocumentId, setResourceDocumentId] = useState('');
  const [action, setAction] = useState<'DISCOVER' | 'VIEW' | 'DOWNLOAD' | 'SHARE' | 'MANAGE'>(
    'VIEW',
  );
  const [ip, setIp] = useState(defaultEnvironment.ip || '127.0.0.1');
  const [simulationTime, setSimulationTime] = useState(() =>
    formatInitialLocalDateTime(defaultEnvironment.currentTime),
  );
  const [deviceTrust, setDeviceTrust] = useState(defaultEnvironment.deviceTrust);
  const [mfa, setMfa] = useState(defaultEnvironment.mfa);
  const [riskScore, setRiskScore] = useState(defaultEnvironment.riskScore);

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [serverResult, setServerResult] = useState<ServerSimulationResponse | null>(null);

  async function handleRunServerSimulation(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setErrorMsg(null);

    if (!isValidPositiveBigInt(subjectUserId)) {
      setErrorMsg(
        'Mã tài khoản người dùng phải là số nguyên dương hợp lệ (từ 1 đến 9223372036854775807).',
      );
      return;
    }
    if (!isValidResourceDocumentIdentifier(resourceDocumentId)) {
      setErrorMsg(
        'Mã tài liệu phải là mã UUID hợp lệ (ví dụ: 550e8400-e29b-41d4-a716-446655440000, không chấp nhận UUID rỗng).',
      );
      return;
    }
    const trimmedIp = ip.trim();
    if (!isValidSimulationIpAddress(trimmedIp)) {
      setErrorMsg('Địa chỉ IP nguồn không đúng định dạng IPv4 hoặc IPv6 hợp lệ.');
      return;
    }

    let resolvedIsoTime: string;
    if (simulationTime.trim()) {
      const parsedTime = new Date(simulationTime);
      if (Number.isNaN(parsedTime.getTime())) {
        setErrorMsg('Thời điểm mô phỏng không hợp lệ. Vui lòng chọn ngày giờ hợp lệ.');
        return;
      }
      resolvedIsoTime = parsedTime.toISOString();
    } else {
      resolvedIsoTime = new Date().toISOString();
    }

    setIsSubmitting(true);
    const startedAt = performance.now();
    try {
      const response = await apiClient<ServerSimulationResponse>('/abac/simulate', {
        method: 'POST',
        body: JSON.stringify({
          subjectUserId: subjectUserId.trim(),
          resourceDocumentId: resourceDocumentId.trim(),
          action,
          environment: {
            currentTime: resolvedIsoTime,
            ip: trimmedIp,
            deviceTrust,
            mfa,
            riskScore: Math.min(100, Math.max(0, Number(riskScore) || 0)),
          },
        }),
      });
      const elapsedMs = Math.round((performance.now() - startedAt) * 100) / 100;
      setServerResult({
        ...response,
        evaluationTimeMs: response.evaluationTimeMs ?? elapsedMs,
      });
    } catch (err) {
      setErrorMsg(
        err instanceof ApiError
          ? err.message || 'Mô phỏng chính sách trên máy chủ thất bại.'
          : 'Không thể kết nối máy chủ để thực hiện mô phỏng chính sách.',
      );
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <div className="space-y-4 text-xs">
      <form
        onSubmit={handleRunServerSimulation}
        noValidate
        className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-4 space-y-3"
      >
        <div className="flex items-center gap-2 font-bold text-[#222222]">
          <Server
            size={16}
            strokeWidth={1.75}
            className="text-[#008489] shrink-0"
            aria-hidden="true"
          />
          <span>
            Tham số mô phỏng trên máy chủ (mọi lượt kiểm thử được ghi nhận trong nhật ký kiểm toán)
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div className="space-y-1">
            <label htmlFor="sim-server-user-id" className="font-semibold text-[#222222] block">
              Mã tài khoản người dùng
            </label>
            <Input
              id="sim-server-user-id"
              value={subjectUserId}
              onChange={(e) => setSubjectUserId(e.target.value)}
              placeholder="VD: 1"
              className="min-h-11 sm:h-9 text-xs rounded-full border-[#dddddd] bg-[#ffffff]"
            />
          </div>

          <div className="space-y-1">
            <label htmlFor="sim-server-doc-id" className="font-semibold text-[#222222] block">
              Mã tài liệu
            </label>
            <Input
              id="sim-server-doc-id"
              value={resourceDocumentId}
              onChange={(e) => setResourceDocumentId(e.target.value)}
              placeholder="VD: 550e8400-e29b-41d4-a716-446655440000"
              className="min-h-11 sm:h-9 text-xs rounded-full border-[#dddddd] bg-[#ffffff] font-mono"
            />
          </div>

          <div className="space-y-1">
            <label htmlFor="sim-server-action" className="font-semibold text-[#222222] block">
              Thao tác kiểm tra
            </label>
            <select
              id="sim-server-action"
              value={action}
              onChange={(e) =>
                setAction(e.target.value as 'DISCOVER' | 'VIEW' | 'DOWNLOAD' | 'SHARE' | 'MANAGE')
              }
              className="w-full min-h-11 sm:h-9 text-xs rounded-full border border-[#dddddd] px-3 bg-[#ffffff] text-[#222222] focus-visible:outline-none focus-visible:border-[#222222] focus-visible:ring-2 focus-visible:ring-[#222222]/15"
            >
              <option value="DISCOVER">Tra cứu</option>
              <option value="VIEW">Chỉ xem</option>
              <option value="DOWNLOAD">Xem &amp; Tải về</option>
              <option value="SHARE">Chia sẻ</option>
              <option value="MANAGE">Quản trị</option>
            </select>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 pt-1">
          <div className="space-y-1">
            <label htmlFor="sim-server-ip" className="font-semibold text-[#222222] block">
              Địa chỉ IP nguồn
            </label>
            <Input
              id="sim-server-ip"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              placeholder="VD: 127.0.0.1 hoặc ::1"
              className="min-h-11 sm:h-9 text-xs rounded-full border-[#dddddd] bg-[#ffffff] font-mono"
            />
          </div>

          <div className="space-y-1">
            <label htmlFor="sim-server-current-time" className="font-semibold text-[#222222] block">
              Thời điểm mô phỏng
            </label>
            <Input
              id="sim-server-current-time"
              type="datetime-local"
              value={simulationTime}
              onChange={(e) => setSimulationTime(e.target.value)}
              className="min-h-11 sm:h-9 text-xs rounded-full border-[#dddddd] bg-[#ffffff]"
            />
          </div>

          <div className="space-y-1">
            <label htmlFor="sim-server-risk" className="font-semibold text-[#222222] block">
              Điểm rủi ro (0–100)
            </label>
            <Input
              id="sim-server-risk"
              type="number"
              min={0}
              max={100}
              value={riskScore}
              onChange={(e) => setRiskScore(Number(e.target.value))}
              className="min-h-11 sm:h-9 text-xs rounded-full border-[#dddddd] bg-[#ffffff]"
            />
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-4 pt-1">
          <label
            htmlFor="sim-server-device-trust"
            className="flex min-h-11 sm:min-h-9 items-center gap-2 font-medium text-[#222222] cursor-pointer"
          >
            <input
              id="sim-server-device-trust"
              type="checkbox"
              checked={deviceTrust}
              onChange={(e) => setDeviceTrust(e.target.checked)}
              className="h-4 w-4 accent-[#FF385C]"
            />
            <span>Thiết bị tin cậy</span>
          </label>

          <label
            htmlFor="sim-server-mfa"
            className="flex min-h-11 sm:min-h-9 items-center gap-2 font-medium text-[#222222] cursor-pointer"
          >
            <input
              id="sim-server-mfa"
              type="checkbox"
              checked={mfa}
              onChange={(e) => setMfa(e.target.checked)}
              className="h-4 w-4 accent-[#FF385C]"
            />
            <span>Đã xác thực MFA</span>
          </label>
        </div>

        <div className="flex justify-center pt-2">
          <Button
            type="submit"
            isLoading={isSubmitting}
            disabled={isSubmitting}
            className="rounded-full bg-[#FF385C] hover:bg-[#E31C5F] text-white px-6 min-h-11 sm:h-9 text-xs font-semibold flex items-center gap-2"
          >
            <Play size={16} strokeWidth={1.75} className="fill-current" aria-hidden="true" />
            <span>Chạy mô phỏng trên máy chủ</span>
          </Button>
        </div>
      </form>

      {errorMsg && (
        <Alert variant="destructive" className="rounded-[16px] text-xs">
          <AlertCircle size={16} strokeWidth={1.75} className="shrink-0" aria-hidden="true" />
          <AlertDescription className="ml-2">{errorMsg}</AlertDescription>
        </Alert>
      )}

      {serverResult && <ServerSimulatorResultCard serverResult={serverResult} />}
    </div>
  );
}
