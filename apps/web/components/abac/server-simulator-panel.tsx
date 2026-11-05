'use client';

import { useState, type FormEvent } from 'react';
import { AlertCircle, CheckCircle2, Play, Server, XCircle } from 'lucide-react';
import { apiClient, ApiError } from '@/lib/api-client';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import type { SimulationEnvironment } from './simulator-evaluator';

interface ServerSimulationResponse {
  decision: 'PERMIT' | 'DENY';
  reasonCode: string;
  obligations?: Array<{ type: string; minutes?: number }>;
  matchedRules?: string[];
  matchedRuleIds?: string[];
  policyVersion?: string;
  evaluationTimeMs?: number;
}

interface ServerSimulatorPanelProps {
  defaultEnvironment: SimulationEnvironment;
}

/**
 * Thuật toán: Điều Phối Giả Lập Quyết Định Chính Sách Có Ghi Vết Kiểm Toán Phía Máy Chủ (`ServerSimulatorPanel`)
 * Mục đích: Gửi yêu cầu `POST /abac/simulate` tới PDP thực tế để đối chiếu quyết định, mã lý do, nghĩa vụ và danh sách quy tắc khớp trên dữ liệu CSDL thật.
 */
export function ServerSimulatorPanel({ defaultEnvironment }: ServerSimulatorPanelProps) {
  const [subjectUserId, setSubjectUserId] = useState('1');
  const [resourceDocumentId, setResourceDocumentId] = useState('');
  const [action, setAction] = useState<'DISCOVER' | 'VIEW' | 'DOWNLOAD' | 'SHARE' | 'MANAGE'>(
    'VIEW',
  );
  const [ip, setIp] = useState(defaultEnvironment.ip || '127.0.0.1');
  const [deviceTrust, setDeviceTrust] = useState(defaultEnvironment.deviceTrust);
  const [mfa, setMfa] = useState(defaultEnvironment.mfa);
  const [riskScore, setRiskScore] = useState(defaultEnvironment.riskScore);

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [serverResult, setServerResult] = useState<ServerSimulationResponse | null>(null);

  async function handleRunServerSimulation(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setErrorMsg(null);

    if (!/^\d+$/u.test(subjectUserId.trim())) {
      setErrorMsg('Mã người dùng (subjectUserId) phải là chuỗi số nguyên dương.');
      return;
    }
    if (!resourceDocumentId.trim()) {
      setErrorMsg('Vui lòng nhập UUID tài liệu (resourceDocumentId) cần mô phỏng.');
      return;
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
            currentTime: new Date().toISOString(),
            ip: ip.trim() || '127.0.0.1',
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
          ? err.message || 'Mô phỏng PDP máy chủ thất bại.'
          : 'Không thể kết nối điểm cuối mô phỏng /abac/simulate.',
      );
    } finally {
      setIsSubmitting(false);
    }
  }

  const matchedList = serverResult?.matchedRules ?? serverResult?.matchedRuleIds ?? [];

  return (
    <div className="space-y-4 text-xs">
      <form
        onSubmit={handleRunServerSimulation}
        className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-4 space-y-3"
      >
        <div className="flex items-center gap-2 font-bold text-[#222222]">
          <Server size={16} strokeWidth={1.75} className="text-[#008489]" aria-hidden="true" />
          <span>Tham số đánh giá PDP Máy chủ (Có ghi nhận nhật ký kiểm toán POLICY_SIMULATED)</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div className="space-y-1">
            <label htmlFor="sim-server-user-id" className="font-semibold text-[#222222] block">
              ID Người dùng (subjectUserId)
            </label>
            <Input
              id="sim-server-user-id"
              value={subjectUserId}
              onChange={(e) => setSubjectUserId(e.target.value)}
              placeholder="VD: 1"
              className="h-8 text-xs rounded-full border-[#dddddd] bg-[#ffffff]"
            />
          </div>

          <div className="space-y-1">
            <label htmlFor="sim-server-doc-id" className="font-semibold text-[#222222] block">
              UUID Tài liệu (resourceDocumentId)
            </label>
            <Input
              id="sim-server-doc-id"
              value={resourceDocumentId}
              onChange={(e) => setResourceDocumentId(e.target.value)}
              placeholder="00000000-0000-0000-0000-000000000000"
              className="h-8 text-xs rounded-full border-[#dddddd] bg-[#ffffff] font-mono"
            />
          </div>

          <div className="space-y-1">
            <label htmlFor="sim-server-action" className="font-semibold text-[#222222] block">
              Hành động kiểm tra
            </label>
            <select
              id="sim-server-action"
              value={action}
              onChange={(e) =>
                setAction(e.target.value as 'DISCOVER' | 'VIEW' | 'DOWNLOAD' | 'SHARE' | 'MANAGE')
              }
              className="w-full h-8 text-xs rounded-full border border-[#dddddd] px-3 bg-[#ffffff] text-[#222222]"
            >
              <option value="DISCOVER">DISCOVER</option>
              <option value="VIEW">VIEW</option>
              <option value="DOWNLOAD">DOWNLOAD</option>
              <option value="SHARE">SHARE</option>
              <option value="MANAGE">MANAGE</option>
            </select>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 pt-1">
          <div className="space-y-1">
            <label htmlFor="sim-server-ip" className="font-semibold text-[#222222] block">
              Địa chỉ IP nguồn
            </label>
            <Input
              id="sim-server-ip"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              className="h-8 text-xs rounded-full border-[#dddddd] bg-[#ffffff] font-mono"
            />
          </div>

          <div className="space-y-1">
            <label htmlFor="sim-server-risk" className="font-semibold text-[#222222] block">
              Điểm rủi ro (0-100)
            </label>
            <Input
              id="sim-server-risk"
              type="number"
              min={0}
              max={100}
              value={riskScore}
              onChange={(e) => setRiskScore(Number(e.target.value))}
              className="h-8 text-xs rounded-full border-[#dddddd] bg-[#ffffff]"
            />
          </div>

          <div className="flex items-end pb-1.5">
            <label
              htmlFor="sim-server-device-trust"
              className="flex items-center gap-2 font-medium text-[#222222] cursor-pointer"
            >
              <input
                id="sim-server-device-trust"
                type="checkbox"
                checked={deviceTrust}
                onChange={(e) => setDeviceTrust(e.target.checked)}
                className="h-4 w-4 accent-[#FF385C]"
              />
              <span>Thiết bị tin cậy (MDM)</span>
            </label>
          </div>

          <div className="flex items-end pb-1.5">
            <label
              htmlFor="sim-server-mfa"
              className="flex items-center gap-2 font-medium text-[#222222] cursor-pointer"
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
        </div>

        <div className="flex justify-center pt-2">
          <Button
            type="submit"
            isLoading={isSubmitting}
            disabled={isSubmitting}
            className="rounded-full bg-[#FF385C] hover:bg-[#E31C5F] text-white px-6 h-9 text-xs font-semibold flex items-center gap-2"
          >
            <Play size={16} strokeWidth={1.75} className="fill-current" aria-hidden="true" />
            <span>Thực Thi Mô Phỏng Máy Chủ (/abac/simulate)</span>
          </Button>
        </div>
      </form>

      {errorMsg && (
        <Alert
          variant="destructive"
          className="rounded-[16px] border border-[#C13515]/30 bg-[#C13515]/10 text-[#C13515] text-xs"
        >
          <AlertCircle size={16} strokeWidth={1.75} className="shrink-0" aria-hidden="true" />
          <AlertDescription className="ml-2">{errorMsg}</AlertDescription>
        </Alert>
      )}

      {serverResult && (
        <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-4 space-y-2.5">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#ebebeb] pb-2.5">
            <div className="flex items-center gap-2">
              {serverResult.decision === 'PERMIT' ? (
                <CheckCircle2
                  size={16}
                  strokeWidth={1.75}
                  className="text-[#008A05]"
                  aria-hidden="true"
                />
              ) : (
                <XCircle
                  size={16}
                  strokeWidth={1.75}
                  className="text-[#C13515]"
                  aria-hidden="true"
                />
              )}
              <Badge variant={serverResult.decision === 'PERMIT' ? 'success' : 'danger'}>
                {serverResult.decision}
              </Badge>
              <span className="font-mono text-[#717171]">
                Reason: <strong className="text-[#222222]">{serverResult.reasonCode}</strong>
              </span>
            </div>
            <span className="font-mono text-[#717171]">
              Thời gian đánh giá:{' '}
              <strong className="text-[#222222]">{serverResult.evaluationTimeMs}ms</strong>
            </span>
          </div>

          <div className="flex flex-wrap gap-3 text-[11px] text-[#717171]">
            <span>
              Quy tắc khớp:{' '}
              <strong className="font-mono text-[#222222]">
                {matchedList.length > 0 ? matchedList.join(', ') : '—'}
              </strong>
            </span>
            <span>·</span>
            <span>
              Nghĩa vụ:{' '}
              <strong className="font-mono text-[#008489]">
                {serverResult.obligations && serverResult.obligations.length > 0
                  ? serverResult.obligations.map((o) => o.type).join(', ')
                  : 'Không có'}
              </strong>
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
