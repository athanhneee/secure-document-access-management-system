'use client';

import { Activity, Cpu, ShieldAlert, ShieldCheck } from 'lucide-react';
import { Badge } from '@/components/ui/badge';

export function NetworkDlpOverview() {
  return (
    <>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-0.5">
          <div className="flex items-center justify-between text-xs text-[#717171]">
            <span>Giao thức</span>
            <Cpu size={16} strokeWidth={1.75} className="text-[#008489]" aria-hidden="true" />
          </div>
          <div className="text-sm font-bold text-[#222222]">ICAP/1.0 · TCP 1344</div>
        </div>

        <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-0.5">
          <div className="flex items-center justify-between text-xs text-[#717171]">
            <span>Chế độ quét</span>
            <Activity size={16} strokeWidth={1.75} className="text-[#008A05]" aria-hidden="true" />
          </div>
          <div className="text-sm font-bold text-[#222222]">RESPMOD &amp; REQMOD</div>
        </div>

        <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-0.5">
          <div className="flex items-center justify-between text-xs text-[#717171]">
            <span>Vi phạm</span>
            <ShieldAlert
              size={16}
              strokeWidth={1.75}
              className="text-[#C13515]"
              aria-hidden="true"
            />
          </div>
          <div className="text-sm font-bold text-[#C13515]">HTTP 403 Forbidden</div>
        </div>

        <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3 space-y-0.5">
          <div className="flex items-center justify-between text-xs text-[#717171]">
            <span>Luồng sạch</span>
            <ShieldCheck
              size={16}
              strokeWidth={1.75}
              className="text-[#008A05]"
              aria-hidden="true"
            />
          </div>
          <div className="text-sm font-bold text-[#008A05]">204 No modifications</div>
        </div>
      </div>

      <div className="space-y-2.5">
        <h3 className="text-xs font-bold text-[#222222] uppercase tracking-wider">
          Chính sách kiểm duyệt nội dung (Inspection Policies)
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
          <div className="rounded-[16px] border border-[#ebebeb] p-3 space-y-1 bg-[#ffffff]">
            <div className="flex items-center justify-between gap-2">
              <span className="font-semibold text-[#222222]">Nhãn phân loại mật</span>
              <Badge variant="danger">BẮT BUỘC</Badge>
            </div>
            <p className="text-xs text-[#717171]">
              Chặn nhãn <span className="font-mono">TUYỆT MẬT</span>,{' '}
              <span className="font-mono">TỐI MẬT</span>,{' '}
              <span className="font-mono">TOP SECRET</span>,{' '}
              <span className="font-mono">STRICTLY CONFIDENTIAL</span>.
            </p>
          </div>

          <div className="rounded-[16px] border border-[#ebebeb] p-3 space-y-1 bg-[#ffffff]">
            <div className="flex items-center justify-between gap-2">
              <span className="font-semibold text-[#222222]">Thủy ấn số pháp chứng</span>
              <Badge variant="primary">PHÁP CHỨNG</Badge>
            </div>
            <p className="text-xs text-[#717171]">
              Phát hiện token định dạng <span className="font-mono">{'WM-[a-f0-9]{48}'}</span> gửi
              qua cổng biên mạng.
            </p>
          </div>

          <div className="rounded-[16px] border border-[#ebebeb] p-3 space-y-1 bg-[#ffffff]">
            <div className="flex items-center justify-between gap-2">
              <span className="font-semibold text-[#222222]">Khóa bí mật &amp; Token</span>
              <Badge variant="warning">BẢO VỆ KHÓA</Badge>
            </div>
            <p className="text-xs text-[#717171]">
              Chặn <span className="font-mono">PEM Private Keys</span>,{' '}
              <span className="font-mono">AKIA...</span>, <span className="font-mono">ghp_...</span>
              .
            </p>
          </div>

          <div className="rounded-[16px] border border-[#ebebeb] p-3 space-y-1 bg-[#ffffff]">
            <div className="flex items-center justify-between gap-2">
              <span className="font-semibold text-[#222222]">Thẻ thanh toán &amp; CCCD</span>
              <Badge variant="info">PII</Badge>
            </div>
            <p className="text-xs text-[#717171]">
              Kiểm tra số thẻ quốc tế (Luhn Checksum) và CCCD 12 chữ số.
            </p>
          </div>
        </div>
      </div>
    </>
  );
}

export function NetworkDlpBlueprint() {
  return (
    <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3.5 space-y-2 text-xs">
      <div className="font-bold text-[#222222] flex items-center gap-1.5">
        <Cpu size={16} strokeWidth={1.75} className="text-[#008489]" aria-hidden="true" />
        <span>Cấu hình định tuyến Proxy / Edge Gateway (ICAP)</span>
      </div>
      <div className="p-3 bg-[#222222] text-[#f7f7f7] rounded-[12px] font-mono text-xs overflow-x-auto space-y-1">
        <div># squid.conf</div>
        <div className="text-[#ffffff]">icap_enable on</div>
        <div>icap_service sda_dlp respmod_precache icap://127.0.0.1:1344/dlp-respmod bypass=0</div>
        <div>adaptation_access sda_dlp allow all</div>
      </div>
    </div>
  );
}
