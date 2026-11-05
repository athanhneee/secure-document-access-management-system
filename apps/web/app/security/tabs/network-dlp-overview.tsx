'use client';

import { Activity, Cpu, ShieldAlert, ShieldCheck } from 'lucide-react';
import { Badge } from '@/components/ui/badge';

export function NetworkDlpOverview() {
  return (
    <>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3.5 space-y-1">
          <div className="flex items-center justify-between text-xs text-[#717171]">
            <span>Giao thức mạng</span>
            <Cpu size={16} strokeWidth={1.75} className="text-[#008489]" aria-hidden="true" />
          </div>
          <div className="text-sm font-bold text-[#222222]">ICAP/1.0 (RFC 3507)</div>
          <p className="text-[11px] text-[#717171]">Lắng nghe cổng TCP 1344 (IANA Standard)</p>
        </div>

        <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3.5 space-y-1">
          <div className="flex items-center justify-between text-xs text-[#717171]">
            <span>Cơ chế kiểm tra</span>
            <Activity size={16} strokeWidth={1.75} className="text-[#008A05]" aria-hidden="true" />
          </div>
          <div className="text-sm font-bold text-[#222222]">RESPMOD & REQMOD</div>
          <p className="text-[11px] text-[#717171]">Hỗ trợ Preview Chunks & 204 No-Mod</p>
        </div>

        <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3.5 space-y-1">
          <div className="flex items-center justify-between text-xs text-[#717171]">
            <span>Chính sách phản hồi</span>
            <ShieldAlert
              size={16}
              strokeWidth={1.75}
              className="text-[#C13515]"
              aria-hidden="true"
            />
          </div>
          <div className="text-sm font-bold text-[#C13515]">HTTP 403 Forbidden</div>
          <p className="text-[11px] text-[#717171]">Chặn luồng vi phạm kèm trang cảnh báo SDA</p>
        </div>

        <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-3.5 space-y-1">
          <div className="flex items-center justify-between text-xs text-[#717171]">
            <span>Luồng sạch (Clean Pass)</span>
            <ShieldCheck
              size={16}
              strokeWidth={1.75}
              className="text-[#008A05]"
              aria-hidden="true"
            />
          </div>
          <div className="text-sm font-bold text-[#008A05]">204 No modifications</div>
          <p className="text-[11px] text-[#717171]">
            Chuyển tiếp tức thì, không giữ buffer dữ liệu
          </p>
        </div>
      </div>

      <div className="space-y-3">
        <h3 className="text-xs font-bold text-[#222222] uppercase tracking-wider">
          Các chính sách phân tích rò rỉ dữ liệu (Inspection Policies)
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
          <div className="rounded-[16px] border border-[#ebebeb] p-3 space-y-1.5 bg-[#ffffff]">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-[#222222]">
                Nhãn phân loại mật quốc gia & doanh nghiệp
              </span>
              <Badge variant="danger">BẮT BUỘC</Badge>
            </div>
            <p className="text-[11px] text-[#717171]">
              Quét nội dung chứa nhãn <span className="font-mono font-medium">TUYỆT MẬT</span>,{' '}
              <span className="font-mono font-medium">TỐI MẬT</span>,{' '}
              <span className="font-mono font-medium">TOP SECRET</span>,{' '}
              <span className="font-mono font-medium">STRICTLY CONFIDENTIAL</span> gửi ra Internet.
            </p>
          </div>

          <div className="rounded-[16px] border border-[#ebebeb] p-3 space-y-1.5 bg-[#ffffff]">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-[#222222]">
                Thủy ấn số pháp chứng rò rỉ (Watermark Leak)
              </span>
              <Badge variant="primary">PHÁP CHỨNG</Badge>
            </div>
            <p className="text-[11px] text-[#717171]">
              Phát hiện các mã token thủy ấn bí mật định dạng{' '}
              <span className="font-mono font-medium">{'WM-[a-f0-9]{48}'}</span> bị người dùng cố ý
              sao chép hoặc tuồn qua đường mạng biên.
            </p>
          </div>

          <div className="rounded-[16px] border border-[#ebebeb] p-3 space-y-1.5 bg-[#ffffff]">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-[#222222]">
                Khóa bí mật & Tokens truy cập (Secrets/Keys)
              </span>
              <Badge variant="warning">BẢO VỆ KHÓA</Badge>
            </div>
            <p className="text-[11px] text-[#717171]">
              Ngăn chặn rò rỉ <span className="font-mono font-medium">PEM RSA/EC Private Keys</span>
              , <span className="font-mono font-medium">AWS Access Key (AKIA...)</span>,{' '}
              <span className="font-mono font-medium">GitHub Personal Access Token (ghp_...)</span>.
            </p>
          </div>

          <div className="rounded-[16px] border border-[#ebebeb] p-3 space-y-1.5 bg-[#ffffff]">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-[#222222]">
                Thẻ tài chính quốc tế & CCCD Việt Nam (PII)
              </span>
              <Badge variant="info">DỮ LIỆU CÁ NHÂN</Badge>
            </div>
            <p className="text-[11px] text-[#717171]">
              Kiểm tra số thẻ Visa / MasterCard / Amex bằng{' '}
              <span className="font-medium">thuật toán Luhn Checksum</span> và số Căn cước công dân
              12 chữ số theo quy chuẩn quốc gia.
            </p>
          </div>
        </div>
      </div>
    </>
  );
}

export function NetworkDlpBlueprint() {
  return (
    <div className="rounded-[16px] border border-[#ebebeb] bg-[#f7f7f7] p-4 space-y-2 text-xs">
      <div className="font-bold text-[#222222] flex items-center gap-1.5">
        <Cpu size={16} strokeWidth={1.75} className="text-[#008489]" aria-hidden="true" />
        <span>Cấu hình tích hợp Gateway DLP chuyên dụng (Edge Proxy / Firewall / NextGen DLP)</span>
      </div>
      <p className="text-[#717171] leading-relaxed">
        Để kết nối Squid Proxy hoặc các cổng biên mạng (Symantec, Forcepoint, BlueCoat, F5) với máy
        chủ ICAP của hệ thống, thêm định tuyến ICAP service vào cấu hình proxy:
      </p>
      <div className="p-3 bg-[#222222] text-[#f7f7f7] rounded-[12px] font-mono text-[11px] overflow-x-auto space-y-1">
        <div># squid.conf - Network DLP ICAP Service Integration</div>
        <div className="text-[#008489]">icap_enable on</div>
        <div>icap_service sda_dlp respmod_precache icap://127.0.0.1:1344/dlp-respmod bypass=0</div>
        <div>adaptation_access sda_dlp allow all</div>
      </div>
    </div>
  );
}
