'use client';

import { useEffect, useRef, useState } from 'react';
import { Code2, Check, Copy, AlertTriangle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card';

interface PolicyJsonPreviewProps {
  jsonText: string;
  jsonError: string | null;
  onChangeJsonText: (text: string) => void;
  onApplyJson: () => void;
}

export function PolicyJsonPreview({
  jsonText,
  jsonError,
  onChangeJsonText,
  onApplyJson,
}: PolicyJsonPreviewProps) {
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState<string | null>(null);
  const copyTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current) clearTimeout(copyTimerRef.current);
    };
  }, []);

  async function handleCopyJson() {
    setCopyError(null);
    try {
      await navigator.clipboard.writeText(jsonText);
      setCopied(true);
      if (copyTimerRef.current) clearTimeout(copyTimerRef.current);
      copyTimerRef.current = setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopyError('Không thể sao chép tự động. Vui lòng chọn và sao chép thủ công.');
    }
  }

  return (
    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-xs flex-1">
      <CardHeader className="pb-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <CardTitle className="text-base text-[#222222] flex items-center gap-2">
            <Code2 size={16} strokeWidth={1.75} className="text-[#FF385C]" aria-hidden="true" />
            <span>Cấu hình JSON nâng cao</span>
          </CardTitle>
          <CardDescription className="text-xs text-[#717171]">
            Xem hoặc chỉnh sửa trực tiếp định dạng JSON của quy tắc truy cập.
          </CardDescription>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => void handleCopyJson()}
            className="rounded-full text-xs min-h-11 sm:h-9 border-[#dddddd] flex items-center gap-1.5"
          >
            {copied ? (
              <Check size={16} strokeWidth={1.75} className="text-[#008A05]" aria-hidden="true" />
            ) : (
              <Copy size={16} strokeWidth={1.75} aria-hidden="true" />
            )}
            <span>{copied ? 'Đã sao chép' : 'Sao chép JSON'}</span>
          </Button>
          <Button
            type="button"
            size="sm"
            onClick={onApplyJson}
            className="rounded-full bg-[#FF385C] hover:bg-[#E31C5F] text-white text-xs min-h-11 sm:h-9 font-semibold"
          >
            Áp dụng sang trình kéo thả
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {(jsonError || copyError) && (
          <div className="p-3 rounded-[12px] bg-[#C13515]/10 border border-[#dddddd] text-xs text-[#C13515] flex items-center gap-2">
            <AlertTriangle size={16} strokeWidth={1.75} className="shrink-0" aria-hidden="true" />
            <span>{jsonError || copyError}</span>
          </div>
        )}
        <textarea
          aria-label="Nội dung JSON của chính sách truy cập"
          value={jsonText}
          onChange={(e) => onChangeJsonText(e.target.value)}
          rows={20}
          className="w-full font-mono text-xs p-4 rounded-[16px] bg-[#222222] text-[#f7f7f7] border border-[#dddddd] focus-visible:outline-none focus-visible:border-[#222222] focus-visible:ring-2 focus-visible:ring-[#222222]/25"
          spellCheck={false}
        />
      </CardContent>
    </Card>
  );
}
