'use client';

import { useState } from 'react';
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

  return (
    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-xs flex-1">
      <CardHeader className="pb-3 flex flex-row items-center justify-between">
        <div>
          <CardTitle className="text-base text-[#222222] flex items-center gap-2">
            <Code2 size={16} strokeWidth={1.75} className="text-[#FF385C]" aria-hidden="true" />
            <span>Trình Soạn Thảo JSON AST Trực Tiếp</span>
          </CardTitle>
          <CardDescription className="text-xs text-[#717171]">
            Xem hoặc chỉnh sửa trực tiếp biểu diễn trừu tượng (Abstract Syntax Tree) của quy tắc.
          </CardDescription>
        </div>
        <div className="flex items-center gap-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => {
              navigator.clipboard.writeText(jsonText);
              setCopied(true);
              setTimeout(() => setCopied(false), 2000);
            }}
            className="rounded-full text-xs h-8 border-[#dddddd] flex items-center gap-1.5"
          >
            {copied ? (
              <Check size={16} strokeWidth={1.75} className="text-[#008A05]" aria-hidden="true" />
            ) : (
              <Copy size={16} strokeWidth={1.75} aria-hidden="true" />
            )}
            <span>{copied ? 'Đã sao chép!' : 'Sao chép JSON'}</span>
          </Button>
          <Button
            type="button"
            size="sm"
            onClick={onApplyJson}
            className="rounded-full bg-[#FF385C] hover:bg-[#E31C5F] text-white text-xs h-8 font-semibold"
          >
            Cập nhật vào Trình Kéo Thả
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {jsonError && (
          <div className="p-3 rounded-[12px] bg-[#C13515]/10 border border-[#C13515]/30 text-xs text-[#C13515] flex items-center gap-2">
            <AlertTriangle size={16} strokeWidth={1.75} className="shrink-0" aria-hidden="true" />
            <span>{jsonError}</span>
          </div>
        )}
        <textarea
          aria-label="Biểu diễn JSON AST của chính sách ABAC"
          value={jsonText}
          onChange={(e) => onChangeJsonText(e.target.value)}
          rows={20}
          className="w-full font-mono text-xs p-4 rounded-[16px] bg-[#222222] text-[#f7f7f7] border border-[#dddddd] focus:outline-none focus:border-[#FF385C]"
          spellCheck={false}
        />
      </CardContent>
    </Card>
  );
}
