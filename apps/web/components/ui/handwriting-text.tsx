'use client';

/**
 * Thuật toán: Hiệu Ứng Hiện Chữ Từ Từ Kiểu Viết Tay Không Giật Bố Cục (`HandwritingText`)
 * Mục đích:
 *   - Tách cụm ký tự tiếng Việt (grapheme cluster) qua `Intl.Segmenter` và nhóm theo từng từ (`whitespace-nowrap`) kết hợp giữ chỗ vô hình phần chưa viết để loại bỏ hoàn toàn hiện tượng nhảy dòng khi đang hiện chữ.
 *   - Điều phối nhịp viết tự nhiên theo `requestAnimationFrame` (nhanh ở khoảng trắng, nghỉ nhẹ ở dấu câu `,` `.` `:`), hiện chữ mượt mà không cần con trỏ nhấp nháy và tự động tắt hiệu ứng khi người dùng bật `prefers-reduced-motion: reduce`.
 */
import { useEffect, useMemo, useState } from 'react';
import { cn } from '@/lib/utils';

export interface HandwritingSegment {
  text: string;
  strong?: boolean | undefined;
  className?: string | undefined;
}

export interface HandwritingTextProps {
  text?: string | undefined;
  segments?: readonly HandwritingSegment[] | undefined;
  active: boolean;
  startDelayMs?: number | undefined;
  charIntervalMs?: number | undefined;
  maxDurationMs?: number | undefined;
  className?: string | undefined;
}

interface LayoutToken {
  rawText: string;
  graphemes: string[];
  startIndex: number;
  endIndex: number;
  isSpace: boolean;
  strong?: boolean | undefined;
  className?: string | undefined;
}

function splitGraphemes(value: string): string[] {
  if (typeof Intl !== 'undefined' && typeof Intl.Segmenter === 'function') {
    const segmenter = new Intl.Segmenter('vi', { granularity: 'grapheme' });
    const parts: string[] = [];
    for (const item of segmenter.segment(value)) {
      parts.push(item.segment);
    }
    return parts;
  }
  return Array.from(value);
}

function buildLayoutPlan(
  segments: readonly HandwritingSegment[],
  charIntervalMs: number,
  maxDurationMs: number,
) {
  const tokens: LayoutToken[] = [];
  const allGraphemes: string[] = [];
  let cursor = 0;

  for (const segment of segments) {
    if (!segment.text) continue;
    const chunks = segment.text.split(/(\s+)/);
    for (const chunk of chunks) {
      if (!chunk) continue;
      const isSpace = /^\s+$/.test(chunk);
      const graphemes = isSpace ? [chunk] : splitGraphemes(chunk);
      const startIndex = cursor;
      cursor += graphemes.length;
      for (const g of graphemes) {
        allGraphemes.push(g);
      }
      tokens.push({
        rawText: chunk,
        graphemes,
        startIndex,
        endIndex: cursor,
        isSpace,
        strong: segment.strong,
        className: segment.className,
      });
    }
  }

  const totalChars = allGraphemes.length;
  const baseStep = Math.min(charIntervalMs, Math.max(8, maxDurationMs / Math.max(totalChars, 1)));
  const rawTimes: number[] = [];
  let elapsed = 0;

  for (let i = 0; i < totalChars; i++) {
    const ch = allGraphemes[i] ?? '';
    let step: number;
    if (/^\s+$/.test(ch)) {
      step = baseStep * 0.55;
    } else if (ch === '.' || ch === '!' || ch === '?') {
      step = baseStep + 115;
    } else if (ch === ',' || ch === ':' || ch === ';' || ch === '—') {
      step = baseStep + 60;
    } else {
      // Nhịp biến thiên nhẹ theo vị trí ký tự tạo cảm giác nét bút viết tay tự nhiên
      const wave = ((i * 37) % 11) / 10;
      step = baseStep * (0.84 + wave * 0.32);
    }
    elapsed += step;
    rawTimes.push(elapsed);
  }

  const ceiling = maxDurationMs * 1.18;
  const scale = elapsed > ceiling && elapsed > 0 ? ceiling / elapsed : 1;
  const charTimes = scale === 1 ? rawTimes : rawTimes.map((t) => t * scale);

  return {
    tokens,
    totalChars,
    charTimes,
    plainText: segments.map((s) => s.text).join(''),
  };
}

export function HandwritingText({
  text,
  segments,
  active,
  startDelayMs = 85,
  charIntervalMs = 20,
  maxDurationMs = 1450,
  className,
}: HandwritingTextProps) {
  const normalizedSegments = useMemo<readonly HandwritingSegment[]>(() => {
    if (segments && segments.length > 0) return segments;
    return text ? [{ text }] : [];
  }, [segments, text]);

  const plan = useMemo(
    () => buildLayoutPlan(normalizedSegments, charIntervalMs, maxDurationMs),
    [normalizedSegments, charIntervalMs, maxDurationMs],
  );

  const [revealedCount, setRevealedCount] = useState(0);

  useEffect(() => {
    if (!active || plan.totalChars === 0) return;

    const prefersReducedMotion =
      typeof window !== 'undefined' &&
      typeof window.matchMedia === 'function' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    let rafId = 0;
    let startTimestamp: number | null = null;
    let lastCommitted = -1;

    const tick = (now: number) => {
      if (prefersReducedMotion) {
        setRevealedCount(plan.totalChars);
        return;
      }

      if (startTimestamp === null) {
        startTimestamp = now;
      }

      const elapsed = now - startTimestamp - startDelayMs;
      let nextCount = 0;

      if (elapsed > 0) {
        let low = 0;
        let high = plan.totalChars;
        while (low < high) {
          const mid = (low + high) >> 1;
          if ((plan.charTimes[mid] ?? 0) <= elapsed) {
            low = mid + 1;
          } else {
            high = mid;
          }
        }
        nextCount = low;
      }

      if (nextCount !== lastCommitted) {
        lastCommitted = nextCount;
        setRevealedCount(nextCount);
      }

      if (nextCount < plan.totalChars) {
        rafId = window.requestAnimationFrame(tick);
      }
    };

    rafId = window.requestAnimationFrame(tick);

    return () => {
      if (rafId) {
        window.cancelAnimationFrame(rafId);
      }
    };
  }, [active, plan, startDelayMs]);

  return (
    <span className={cn('relative inline', className)}>
      <span className="sr-only">{plan.plainText}</span>
      <span aria-hidden="true">
        {plan.tokens.map((token, tokenIndex) => {
          const isFullyRevealed = revealedCount >= token.endIndex;
          const isUntouched = revealedCount <= token.startIndex;

          let body: React.ReactNode;

          if (token.isSpace) {
            body = isUntouched ? (
              <span className="opacity-0 select-none">{token.rawText}</span>
            ) : (
              token.rawText
            );
          } else if (isUntouched) {
            body = <span className="opacity-0 select-none">{token.rawText}</span>;
          } else if (isFullyRevealed) {
            body = token.graphemes.map((grapheme, charIndex) => (
              <span key={charIndex} className="handwrite-char">
                {grapheme}
              </span>
            ));
          } else {
            const localCount = revealedCount - token.startIndex;
            const visiblePart = token.graphemes.slice(0, localCount);
            const hiddenPart = token.graphemes.slice(localCount).join('');
            body = (
              <>
                {visiblePart.map((grapheme, charIndex) => (
                  <span key={charIndex} className="handwrite-char">
                    {grapheme}
                  </span>
                ))}
                <span className="opacity-0 select-none">{hiddenPart}</span>
              </>
            );
          }

          if (token.strong) {
            return (
              <strong
                key={tokenIndex}
                className={cn(
                  !token.isSpace && 'whitespace-nowrap',
                  'font-semibold text-[#222222]',
                  token.className,
                )}
              >
                {body}
              </strong>
            );
          }

          return (
            <span
              key={tokenIndex}
              className={cn(!token.isSpace && 'whitespace-nowrap', token.className)}
            >
              {body}
            </span>
          );
        })}
      </span>
    </span>
  );
}
