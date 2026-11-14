'use client';

import { SlidersHorizontal, Search, KeyRound, FileCheck2, Network, Plus } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import type { AttributeMetadata } from './abac-models';

type PaletteCategory = 'ALL' | 'SUBJECT' | 'RESOURCE' | 'ENVIRONMENT';

interface AttributePalettePanelProps {
  filteredAttributes: AttributeMetadata[];
  selectedCategory: PaletteCategory;
  onSelectCategory: (cat: PaletteCategory) => void;
  searchPalette: string;
  onSearchChange: (query: string) => void;
  firstGroupId: number;
  onAddAttributeToFirstGroup: (groupId: number, attributeKey: string) => void;
}

export function AttributePalettePanel({
  filteredAttributes,
  selectedCategory,
  onSelectCategory,
  searchPalette,
  onSearchChange,
  firstGroupId,
  onAddAttributeToFirstGroup,
}: AttributePalettePanelProps) {
  return (
    <div className="lg:col-span-4 p-4 rounded-[16px] border border-[#ebebeb] bg-[#ffffff] space-y-3 shadow-xs">
      <div className="flex items-center justify-between border-b border-[#ebebeb] pb-2">
        <div className="flex items-center gap-1.5 font-bold text-xs text-[#222222]">
          <SlidersHorizontal
            size={16}
            strokeWidth={1.75}
            className="text-[#FF385C]"
            aria-hidden="true"
          />
          <span>Bảng Khối Thuộc Tính (Palette)</span>
        </div>
        <span className="text-xs text-[#717171]">{filteredAttributes.length} thuộc tính</span>
      </div>

      <div className="flex flex-wrap gap-1.5 text-xs">
        {(['ALL', 'SUBJECT', 'RESOURCE', 'ENVIRONMENT'] as const).map((cat) => (
          <button
            key={cat}
            type="button"
            onClick={() => onSelectCategory(cat)}
            className={`min-h-11 sm:min-h-8 px-3 py-1 rounded-full font-medium transition-all cursor-pointer ${
              selectedCategory === cat
                ? 'bg-[#222222] text-white'
                : 'bg-[#f7f7f7] text-[#717171] hover:text-[#222222]'
            }`}
          >
            {cat === 'ALL'
              ? 'Tất cả'
              : cat === 'SUBJECT'
                ? 'Chủ thể'
                : cat === 'RESOURCE'
                  ? 'Tài nguyên'
                  : 'Môi trường'}
          </button>
        ))}
      </div>

      <div className="relative">
        <Search
          size={16}
          strokeWidth={1.75}
          className="absolute left-3 top-3.5 sm:top-2.5 text-[#717171]"
          aria-hidden="true"
        />
        <Input
          aria-label="Tìm kiếm thuộc tính ABAC"
          value={searchPalette}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="Tìm thuộc tính..."
          className="pl-9 min-h-11 sm:h-9 text-xs rounded-full border-[#dddddd] bg-[#ffffff]"
        />
      </div>

      <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
        {filteredAttributes.map((attr) => {
          const isSubject = attr.category === 'SUBJECT';
          const isResource = attr.category === 'RESOURCE';
          const isEnv = attr.category === 'ENVIRONMENT';

          return (
            <div
              key={attr.key}
              draggable
              onDragStart={(e) => {
                e.dataTransfer.setData('text/plain', attr.key);
              }}
              className="group p-2.5 rounded-[12px] border border-[#ebebeb] bg-[#ffffff] hover:border-[#FF385C] hover:shadow-xs transition-all text-xs cursor-grab active:cursor-grabbing"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-1.5 font-semibold text-[#222222]">
                  {isSubject && (
                    <KeyRound
                      size={16}
                      strokeWidth={1.75}
                      className="text-[#008489] shrink-0"
                      aria-hidden="true"
                    />
                  )}
                  {isResource && (
                    <FileCheck2
                      size={16}
                      strokeWidth={1.75}
                      className="text-[#FF385C] shrink-0"
                      aria-hidden="true"
                    />
                  )}
                  {isEnv && (
                    <Network
                      size={16}
                      strokeWidth={1.75}
                      className="text-[#008A05] shrink-0"
                      aria-hidden="true"
                    />
                  )}
                  <span>{attr.label}</span>
                </div>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => onAddAttributeToFirstGroup(firstGroupId, attr.key)}
                  title="Thêm vào nhóm đầu tiên"
                  aria-label={`Thêm thuộc tính ${attr.label}`}
                  className="min-h-11 min-w-11 sm:h-9 sm:w-9 p-0 rounded-full hover:bg-[#FF385C]/10 hover:text-[#E31C5F]"
                >
                  <Plus size={16} strokeWidth={1.75} aria-hidden="true" />
                </Button>
              </div>

              <div className="mt-1 flex items-center justify-between text-xs text-[#717171]">
                <span className="font-mono text-[13px] text-[#717171]">{attr.key}</span>
                <span className="text-[13px] uppercase font-bold text-[#717171]">{attr.type}</span>
              </div>

              <p className="mt-1 text-xs text-[#717171] line-clamp-2">{attr.description}</p>
            </div>
          );
        })}
      </div>
    </div>
  );
}
