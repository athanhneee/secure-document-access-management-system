'use client';

import { useState } from 'react';

interface CapabilityItem {
  id: string;
  title: string;
  subtitle: string;
  imageSrc: string;
  imageAlt: string;
}

const capabilities: CapabilityItem[] = [
  {
    id: '01',
    title: 'Kho lưu trữ mật',
    subtitle: 'AES-256-GCM',
    imageSrc: '/images/cap-vault.jpg',
    imageAlt: 'Kho lưu trữ tài liệu mật với mã hóa đầu cuối',
  },
  {
    id: '02',
    title: 'Kiểm soát truy cập',
    subtitle: 'RBAC · ABAC',
    imageSrc: '/images/cap-access.jpg',
    imageAlt: 'Hệ thống kiểm soát truy cập sinh trắc học',
  },
  {
    id: '03',
    title: 'Nhật ký kiểm toán',
    subtitle: 'HMAC-SHA256',
    imageSrc: '/images/cap-audit.jpg',
    imageAlt: 'Phòng giám sát nhật ký kiểm toán chuỗi hash',
  },
  {
    id: '04',
    title: 'Mã hóa tài liệu',
    subtitle: 'Envelope Encryption',
    imageSrc: '/images/cap-encrypt.jpg',
    imageAlt: 'Tài liệu được bảo vệ bởi lớp mã hóa hexagonal',
  },
];

function CapabilityRow({ id, title, subtitle, imageSrc, imageAlt }: CapabilityItem) {
  const [isHovered, setIsHovered] = useState(false);

  return (
    <div
      className="cap-row"
      data-active={isHovered || undefined}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
      {/* Background image layer */}
      <div className="cap-row-bg">
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src={imageSrc} alt={imageAlt} loading="lazy" decoding="async" />
        <div className="cap-row-overlay" />
      </div>

      {/* Content */}
      <div className="cap-row-content">
        <div className="cap-row-left">
          <span className="cap-row-id">{id}</span>
          <div className="cap-row-titles">
            <h3 className="cap-row-title">{title}</h3>
            <span className="cap-row-subtitle-mobile">{subtitle}</span>
          </div>
        </div>
        <div className="cap-row-right">
          <span className="cap-row-subtitle">{subtitle}</span>
          <div className="cap-row-icon">
            <svg
              width="20"
              height="20"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M5 12h14" />
              <path d="m12 5 7 7-7 7" />
            </svg>
          </div>
        </div>
      </div>
    </div>
  );
}

export function CinematicCapabilities() {
  return (
    <section className="capabilities" id="kha-nang" aria-labelledby="cap-title">
      <div className="cap-header">
        <div>
          <p className="eyebrow">KHẢ NĂNG BẢO MẬT</p>
          <h2 id="cap-title">Bảo vệ toàn diện, từng lớp một.</h2>
        </div>
        <span className="cap-explore">Khám phá hệ thống</span>
      </div>
      <div className="cap-list">
        {capabilities.map((item) => (
          <CapabilityRow key={item.id} {...item} />
        ))}
      </div>
    </section>
  );
}
