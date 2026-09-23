import Link from 'next/link';
import { BallpitBackground } from './components/ballpit-background';
import { CinematicCapabilities } from './components/cinematic-capabilities';

function ShieldMark({ large = false }: Readonly<{ large?: boolean }>) {
  return (
    <svg
      width={large ? 76 : 25}
      height={large ? 88 : 29}
      viewBox="0 0 76 88"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M38 5 67 16v25c0 20-17 34-29 41C26 75 9 61 9 41V16L38 5Z"
        stroke="currentColor"
        strokeWidth={large ? 3 : 5}
        strokeLinejoin="round"
      />
      <path
        d="m25 43 9 9 18-20"
        stroke="currentColor"
        strokeWidth="4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

const principles = [
  {
    number: '01',
    title: 'Đúng người',
    description: 'Quyền truy cập gắn với vai trò và thuộc tính được xác minh.',
  },
  {
    number: '02',
    title: 'Đúng phạm vi',
    description: 'Mỗi lần xem hoặc tải tài liệu đều cần được kiểm tra quyền.',
  },
  {
    number: '03',
    title: 'Có thể kiểm chứng',
    description: 'Các hoạt động nhạy cảm phải có dấu vết kiểm toán.',
  },
] as const;

export default function HomePage() {
  return (
    <div className="site-shell">
      <a className="skip-link" href="#noi-dung">
        Chuyển đến nội dung chính
      </a>
      <header className="site-header">
        <Link className="brand" href="/" aria-label="Secure Document — Trang chủ">
          <span className="brand-mark">
            <ShieldMark />
          </span>
          <span>
            Secure<span className="brand-light">Document</span>
          </span>
        </Link>
        <nav aria-label="Điều hướng chính">
          <a href="#nguyen-tac">Nguyên tắc</a>
          <a href="#kha-nang">Khả năng</a>
          <a href="#lo-trinh">Lộ trình</a>
        </nav>
        <span className="workspace-label">
          <span aria-hidden="true" />
          Không gian nội bộ
        </span>
      </header>

      <main id="noi-dung">
        <section className="hero" aria-labelledby="page-title">
          <div className="hero-copy">
            <p className="eyebrow">
              <span className="eyebrow-line" />
              BẢO VỆ THÔNG TIN TỔ CHỨC
            </p>
            <h1 id="page-title">Hệ thống truy cập tài liệu mật</h1>
            <p className="hero-description">
              Một không gian dành cho tài liệu quan trọng, với quyền truy cập rõ ràng và trách nhiệm
              có thể kiểm chứng.
            </p>
            <div className="status-line">
              <span className="status-dot" />
              <strong>Kiểm soát truy cập sẵn sàng</strong>
              <span className="status-divider" />
              Giai đoạn nền tảng
            </div>
            <p className="availability-note">
              Quản trị tài khoản và RBAC đã được bảo vệ phía máy chủ.
            </p>
            <Link className="text-link" href="/admin">
              Mở không gian quản trị <span aria-hidden="true">↗</span>
            </Link>
          </div>
          <div className="hero-visual" aria-hidden="true">
            <BallpitBackground
              config={{
                count: 120,
                gravity: 0.35,
                friction: 0.995,
                minSize: 0.25,
                maxSize: 0.65,
                lightIntensity: 3.5,
                ambientIntensity: 1.8,
                colors: ['#3a7a5c', '#286f58', '#4a9a72', '#1d5a44', '#5eb88a', '#d9e2d9'],
              }}
            />
          </div>
        </section>

        <section className="principles" id="nguyen-tac" aria-labelledby="principles-title">
          <div className="section-heading">
            <p className="eyebrow">NGUYÊN TẮC THIẾT KẾ</p>
            <h2 id="principles-title">Mỗi quyền truy cập đều có lý do.</h2>
          </div>
          <div className="principle-grid">
            {principles.map((principle) => (
              <article className="principle" key={principle.number}>
                <span className="principle-number">{principle.number}</span>
                <h3>{principle.title}</h3>
                <p>{principle.description}</p>
              </article>
            ))}
          </div>
        </section>

        <CinematicCapabilities />

        <section className="roadmap" id="lo-trinh" aria-labelledby="roadmap-title">
          <div>
            <p className="eyebrow">LỘ TRÌNH TRIỂN KHAI</p>
            <h2 id="roadmap-title">Từng bước xây dựng sự tin cậy.</h2>
            <p className="roadmap-description">
              Trạng thái này phản ánh phạm vi khởi tạo. Các chức năng nghiệp vụ sẽ được triển khai
              và kiểm thử ở những giai đoạn tiếp theo.
            </p>
          </div>
          <ol className="roadmap-steps">
            <li>
              <span className="step-marker">1</span>
              <div>
                <h3>Khởi tạo nền tảng</h3>
                <p>Cấu trúc ứng dụng và công cụ phát triển</p>
              </div>
              <span className="step-state">Hoàn tất</span>
            </li>
            <li className="current">
              <span className="step-marker">2</span>
              <div>
                <h3>Thiết lập kiểm soát truy cập</h3>
                <p>Danh tính, vai trò và chính sách quyền</p>
              </div>
              <span className="step-state">Hiện tại</span>
            </li>
            <li>
              <span className="step-marker">3</span>
              <div>
                <h3>Mở các luồng tài liệu</h3>
                <p>Cấp quyền, truy cập và kiểm toán</p>
              </div>
            </li>
          </ol>
        </section>
      </main>

      <footer className="site-footer">
        <span>Secure Document Access System</span>
        <span>Quyền tối thiểu. Trách nhiệm rõ ràng.</span>
      </footer>
    </div>
  );
}
