'use client';

import { useState, type Dispatch, type SetStateAction } from 'react';
import { FileCheck2, KeyRound, Network } from 'lucide-react';
import {
  CATEGORY_OPTIONS,
  CLEARANCE_OPTIONS,
  DEPARTMENT_OPTIONS,
  EMPLOYMENT_STATUS_OPTIONS,
  type AttributeOption,
  type TargetAction,
} from './abac-models';
import type {
  SimulationEnvironment,
  SimulationResource,
  SimulationSubject,
} from './simulator-evaluator';

interface SimulatorContextFormProps {
  action: TargetAction;
  setAction: Dispatch<SetStateAction<TargetAction>>;
  subject: SimulationSubject;
  setSubject: Dispatch<SetStateAction<SimulationSubject>>;
  resource: SimulationResource;
  setResource: Dispatch<SetStateAction<SimulationResource>>;
  environment: SimulationEnvironment;
  setEnvironment: Dispatch<SetStateAction<SimulationEnvironment>>;
  departmentOptions?: readonly AttributeOption[] | undefined;
  categoryOptions?: readonly AttributeOption[] | undefined;
}

function parseProjectsInput(raw: string): string[] {
  return raw
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function arraysEqual(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((val, idx) => val === right[idx]);
}

/**
 * Thuật toán: Biểu Mẫu Ngữ Cảnh Giả Lập ABAC Đồng Bộ Phòng Ban, Dự Án, Thiết Bị Tin Cậy & Danh Mục Động Từ CSDL (`SimulatorContextForm`)
 */
export function SimulatorContextForm({
  action,
  setAction,
  subject,
  setSubject,
  resource,
  setResource,
  environment,
  setEnvironment,
  departmentOptions = DEPARTMENT_OPTIONS,
  categoryOptions = CATEGORY_OPTIONS,
}: SimulatorContextFormProps) {
  const [projectsDraft, setProjectsDraft] = useState(() => subject.projects.join(', '));
  const displayedProjectsText = arraysEqual(parseProjectsInput(projectsDraft), subject.projects)
    ? projectsDraft
    : subject.projects.join(', ');

  const selectCls =
    'w-full text-xs min-h-11 sm:h-9 rounded-full border border-[#dddddd] px-3 bg-[#ffffff] focus:outline-none focus:border-[#222222] focus-visible:ring-2 focus-visible:ring-[#222222]/15';
  const labelCls = 'block text-xs font-medium text-[#717171] mb-1';

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
      <div className="p-3.5 rounded-[16px] border border-[#ebebeb] bg-[#ffffff] space-y-3 shadow-xs">
        <div className="flex items-center gap-1.5 font-bold text-[#222222] border-b border-[#ebebeb] pb-2">
          <KeyRound size={16} strokeWidth={1.75} className="text-[#008489]" aria-hidden="true" />
          <span>1. Thông tin người dùng</span>
        </div>

        <div>
          <label htmlFor="sim-subject-clearance" className={labelCls}>
            Cấp thẩm quyền bảo mật
          </label>
          <select
            id="sim-subject-clearance"
            value={subject.clearanceRank}
            onChange={(e) => setSubject((s) => ({ ...s, clearanceRank: Number(e.target.value) }))}
            className={selectCls}
          >
            {CLEARANCE_OPTIONS.map((c) => (
              <option key={String(c.value)} value={Number(c.value)}>
                {c.label}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label htmlFor="sim-subject-department" className={labelCls}>
            Phòng ban công tác
          </label>
          <select
            id="sim-subject-department"
            value={subject.departmentId}
            onChange={(e) => setSubject((s) => ({ ...s, departmentId: e.target.value }))}
            className={selectCls}
          >
            {departmentOptions.map((d) => (
              <option key={String(d.value)} value={String(d.value)}>
                {d.label}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label htmlFor="sim-subject-employment" className={labelCls}>
            Trạng thái công tác
          </label>
          <select
            id="sim-subject-employment"
            value={subject.employmentStatus}
            onChange={(e) => setSubject((s) => ({ ...s, employmentStatus: e.target.value }))}
            className={selectCls}
          >
            {EMPLOYMENT_STATUS_OPTIONS.map((opt) => (
              <option key={String(opt.value)} value={String(opt.value)}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label htmlFor="sim-subject-projects" className={labelCls}>
            Dự án tham gia (cách nhau dấu phẩy)
          </label>
          <input
            id="sim-subject-projects"
            type="text"
            value={displayedProjectsText}
            onChange={(e) => {
              const raw = e.target.value;
              setProjectsDraft(raw);
              setSubject((s) => ({ ...s, projects: parseProjectsInput(raw) }));
            }}
            placeholder="VD: PROJECT_ALPHA, HR_REVAMP"
            className={`${selectCls} font-mono text-xs`}
          />
        </div>
      </div>

      <div className="p-3.5 rounded-[16px] border border-[#ebebeb] bg-[#ffffff] space-y-3 shadow-xs">
        <div className="flex items-center gap-1.5 font-bold text-[#222222] border-b border-[#ebebeb] pb-2">
          <FileCheck2 size={16} strokeWidth={1.75} className="text-[#FF385C]" aria-hidden="true" />
          <span>2. Thông tin tài liệu</span>
        </div>

        <div>
          <label htmlFor="sim-resource-classification" className={labelCls}>
            Mức độ mật tài liệu
          </label>
          <select
            id="sim-resource-classification"
            value={resource.classificationRank}
            onChange={(e) =>
              setResource((r) => ({ ...r, classificationRank: Number(e.target.value) }))
            }
            className={selectCls}
          >
            {CLEARANCE_OPTIONS.map((c) => (
              <option key={String(c.value)} value={Number(c.value)}>
                {c.label}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label htmlFor="sim-resource-department" className={labelCls}>
            Phòng ban sở hữu
          </label>
          <select
            id="sim-resource-department"
            value={resource.departmentId}
            onChange={(e) => setResource((r) => ({ ...r, departmentId: e.target.value }))}
            className={selectCls}
          >
            {departmentOptions.map((d) => (
              <option key={String(d.value)} value={String(d.value)}>
                {d.label}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label htmlFor="sim-resource-category" className={labelCls}>
            Danh mục tài liệu
          </label>
          <select
            id="sim-resource-category"
            value={resource.category}
            onChange={(e) => setResource((r) => ({ ...r, category: e.target.value }))}
            className={selectCls}
          >
            {categoryOptions.map((c) => (
              <option key={String(c.value)} value={String(c.value)}>
                {c.label}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label htmlFor="sim-resource-action" className={labelCls}>
            Thao tác yêu cầu
          </label>
          <select
            id="sim-resource-action"
            value={action}
            onChange={(e) => setAction(e.target.value as TargetAction)}
            className="w-full text-xs min-h-11 sm:h-9 rounded-full border border-[#dddddd] px-3 bg-[#ffffff] font-semibold text-[#E31C5F] focus:outline-none focus:border-[#222222] focus-visible:ring-2 focus-visible:ring-[#222222]/15"
          >
            <option value="VIEW">Chỉ xem trực tuyến</option>
            <option value="DOWNLOAD">Tải về bản sao</option>
            <option value="SHARE">Chia sẻ</option>
            <option value="MANAGE">Quản trị</option>
            <option value="DISCOVER">Tra cứu danh mục</option>
          </select>
        </div>
      </div>

      <div className="p-3.5 rounded-[16px] border border-[#ebebeb] bg-[#ffffff] space-y-3 shadow-xs">
        <div className="flex items-center gap-1.5 font-bold text-[#222222] border-b border-[#ebebeb] pb-2">
          <Network size={16} strokeWidth={1.75} className="text-[#008A05]" aria-hidden="true" />
          <span>3. Môi trường và thiết bị</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          <div>
            <label htmlFor="sim-env-network" className={labelCls}>
              Mạng nội bộ
            </label>
            <select
              id="sim-env-network"
              value={environment.trustedNetwork ? 'true' : 'false'}
              onChange={(e) =>
                setEnvironment((env) => ({ ...env, trustedNetwork: e.target.value === 'true' }))
              }
              className={selectCls}
            >
              <option value="true">Tin cậy</option>
              <option value="false">Ngoài mạng nội bộ</option>
            </select>
          </div>

          <div>
            <label htmlFor="sim-env-device-trust" className={labelCls}>
              Thiết bị tin cậy
            </label>
            <select
              id="sim-env-device-trust"
              value={environment.deviceTrust ? 'true' : 'false'}
              onChange={(e) =>
                setEnvironment((env) => ({ ...env, deviceTrust: e.target.value === 'true' }))
              }
              className={selectCls}
            >
              <option value="true">Thiết bị đạt chuẩn</option>
              <option value="false">Thiết bị lạ</option>
            </select>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          <div>
            <label htmlFor="sim-env-mfa" className={labelCls}>
              Xác thực MFA
            </label>
            <select
              id="sim-env-mfa"
              value={environment.mfa ? 'true' : 'false'}
              onChange={(e) =>
                setEnvironment((env) => ({ ...env, mfa: e.target.value === 'true' }))
              }
              className={selectCls}
            >
              <option value="true">Đã bật</option>
              <option value="false">Chưa bật</option>
            </select>
          </div>

          <div>
            <label htmlFor="sim-env-time" className={labelCls}>
              Giờ truy cập
            </label>
            <input
              id="sim-env-time"
              type="time"
              value={environment.currentTime}
              onChange={(e) => setEnvironment((env) => ({ ...env, currentTime: e.target.value }))}
              className={selectCls}
            />
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          <div>
            <label htmlFor="sim-env-risk" className={labelCls}>
              Điểm rủi ro (0–100)
            </label>
            <input
              id="sim-env-risk"
              type="number"
              min="0"
              max="100"
              value={environment.riskScore}
              onChange={(e) =>
                setEnvironment((env) => ({ ...env, riskScore: Number(e.target.value) }))
              }
              className={selectCls}
            />
          </div>

          <div>
            <label htmlFor="sim-env-ip" className={labelCls}>
              Địa chỉ IP nguồn
            </label>
            <input
              id="sim-env-ip"
              type="text"
              value={environment.ip}
              onChange={(e) => setEnvironment((env) => ({ ...env, ip: e.target.value }))}
              className={`${selectCls} font-mono text-xs`}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
