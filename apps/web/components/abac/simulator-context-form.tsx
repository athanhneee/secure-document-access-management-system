'use client';

import type { Dispatch, SetStateAction } from 'react';
import { Network, KeyRound, FileCheck2 } from 'lucide-react';
import { CLEARANCE_OPTIONS, DEPARTMENT_OPTIONS, type TargetAction } from './abac-models';
import type {
  SimulationSubject,
  SimulationResource,
  SimulationEnvironment,
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
}

export function SimulatorContextForm({
  action,
  setAction,
  subject,
  setSubject,
  resource,
  setResource,
  environment,
  setEnvironment,
}: SimulatorContextFormProps) {
  const selectCls =
    'w-full text-xs h-8 rounded-full border border-[#dddddd] px-2.5 bg-[#ffffff] focus:border-[#FF385C]';
  const labelCls = 'block text-[11px] font-medium text-[#717171] mb-1';

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
      {/* SUBJECT CONTEXT */}
      <div className="p-3.5 rounded-[16px] border border-[#ebebeb] bg-[#ffffff] space-y-3 shadow-xs">
        <div className="flex items-center gap-1.5 font-bold text-[#222222] border-b border-[#ebebeb] pb-2">
          <KeyRound size={16} strokeWidth={1.75} className="text-[#008489]" aria-hidden="true" />
          <span>1. Ngữ cảnh Chủ thể (Subject)</span>
        </div>

        <div>
          <label htmlFor="sim-subject-clearance" className={labelCls}>
            Cấp bậc An ninh (Clearance):
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
            Phòng ban công tác:
          </label>
          <select
            id="sim-subject-department"
            value={subject.departmentId}
            onChange={(e) => setSubject((s) => ({ ...s, departmentId: e.target.value }))}
            className={selectCls}
          >
            {DEPARTMENT_OPTIONS.map((d) => (
              <option key={String(d.value)} value={String(d.value)}>
                {d.label}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label htmlFor="sim-subject-employment" className={labelCls}>
            Trạng thái nhân sự:
          </label>
          <select
            id="sim-subject-employment"
            value={subject.employmentStatus}
            onChange={(e) => setSubject((s) => ({ ...s, employmentStatus: e.target.value }))}
            className={selectCls}
          >
            <option value="ACTIVE">Đang công tác (ACTIVE)</option>
            <option value="PROBATION">Thử việc (PROBATION)</option>
            <option value="SUSPENDED">Tạm đình chỉ (SUSPENDED)</option>
          </select>
        </div>
      </div>

      {/* RESOURCE CONTEXT */}
      <div className="p-3.5 rounded-[16px] border border-[#ebebeb] bg-[#ffffff] space-y-3 shadow-xs">
        <div className="flex items-center gap-1.5 font-bold text-[#222222] border-b border-[#ebebeb] pb-2">
          <FileCheck2 size={16} strokeWidth={1.75} className="text-[#FF385C]" aria-hidden="true" />
          <span>2. Ngữ cảnh Tài nguyên (Resource)</span>
        </div>

        <div>
          <label htmlFor="sim-resource-classification" className={labelCls}>
            Cấp độ mật tài liệu:
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
            Phòng ban sở hữu:
          </label>
          <select
            id="sim-resource-department"
            value={resource.departmentId}
            onChange={(e) => setResource((r) => ({ ...r, departmentId: e.target.value }))}
            className={selectCls}
          >
            {DEPARTMENT_OPTIONS.map((d) => (
              <option key={String(d.value)} value={String(d.value)}>
                {d.label}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label htmlFor="sim-resource-action" className={labelCls}>
            Hành động yêu cầu:
          </label>
          <select
            id="sim-resource-action"
            value={action}
            onChange={(e) => setAction(e.target.value as TargetAction)}
            className="w-full text-xs h-8 rounded-full border border-[#dddddd] px-2.5 bg-[#ffffff] font-semibold text-[#FF385C]"
          >
            <option value="VIEW">XEM TRỰC TUYẾN (VIEW)</option>
            <option value="DOWNLOAD">TẢI BẢN SAO (DOWNLOAD)</option>
            <option value="SHARE">CHIA SẺ (SHARE)</option>
            <option value="MANAGE">QUẢN TRỊ (MANAGE)</option>
            <option value="DISCOVER">TÌM KIẾM (DISCOVER)</option>
          </select>
        </div>
      </div>

      {/* ENVIRONMENT CONTEXT */}
      <div className="p-3.5 rounded-[16px] border border-[#ebebeb] bg-[#ffffff] space-y-3 shadow-xs">
        <div className="flex items-center gap-1.5 font-bold text-[#222222] border-b border-[#ebebeb] pb-2">
          <Network size={16} strokeWidth={1.75} className="text-[#008A05]" aria-hidden="true" />
          <span>3. Môi trường &amp; Thiết bị</span>
        </div>

        <div className="grid grid-cols-2 gap-2">
          <div>
            <label htmlFor="sim-env-network" className={labelCls}>
              Mạng nội bộ:
            </label>
            <select
              id="sim-env-network"
              value={environment.trustedNetwork ? 'true' : 'false'}
              onChange={(e) =>
                setEnvironment((env) => ({ ...env, trustedNetwork: e.target.value === 'true' }))
              }
              className="w-full text-xs h-8 rounded-full border border-[#dddddd] px-2 bg-[#ffffff]"
            >
              <option value="true">Tin cậy (Yes)</option>
              <option value="false">Mạng ngoài (No)</option>
            </select>
          </div>

          <div>
            <label htmlFor="sim-env-mfa" className={labelCls}>
              Xác thực MFA:
            </label>
            <select
              id="sim-env-mfa"
              value={environment.mfa ? 'true' : 'false'}
              onChange={(e) =>
                setEnvironment((env) => ({ ...env, mfa: e.target.value === 'true' }))
              }
              className="w-full text-xs h-8 rounded-full border border-[#dddddd] px-2 bg-[#ffffff]"
            >
              <option value="true">Đã bật (Yes)</option>
              <option value="false">Chưa bật (No)</option>
            </select>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-2">
          <div>
            <label htmlFor="sim-env-time" className={labelCls}>
              Giờ truy cập:
            </label>
            <input
              id="sim-env-time"
              type="time"
              value={environment.currentTime}
              onChange={(e) => setEnvironment((env) => ({ ...env, currentTime: e.target.value }))}
              className={selectCls}
            />
          </div>

          <div>
            <label htmlFor="sim-env-risk" className={labelCls}>
              Điểm rủi ro (0-100):
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
        </div>

        <div>
          <label htmlFor="sim-env-ip" className={labelCls}>
            Địa chỉ IP nguồn:
          </label>
          <input
            id="sim-env-ip"
            type="text"
            value={environment.ip}
            onChange={(e) => setEnvironment((env) => ({ ...env, ip: e.target.value }))}
            className={`${selectCls} font-mono text-[11px]`}
          />
        </div>
      </div>
    </div>
  );
}
