'use client';

import Link from 'next/link';
import { useCallback, useEffect, useState, type FormEvent } from 'react';

const apiBase = process.env['NEXT_PUBLIC_API_BASE_URL'] ?? 'http://127.0.0.1:3001/api/v1';

interface CurrentUser {
  fullName: string;
  permissions: string[];
}
interface UserRow {
  id: string;
  username: string;
  fullName: string;
  email: string;
  status: string;
  departmentId: string | null;
  version: number;
}
interface DepartmentRow {
  id: string;
  code: string;
  name: string;
  parentId: string | null;
  isActive: boolean;
  version: number;
}
interface RoleRow {
  id: string;
  code: string;
  name: string;
  isSystemRole: boolean;
  isActive: boolean;
  permissions: Array<{ code: string }>;
}

function csrfToken(): string {
  return (
    document.cookie
      .split('; ')
      .find((entry) => entry.startsWith('sda_csrf='))
      ?.split('=')[1] ?? ''
  );
}

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${apiBase}${path}`, {
    ...init,
    credentials: 'include',
    headers: { 'content-type': 'application/json', 'x-csrf-token': csrfToken(), ...init?.headers },
  });
  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as { message?: string };
    throw new Error(body.message ?? `Yêu cầu thất bại (${response.status})`);
  }
  return response.status === 204 ? (undefined as T) : (response.json() as Promise<T>);
}

export function AdminWorkspace() {
  const [me, setMe] = useState<CurrentUser | null>(null);
  const [users, setUsers] = useState<UserRow[]>([]);
  const [departments, setDepartments] = useState<DepartmentRow[]>([]);
  const [roles, setRoles] = useState<RoleRow[]>([]);
  const [message, setMessage] = useState('Đang kiểm tra phiên đăng nhập…');

  const canUsers = me?.permissions.includes('USER:MANAGE') ?? false;
  const canDepartments = me?.permissions.includes('DEPARTMENT:MANAGE') ?? false;
  const canRoles = me?.permissions.includes('ROLE:MANAGE') ?? false;

  const refresh = useCallback(async () => {
    try {
      const current = await api<CurrentUser>('/users/me');
      setMe(current);
      const [userData, departmentData, roleData] = await Promise.all([
        current.permissions.includes('USER:MANAGE')
          ? api<{ data: UserRow[] }>('/users')
          : Promise.resolve({ data: [] }),
        current.permissions.includes('DEPARTMENT:MANAGE')
          ? api<{ data: DepartmentRow[] }>('/departments')
          : Promise.resolve({ data: [] }),
        current.permissions.includes('ROLE:MANAGE')
          ? api<{ data: RoleRow[] }>('/rbac/roles')
          : Promise.resolve({ data: [] }),
      ]);
      setUsers(userData.data);
      setDepartments(departmentData.data);
      setRoles(roleData.data);
      setMessage('Dữ liệu được quyết định và lọc theo quyền phía máy chủ.');
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Không thể tải không gian quản trị.');
    }
  }, []);

  // Loading server-authorized data is the external synchronization performed by this effect.
  useEffect(() => {
    // oxlint-disable-next-line react/set-state-in-effect
    void refresh();
  }, [refresh]);

  async function createUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await api('/users', {
        method: 'POST',
        body: JSON.stringify({
          username: form.get('username'),
          email: form.get('email'),
          fullName: form.get('fullName'),
          password: form.get('password'),
          departmentId: form.get('departmentId') || null,
        }),
      });
      event.currentTarget.reset();
      setMessage('Đã tạo tài khoản.');
      await refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Không thể tạo tài khoản.');
    }
  }

  async function changeStatus(user: UserRow, action: 'lock' | 'unlock' | 'disable') {
    try {
      await api(`/users/${user.id}/${action}`, {
        method: 'POST',
        body: JSON.stringify({ expectedVersion: user.version }),
      });
      setMessage('Đã cập nhật trạng thái tài khoản.');
      await refresh();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Không thể cập nhật tài khoản.');
    }
  }

  return (
    <main className="admin-shell">
      <header className="admin-header">
        <div>
          <p className="eyebrow">QUẢN TRỊ TRUY CẬP</p>
          <h1>Users · Departments · RBAC</h1>
        </div>
        <Link className="text-link" href="/">
          ← Trang chủ
        </Link>
      </header>
      <output className="admin-notice">{message}</output>

      {canUsers && (
        <section className="admin-panel" aria-labelledby="users-title">
          <div className="admin-title">
            <h2 id="users-title">Tài khoản</h2>
            <span>{users.length} tài khoản trong phạm vi</span>
          </div>
          <form className="admin-form" onSubmit={createUser}>
            <input
              name="username"
              required
              placeholder="Tên đăng nhập"
              aria-label="Tên đăng nhập"
            />
            <input name="fullName" required placeholder="Họ tên" aria-label="Họ tên" />
            <input name="email" required type="email" placeholder="Email" aria-label="Email" />
            <input
              name="password"
              required
              type="password"
              minLength={15}
              placeholder="Mật khẩu khởi tạo"
              aria-label="Mật khẩu khởi tạo"
            />
            <select name="departmentId" aria-label="Phòng ban">
              <option value="">Không có phòng ban</option>
              {departments
                .filter((item) => item.isActive)
                .map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name}
                  </option>
                ))}
            </select>
            <button type="submit">Tạo tài khoản</button>
          </form>
          <table className="admin-table" aria-label="Danh sách tài khoản">
            <tbody>
              {users.map((user) => (
                <tr className="admin-row" key={user.id}>
                  <td>
                    <strong>{user.fullName}</strong>
                    <small>
                      {user.username} · {user.email}
                    </small>
                  </td>
                  <td>
                    <span className={`state state-${user.status.toLowerCase()}`}>
                      {user.status}
                    </span>
                  </td>
                  <td className="row-actions">
                    {user.status === 'ACTIVE' && (
                      <button onClick={() => void changeStatus(user, 'lock')}>Khóa</button>
                    )}
                    {user.status === 'LOCKED' && (
                      <button onClick={() => void changeStatus(user, 'unlock')}>Mở khóa</button>
                    )}
                    {user.status !== 'DISABLED' && (
                      <button className="danger" onClick={() => void changeStatus(user, 'disable')}>
                        Vô hiệu
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      <div className="admin-grid">
        {canDepartments && (
          <section className="admin-panel">
            <div className="admin-title">
              <h2>Phòng ban</h2>
              <span>Cây tổ chức</span>
            </div>
            {departments.map((department) => (
              <div className="compact-row" key={department.id}>
                <span>{department.code}</span>
                <strong>{department.name}</strong>
                <em>{department.isActive ? 'Active' : 'Inactive'}</em>
              </div>
            ))}
          </section>
        )}
        {canRoles && (
          <section className="admin-panel">
            <div className="admin-title">
              <h2>Vai trò</h2>
              <span>Ma trận quyền</span>
            </div>
            {roles.map((role) => (
              <div className="role-card" key={role.id}>
                <div>
                  <strong>{role.name}</strong>
                  <small>
                    {role.code}
                    {role.isSystemRole ? ' · system' : ''}
                  </small>
                </div>
                <p>
                  {role.permissions.map((permission) => permission.code).join(' · ') ||
                    'Chưa có permission'}
                </p>
              </div>
            ))}
          </section>
        )}
      </div>
      {me && !canUsers && !canDepartments && !canRoles && (
        <p className="empty-state">
          Tài khoản này không có quyền quản trị. Backend vẫn là nơi quyết định quyền truy cập.
        </p>
      )}
    </main>
  );
}
