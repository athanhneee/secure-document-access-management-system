'use client';

import { Ban, Key, Lock, Search, Unlock } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { InteractiveHoverButton } from '@/components/ui/interactive-hover-button';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { filterUsersByQuery } from '../helpers';
import type { DepartmentRow, UserRow, UserStatusAction } from '../types';

interface UsersTabProps {
  users: UserRow[];
  departments: DepartmentRow[];
  searchQuery: string;
  onSearchQueryChange: (query: string) => void;
  onOpenAssignRole: (user: UserRow) => void;
  onChangeStatus: (user: UserRow, action: UserStatusAction) => void;
}

export function UsersTab({
  users,
  departments,
  searchQuery,
  onSearchQueryChange,
  onOpenAssignRole,
  onChangeStatus,
}: UsersTabProps) {
  const filteredUsers = filterUsersByQuery(users, searchQuery);

  return (
    <Card className="border-[#ebebeb] bg-[#ffffff] shadow-[0_6px_20px_rgba(0,0,0,0.04)]">
      <CardHeader className="pb-3 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <CardTitle className="text-base text-[#222222]">Danh sách tài khoản người dùng</CardTitle>
          <CardDescription className="text-xs text-[#717171]">
            Quản lý danh tính nhân sự, trạng thái khóa, phòng ban và gán vai trò RBAC
          </CardDescription>
        </div>
        <div className="relative w-full sm:w-64">
          <Search
            size={16}
            strokeWidth={1.75}
            className="pointer-events-none absolute left-3 top-2 text-[#717171]"
            aria-hidden="true"
          />
          <Input
            type="text"
            aria-label="Tìm kiếm tài khoản người dùng"
            placeholder="Tìm theo tên, username..."
            value={searchQuery}
            onChange={(e) => onSearchQueryChange(e.target.value)}
            className="pl-9 h-8 text-xs rounded-full bg-[#ffffff] border-[#dddddd] text-[#222222] placeholder:text-[#b0b0b0] focus-visible:border-[#FF385C]"
          />
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader className="bg-[#f7f7f7] border-b border-[#ebebeb]">
              <TableRow>
                <TableHead className="text-xs text-[#717171]">Tài khoản</TableHead>
                <TableHead className="text-xs text-[#717171]">Email</TableHead>
                <TableHead className="text-xs text-[#717171]">Phòng ban</TableHead>
                <TableHead className="text-xs text-[#717171]">Trạng thái</TableHead>
                <TableHead className="text-xs text-[#717171] text-right">Thao tác</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredUsers.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center py-8 text-xs text-[#717171]">
                    Không tìm thấy tài khoản nào
                  </TableCell>
                </TableRow>
              ) : (
                filteredUsers.map((u) => (
                  <TableRow key={u.id} className="border-b border-[#ebebeb] hover:bg-[#f7f7f7]/60">
                    <TableCell>
                      <div className="font-semibold text-xs text-[#222222]">{u.fullName}</div>
                      <div className="text-[11px] text-[#717171]">@{u.username}</div>
                    </TableCell>
                    <TableCell className="text-xs text-[#717171]">{u.email}</TableCell>
                    <TableCell className="text-xs text-[#222222]">
                      {departments.find((d) => d.id === u.departmentId)?.name || 'Chưa gán'}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          u.status === 'ACTIVE'
                            ? 'success'
                            : u.status === 'LOCKED'
                              ? 'warning'
                              : 'destructive'
                        }
                        className="text-[10px]"
                      >
                        {u.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <InteractiveHoverButton
                          variant="secondary"
                          size="sm"
                          text="Gán vai trò"
                          icon={<Key size={16} strokeWidth={1.75} aria-hidden="true" />}
                          onClick={() => onOpenAssignRole(u)}
                        />
                        {u.status === 'ACTIVE' && (
                          <InteractiveHoverButton
                            variant="ghost"
                            size="sm"
                            text="Khóa"
                            icon={<Lock size={16} strokeWidth={1.75} aria-hidden="true" />}
                            onClick={() => onChangeStatus(u, 'lock')}
                          />
                        )}
                        {u.status === 'LOCKED' && (
                          <InteractiveHoverButton
                            variant="secondary"
                            size="sm"
                            text="Mở khóa"
                            icon={<Unlock size={16} strokeWidth={1.75} aria-hidden="true" />}
                            onClick={() => onChangeStatus(u, 'unlock')}
                          />
                        )}
                        {u.status !== 'DISABLED' && (
                          <InteractiveHoverButton
                            variant="danger"
                            size="sm"
                            text="Vô hiệu"
                            icon={<Ban size={16} strokeWidth={1.75} aria-hidden="true" />}
                            onClick={() => onChangeStatus(u, 'disable')}
                          />
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}
