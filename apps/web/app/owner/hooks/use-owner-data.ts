'use client';

import { useState, useEffect, useCallback } from 'react';
import { apiClient } from '@/lib/api-client';
import {
  buildGrantLookupMaps,
  extractAuditPagination,
  mapDocumentDtoToItem,
  mapGrantDtoToItem,
} from '../helpers';
import type {
  AccessGrantApiDto,
  AccessGrantItem,
  AccessRequestItem,
  AuditLogItem,
  BusinessCategoryLookupItem,
  ClassificationLevelLookupItem,
  DepartmentLookupItem,
  DocumentApiDto,
  DocumentItem,
  RoleLookupItem,
  UserLookupItem,
} from '../types';

/**
 * Thuật toán: Đồng bộ Song song Dữ liệu Không gian Chủ sở hữu (`useOwnerData`)
 * Điều phối đồng thời 8 truy vấn danh mục/tra cứu qua `Promise.allSettled` và kết nối bảng băm khóa ngoại cho danh sách giấy phép trong `O(N)`.
 */
export function useOwnerData() {
  const [documents, setDocuments] = useState<DocumentItem[]>([]);
  const [requests, setRequests] = useState<AccessRequestItem[]>([]);
  const [grants, setGrants] = useState<AccessGrantItem[]>([]);

  const [departments, setDepartments] = useState<DepartmentLookupItem[]>([]);
  const [businessCategories, setBusinessCategories] = useState<BusinessCategoryLookupItem[]>([]);
  const [classificationLevels, setClassificationLevels] = useState<ClassificationLevelLookupItem[]>(
    [],
  );
  const [usersLookup, setUsersLookup] = useState<UserLookupItem[]>([]);
  const [rolesLookup, setRolesLookup] = useState<RoleLookupItem[]>([]);

  const [auditLogs, setAuditLogs] = useState<AuditLogItem[]>([]);
  const [auditPage, setAuditPage] = useState(1);
  const [auditTotalPages, setAuditTotalPages] = useState(1);
  const [auditTotal, setAuditTotal] = useState(0);
  const [isLoadingAudit, setIsLoadingAudit] = useState(false);
  const [selectedAuditLog, setSelectedAuditLog] = useState<AuditLogItem | null>(null);
  const [auditDetailOpen, setAuditDetailOpen] = useState(false);

  const [isLoading, setIsLoading] = useState(true);
  const [message, setMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const loadAuditLogs = useCallback(async (page = 1) => {
    setIsLoadingAudit(true);
    try {
      const res = await apiClient<{
        data: AuditLogItem[];
        total?: number;
        page?: number;
        pageSize?: number;
        totalPages?: number;
        pagination?: {
          page?: number;
          pageSize?: number;
          total?: number;
          totalPages?: number;
        };
      }>(`/audit-logs?page=${page}&pageSize=15`);
      // CONFLICT-RESOLVED: Đọc thông tin phân trang từ res.pagination (page, totalPages, total) khớp phản hồi của AuditService.
      const pageMeta = extractAuditPagination(res);
      setAuditLogs(res.data || []);
      setAuditPage(pageMeta.page);
      setAuditTotalPages(pageMeta.totalPages);
      setAuditTotal(pageMeta.total);
    } catch {
      setAuditLogs([]);
    } finally {
      setIsLoadingAudit(false);
    }
  }, []);

  const refreshData = useCallback(async (options?: { silent?: boolean }) => {
    if (!options?.silent) {
      setIsLoading(true);
    }
    setErrorMessage(null);

    const [
      docsResult,
      grantsResult,
      requestsResult,
      deptsResult,
      catsResult,
      levelsResult,
      usersResult,
      rolesResult,
    ] = await Promise.allSettled([
      apiClient<{ data: DocumentApiDto[] }>('/documents?pageSize=50'),
      apiClient<{ data: AccessGrantApiDto[] }>('/access-grants?pageSize=50'),
      apiClient<{ data: AccessRequestItem[] }>('/access-requests?scope=incoming&status=PENDING'),
      apiClient<{ data: DepartmentLookupItem[] }>('/departments/lookup'),
      apiClient<{ data: BusinessCategoryLookupItem[] }>('/classifications/categories'),
      apiClient<{ data: ClassificationLevelLookupItem[] }>('/classifications/levels'),
      apiClient<{ data: UserLookupItem[] }>('/users/lookup'),
      apiClient<{ data: RoleLookupItem[] }>('/rbac/roles/lookup'),
    ]);

    const mappedDocs =
      docsResult.status === 'fulfilled'
        ? (docsResult.value.data || []).map(mapDocumentDtoToItem)
        : [];
    if (docsResult.status === 'fulfilled') {
      setDocuments(mappedDocs);
    } else {
      setErrorMessage('Không thể tải danh sách tài liệu từ máy chủ.');
    }

    const loadedUsers = usersResult.status === 'fulfilled' ? usersResult.value.data || [] : [];
    const loadedRoles = rolesResult.status === 'fulfilled' ? rolesResult.value.data || [] : [];

    if (usersResult.status === 'fulfilled') {
      setUsersLookup(loadedUsers);
    }

    if (rolesResult.status === 'fulfilled') {
      setRolesLookup(loadedRoles);
    }

    if (grantsResult.status === 'fulfilled') {
      // CONFLICT-RESOLVED: Truyền bảng tra cứu docs/users/roles vào mapGrantDtoToItem để hiển thị đúng tên tài liệu và đối tượng nhận quyền.
      const grantLookups = buildGrantLookupMaps(mappedDocs, loadedUsers, loadedRoles);
      setGrants((grantsResult.value.data || []).map((g) => mapGrantDtoToItem(g, grantLookups)));
    }

    if (requestsResult.status === 'fulfilled') {
      setRequests(requestsResult.value.data || []);
    }

    if (deptsResult.status === 'fulfilled') {
      setDepartments(deptsResult.value.data || []);
    }

    if (catsResult.status === 'fulfilled') {
      setBusinessCategories(catsResult.value.data || []);
    }

    if (levelsResult.status === 'fulfilled') {
      setClassificationLevels(levelsResult.value.data || []);
    }

    if (!options?.silent) {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    let ignore = false;
    const run = async () => {
      await Promise.resolve();
      if (!ignore) {
        void refreshData();
        void loadAuditLogs(1);
      }
    };
    void run();
    return () => {
      ignore = true;
    };
  }, [refreshData, loadAuditLogs]);

  return {
    documents,
    setDocuments,
    requests,
    setRequests,
    grants,
    setGrants,
    departments,
    businessCategories,
    classificationLevels,
    usersLookup,
    rolesLookup,
    auditLogs,
    auditPage,
    auditTotalPages,
    auditTotal,
    isLoadingAudit,
    selectedAuditLog,
    setSelectedAuditLog,
    auditDetailOpen,
    setAuditDetailOpen,
    isLoading,
    message,
    setMessage,
    errorMessage,
    setErrorMessage,
    loadAuditLogs,
    refreshData,
  };
}
