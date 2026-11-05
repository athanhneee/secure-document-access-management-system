'use client';

import { useState, useEffect, useCallback } from 'react';
import { apiClient } from '@/lib/api-client';
import { mapDocumentDtoToItem, mapGrantDtoToItem } from '../helpers';
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
 * Algorithm: Concurrent Owner Workspace Hydration
 * Dispatches 8 independent catalog/lookup requests concurrently via `Promise.allSettled`
 * so partial lookup failures degrade gracefully without blocking core document management.
 * Time Complexity: O(N) over returned payload items | Space Complexity: O(N)
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
        total: number;
        page: number;
        pageSize: number;
        totalPages: number;
      }>(`/audit-logs?page=${page}&pageSize=15`);
      setAuditLogs(res.data || []);
      setAuditPage(res.page || 1);
      setAuditTotalPages(res.totalPages || 1);
      setAuditTotal(res.total || 0);
    } catch {
      setAuditLogs([]);
    } finally {
      setIsLoadingAudit(false);
    }
  }, []);

  const refreshData = useCallback(async () => {
    setIsLoading(true);
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

    if (docsResult.status === 'fulfilled') {
      setDocuments((docsResult.value.data || []).map(mapDocumentDtoToItem));
    } else {
      setErrorMessage('Không thể tải danh sách tài liệu từ máy chủ.');
    }

    if (grantsResult.status === 'fulfilled') {
      setGrants((grantsResult.value.data || []).map(mapGrantDtoToItem));
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

    if (usersResult.status === 'fulfilled') {
      setUsersLookup(usersResult.value.data || []);
    }

    if (rolesResult.status === 'fulfilled') {
      setRolesLookup(rolesResult.value.data || []);
    }

    setIsLoading(false);
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
    requests,
    grants,
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
