import { type getDatabaseClient } from '@sda/database';

/**
 * Thuật toán / Tổng quan module:
 * Bộ truy vấn dữ liệu kết xuất có giới hạn trần `take <= 10.000` và cô lập phạm vi phòng ban `__allowedDepartmentIds`
 * cho 4 loại báo cáo (`AUDIT_LOGS`, `SECURITY_ALERTS`, `INCIDENT_REPORTS`, `SYSTEM_REPORT`).
 */

type PrismaClient = ReturnType<typeof getDatabaseClient>;
const MAX_EXPORT_ROWS = 10_000;
const ISO_DATE_ONLY_REGEX = /^\d{4}-\d{2}-\d{2}$/u;

export function parseFilterParams(raw: unknown): Record<string, unknown> {
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw) as unknown;
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      return {};
    }
  }
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    return raw as Record<string, unknown>;
  }
  return {};
}

/**
 * Thuật toán: Phân tích mốc thời gian đầu/cuối ngày cho chuỗi ngày thuần `YYYY-MM-DD` (Inclusive End-of-Day Bound)
 * giúp Worker khớp 100% logic lọc ngày của `@sda/api` và không bỏ sót dữ liệu ngày cuối.
 */
export function parseDateBound(raw: unknown, endOfDay = false): Date | undefined {
  if (raw instanceof Date && !Number.isNaN(raw.getTime())) return raw;
  if (typeof raw === 'string' && raw.trim().length > 0) {
    const trimmed = raw.trim();
    const normalized = ISO_DATE_ONLY_REGEX.test(trimmed)
      ? `${trimmed}${endOfDay ? 'T23:59:59.999Z' : 'T00:00:00.000Z'}`
      : trimmed;
    const parsed = new Date(normalized);
    if (!Number.isNaN(parsed.getTime())) return parsed;
  }
  return undefined;
}

function parseOptionalBigInt(raw: unknown): bigint | undefined {
  if (typeof raw === 'bigint') return raw;
  if (typeof raw === 'number' && Number.isInteger(raw)) return BigInt(raw);
  if (typeof raw === 'string' && /^\d+$/u.test(raw.trim())) return BigInt(raw.trim());
  return undefined;
}

/**
 * Thuật toán: Phân giải tập định danh người dùng & tài liệu thuộc phạm vi phòng ban `__allowedDepartmentIds` (Fail-Closed Scope Filter).
 */
async function resolveDepartmentScopeSets(
  database: PrismaClient,
  filterParams: Record<string, unknown>,
): Promise<{ restricted: boolean; userIds: bigint[]; documentIds: string[]; deptIds: bigint[] }> {
  const rawDepts = filterParams['__allowedDepartmentIds'];
  if (!Array.isArray(rawDepts)) {
    return { restricted: false, userIds: [], documentIds: [], deptIds: [] };
  }
  const deptIds = rawDepts
    .map((item) => parseOptionalBigInt(item))
    .filter((id): id is bigint => id !== undefined);
  if (deptIds.length === 0) {
    return { restricted: true, userIds: [], documentIds: [], deptIds: [] };
  }
  const users =
    typeof database.user?.findMany === 'function'
      ? await database.user.findMany({
          where: { department_id: { in: deptIds } },
          select: { id: true },
        })
      : [];
  const docs =
    typeof database.document?.findMany === 'function'
      ? await database.document.findMany({
          where: { department_id: { in: deptIds } },
          select: { id: true },
        })
      : [];
  return {
    restricted: true,
    userIds: users.map((u) => u.id),
    documentIds: docs.map((d) => d.id),
    deptIds,
  };
}

/**
 * Thuật toán: Truy vấn tập bản ghi báo cáo theo `exportType` áp dụng đồng thời bộ lọc nghiệp vụ, giới hạn `10.000` dòng và phạm vi phòng ban.
 */
export async function queryExportDataset(
  database: PrismaClient,
  exportType: string,
  filterParams: Record<string, unknown>,
): Promise<Record<string, unknown>[]> {
  const requestedLimit = Number(filterParams['limit'] ?? MAX_EXPORT_ROWS);
  const take =
    Number.isFinite(requestedLimit) && requestedLimit > 0
      ? Math.min(MAX_EXPORT_ROWS, Math.floor(requestedLimit))
      : MAX_EXPORT_ROWS;
  const fromDate = parseDateBound(filterParams['from'] ?? filterParams['startDate'], false);
  const toDate = parseDateBound(filterParams['to'] ?? filterParams['endDate'], true);
  const scope = await resolveDepartmentScopeSets(database, filterParams);

  if (exportType === 'AUDIT_LOGS') {
    const baseWhere: Record<string, unknown> = {};
    const actorId = parseOptionalBigInt(filterParams['actorUserId']);
    if (actorId !== undefined) baseWhere['actor_user_id'] = actorId;
    if (typeof filterParams['actorUsername'] === 'string' && filterParams['actorUsername'].trim()) {
      baseWhere['actor_username'] = {
        contains: filterParams['actorUsername'].trim(),
        mode: 'insensitive',
      };
    }
    if (typeof filterParams['documentId'] === 'string' && filterParams['documentId'])
      baseWhere['document_id'] = filterParams['documentId'];
    if (typeof filterParams['action'] === 'string' && filterParams['action'].trim()) {
      baseWhere['action'] = { contains: filterParams['action'].trim(), mode: 'insensitive' };
    }
    if (typeof filterParams['outcome'] === 'string' && filterParams['outcome'])
      baseWhere['outcome'] = filterParams['outcome'];
    if (
      typeof filterParams['chainPartition'] === 'string' &&
      filterParams['chainPartition'].trim()
    ) {
      baseWhere['chain_partition'] = filterParams['chainPartition'].trim();
    }
    if (typeof filterParams['correlationId'] === 'string' && filterParams['correlationId'].trim()) {
      baseWhere['correlation_id'] = {
        contains: filterParams['correlationId'].trim(),
        mode: 'insensitive',
      };
    }
    if (fromDate || toDate) {
      baseWhere['occurred_at'] = {
        ...(fromDate ? { gte: fromDate } : {}),
        ...(toDate ? { lte: toDate } : {}),
      };
    }
    if (scope.restricted) {
      const orClauses: Record<string, unknown>[] = [];
      if (scope.userIds.length > 0) orClauses.push({ actor_user_id: { in: scope.userIds } });
      if (scope.documentIds.length > 0) orClauses.push({ document_id: { in: scope.documentIds } });
      if (orClauses.length === 0) return [];
      return (await database.auditLog.findMany({
        where: { AND: [baseWhere, { OR: orClauses }] } as never,
        orderBy: { occurred_at: 'desc' },
        take,
      })) as unknown as Record<string, unknown>[];
    }
    return (await database.auditLog.findMany({
      where: baseWhere as never,
      orderBy: { occurred_at: 'desc' },
      take,
    })) as unknown as Record<string, unknown>[];
  }

  if (exportType === 'SECURITY_ALERTS') {
    const baseWhere: Record<string, unknown> = {};
    if (typeof filterParams['status'] === 'string' && filterParams['status'])
      baseWhere['status'] = filterParams['status'];
    if (typeof filterParams['severity'] === 'string' && filterParams['severity'])
      baseWhere['severity'] = filterParams['severity'];
    if (typeof filterParams['alertType'] === 'string' && filterParams['alertType'])
      baseWhere['alert_type'] = filterParams['alertType'];
    const detectedUid = parseOptionalBigInt(filterParams['detectedUserId']);
    if (detectedUid !== undefined) baseWhere['detected_user_id'] = detectedUid;
    if (fromDate || toDate) {
      baseWhere['detected_at'] = {
        ...(fromDate ? { gte: fromDate } : {}),
        ...(toDate ? { lte: toDate } : {}),
      };
    }
    if (scope.restricted) {
      const orClauses: Record<string, unknown>[] = [];
      if (scope.userIds.length > 0) orClauses.push({ detected_user_id: { in: scope.userIds } });
      if (scope.documentIds.length > 0) orClauses.push({ document_id: { in: scope.documentIds } });
      if (orClauses.length === 0) return [];
      return (await database.securityAlert.findMany({
        where: { AND: [baseWhere, { OR: orClauses }] } as never,
        orderBy: { detected_at: 'desc' },
        take,
      })) as unknown as Record<string, unknown>[];
    }
    return (await database.securityAlert.findMany({
      where: baseWhere as never,
      orderBy: { detected_at: 'desc' },
      take,
    })) as unknown as Record<string, unknown>[];
  }

  if (exportType === 'INCIDENT_REPORTS') {
    const baseWhere: Record<string, unknown> = {};
    if (typeof filterParams['status'] === 'string' && filterParams['status'])
      baseWhere['status'] = filterParams['status'];
    const preparedBy = parseOptionalBigInt(filterParams['preparedBy']);
    if (preparedBy !== undefined) baseWhere['prepared_by'] = preparedBy;
    if (typeof filterParams['alertId'] === 'string' && filterParams['alertId'])
      baseWhere['alert_id'] = filterParams['alertId'];
    if (fromDate || toDate) {
      baseWhere['created_at'] = {
        ...(fromDate ? { gte: fromDate } : {}),
        ...(toDate ? { lte: toDate } : {}),
      };
    }
    if (scope.restricted) {
      if (scope.userIds.length === 0) return [];
      return (await database.incidentReport.findMany({
        where: { AND: [baseWhere, { prepared_by: { in: scope.userIds } }] } as never,
        orderBy: { created_at: 'desc' },
        take,
      })) as unknown as Record<string, unknown>[];
    }
    return (await database.incidentReport.findMany({
      where: baseWhere as never,
      orderBy: { created_at: 'desc' },
      take,
    })) as unknown as Record<string, unknown>[];
  }

  if (exportType === 'SYSTEM_REPORT') {
    const capturedAt = new Date().toISOString();
    if (scope.restricted && scope.deptIds.length === 0) return [];
    const docWhere = scope.restricted ? { department_id: { in: scope.deptIds } } : {};
    const userWhere = scope.restricted ? { department_id: { in: scope.deptIds } } : {};
    const [activeDocuments, activeUsers, openAlerts] = await Promise.all([
      typeof database.document?.count === 'function'
        ? database.document.count({ where: { ...docWhere, status: 'ACTIVE' } as never })
        : Promise.resolve(0),
      typeof database.user?.count === 'function'
        ? database.user.count({ where: { ...userWhere, status: 'ACTIVE' } as never })
        : Promise.resolve(0),
      typeof database.securityAlert?.count === 'function'
        ? database.securityAlert.count({ where: { status: 'OPEN' } as never })
        : Promise.resolve(0),
    ]);
    return [
      { metric: 'active_documents', value: activeDocuments, captured_at: capturedAt },
      { metric: 'active_users', value: activeUsers, captured_at: capturedAt },
      { metric: 'open_security_alerts', value: openAlerts, captured_at: capturedAt },
    ];
  }

  throw new Error(`Unsupported export_type: ${exportType}`);
}
