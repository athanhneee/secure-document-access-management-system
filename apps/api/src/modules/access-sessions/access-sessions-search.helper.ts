/**
 * @module AccessSessionsSearchHelper
 * Thuật toán: Truy Vấn Tìm Kiếm Phiên Đọc An Toàn Kiểu `INET` Trên PostgreSQL (`Safe INET Session Search`).
 *   - Loại bỏ hoàn toàn bộ lọc Prisma `{ ip_address: { contains } }` vốn sinh `inet ~~* text` gây `SQLSTATE 42883`.
 *   - Trên PostgreSQL thực (`$queryRaw`), đối khớp tiền tố/chuỗi con IP qua `host(s."ip_address") ILIKE ... ESCAPE '!'`
 *     (tránh hậu tố `/32`, `/128` của `::text`), đồng thời bổ sung so khớp chuẩn hóa `s."ip_address" = $term::inet`
 *     khi `net.isIP(term) !== 0` để hỗ trợ dạng IPv6 chưa nén (ví dụ `0:0:0:0:0:0:0:1` khớp `::1`).
 *   - Với các bộ kiểm thử dùng mock DB không có `$queryRaw`, chỉ thêm `{ ip_address: { equals: term } }` khi `isIP(term) !== 0`.
 */
import { isIP } from 'node:net';
import { type getDatabaseClient, Prisma, type session_status } from '@sda/database';
import type { AccessSessionDto } from './access-sessions.service.js';

type PrismaClient = ReturnType<typeof getDatabaseClient>;

interface RawAccessSessionRow {
  id: string;
  access_grant_id: string;
  document_version_id: string | bigint;
  user_id: string | bigint;
  ip_address: string;
  user_agent: string | null;
  status: string;
  started_at: Date | string;
  last_activity_at: Date | string;
  ended_at: Date | string | null;
  terminated_reason: string | null;
  username: string;
  full_name: string;
  version_no: number | string;
  document_id: string;
  document_code: string;
  document_title: string;
}

interface RawCountRow {
  total: bigint | number | string;
}

/**
 * Thuật toán: Chuẩn hóa chuỗi tìm kiếm phiên đọc bằng cách loại bỏ ký tự NUL (`\u0000`) không hợp lệ trong PostgreSQL UTF-8 và cắt khoảng trắng hai đầu.
 */
export function normalizeSessionSearchTerm(search?: string): string {
  if (!search) return '';
  return search.replaceAll('\0', '').trim();
}

/**
 * Thuật toán: Thoát các ký tự đại diện `ILIKE` (`!`, `%`, `_`) bằng ký tự thoát `!` (độc lập với `standard_conforming_strings`).
 */
export function escapeSqlLikePattern(value: string): string {
  return value.replace(/[!%_]/gu, (ch) => `!${ch}`);
}

/**
 * Thuật toán: Kiểm định địa chỉ IPv4/IPv6 thuần hợp lệ với kiểu `INET` của PostgreSQL
 * (loại trừ hậu tố zone index IPv6 như `%eth0` vốn được Node `net.isIP` chấp nhận nhưng PostgreSQL `::inet` từ chối bằng `22P02`).
 */
export function isValidPostgresInetLiteral(value: string): boolean {
  return /^[0-9a-fA-F:.]+$/u.test(value) && isIP(value) !== 0;
}

/**
 * Thuật toán: Xây dựng nhánh `where.OR` an toàn cho Prisma `findMany`/`count` (không bao giờ phát sinh `ip_address.contains` trên cột `INET`).
 */
export function buildAccessSessionPrismaSearchOr(term: string): Prisma.AccessSessionWhereInput[] {
  const searchOr: Prisma.AccessSessionWhereInput[] = [
    { users: { username: { contains: term, mode: 'insensitive' } } },
    { users: { full_name: { contains: term, mode: 'insensitive' } } },
    {
      document_versions: {
        document: {
          OR: [
            { title: { contains: term, mode: 'insensitive' } },
            { document_code: { contains: term, mode: 'insensitive' } },
          ],
        },
      },
    },
  ];
  if (isValidPostgresInetLiteral(term)) {
    searchOr.unshift({ ip_address: { equals: term } });
  }
  return searchOr;
}

function toIsoTimestamp(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

/**
 * Thuật toán: Thực thi cặp truy vấn SQL tham số hóa (`rows` + `COUNT(*)`) qua `$queryRaw` để tìm kiếm phiên đọc theo người dùng, tài liệu và địa chỉ IP (`INET`) kèm cô lập phòng ban.
 */
export async function queryAccessSessionsWithSearch(params: {
  database: PrismaClient;
  requestedStatus: session_status | 'ALL';
  term: string;
  visibleDepts: bigint[] | null;
  limit: number;
  skip: number;
}): Promise<{ data: AccessSessionDto[]; filteredTotal: number }> {
  const { database, requestedStatus, term, visibleDepts, limit, skip } = params;
  const conditions: Prisma.Sql[] = [];

  if (visibleDepts !== null) {
    if (visibleDepts.length === 0) {
      conditions.push(Prisma.sql`FALSE`);
    } else {
      const deptIdStrings = visibleDepts.map((id) => id.toString());
      conditions.push(Prisma.sql`d."department_id" = ANY((${deptIdStrings}::text[])::bigint[])`);
    }
  }

  if (requestedStatus !== 'ALL') {
    conditions.push(Prisma.sql`s."status" = ${requestedStatus}::session_status`);
  }

  const likePattern = `%${escapeSqlLikePattern(term)}%`;
  const searchPredicates: Prisma.Sql[] = [
    Prisma.sql`host(s."ip_address") ILIKE ${likePattern} ESCAPE '!'`,
    Prisma.sql`u."username" ILIKE ${likePattern} ESCAPE '!'`,
    Prisma.sql`u."full_name" ILIKE ${likePattern} ESCAPE '!'`,
    Prisma.sql`d."title" ILIKE ${likePattern} ESCAPE '!'`,
    Prisma.sql`d."document_code" ILIKE ${likePattern} ESCAPE '!'`,
  ];
  if (isValidPostgresInetLiteral(term)) {
    searchPredicates.push(Prisma.sql`s."ip_address" = ${term}::inet`);
  }
  conditions.push(Prisma.sql`(${Prisma.join(searchPredicates, ' OR ')})`);

  const whereSql = Prisma.sql`WHERE ${Prisma.join(conditions, ' AND ')}`;

  const [rows, countRows] = await Promise.all([
    database.$queryRaw<RawAccessSessionRow[]>(
      Prisma.sql`
        SELECT
          s."id"::text AS "id",
          s."access_grant_id"::text AS "access_grant_id",
          s."document_version_id"::text AS "document_version_id",
          s."user_id"::text AS "user_id",
          host(s."ip_address") AS "ip_address",
          s."user_agent",
          s."status"::text AS "status",
          s."started_at",
          s."last_activity_at",
          s."ended_at",
          s."terminated_reason",
          u."username",
          u."full_name",
          dv."version_no",
          d."id"::text AS "document_id",
          d."document_code",
          d."title" AS "document_title"
        FROM "access_sessions" s
        INNER JOIN "users" u ON u."id" = s."user_id"
        INNER JOIN "document_versions" dv ON dv."id" = s."document_version_id"
        INNER JOIN "documents" d ON d."id" = dv."document_id"
        ${whereSql}
        ORDER BY s."started_at" DESC, s."id" DESC
        LIMIT ${limit}
        OFFSET ${skip}
      `,
    ),
    database.$queryRaw<RawCountRow[]>(
      Prisma.sql`
        SELECT COUNT(*)::bigint AS "total"
        FROM "access_sessions" s
        INNER JOIN "users" u ON u."id" = s."user_id"
        INNER JOIN "document_versions" dv ON dv."id" = s."document_version_id"
        INNER JOIN "documents" d ON d."id" = dv."document_id"
        ${whereSql}
      `,
    ),
  ]);

  const data: AccessSessionDto[] = rows.map((row) => ({
    id: row.id,
    accessGrantId: row.access_grant_id,
    documentVersionId: String(row.document_version_id),
    userId: String(row.user_id),
    username: row.username,
    fullName: row.full_name,
    documentId: row.document_id,
    documentCode: row.document_code,
    documentTitle: row.document_title,
    versionNo: Number(row.version_no),
    ipAddress: row.ip_address,
    userAgent: row.user_agent,
    status: row.status,
    startedAt: toIsoTimestamp(row.started_at),
    lastActivityAt: toIsoTimestamp(row.last_activity_at),
    endedAt: row.ended_at ? toIsoTimestamp(row.ended_at) : null,
    terminatedReason: row.terminated_reason,
  }));

  const filteredTotal = Number(countRows[0]?.total ?? 0);
  return { data, filteredTotal };
}
