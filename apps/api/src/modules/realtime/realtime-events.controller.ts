/**
 * @module RealtimeEventsController
 * Thuật toán: Điểm cuối luồng Server-Sent Events (`GET /api/v1/events/stream`) bảo vệ bằng `AuthGuard` + `@AllowAuthenticatedSelf()`,
 * xác định hạn sống phiên `expiresAtMs` và bao đóng phòng ban `allowedDeptIds` tại thời điểm kết nối (`BUG-063`),
 * chiếm quyền phản hồi Fastify (`reply.hijack()`) và áp đặt đầy đủ tiêu đề bảo mật OWASP.
 */
import {
  Controller,
  ForbiddenException,
  Get,
  Optional,
  Req,
  Res,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { getDatabaseClient } from '@sda/database';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { AppConfigService } from '../../config/config.service.js';
import { AllowAuthenticatedSelf } from '../rbac/require-permission.js';
import { RealtimeEventsService } from './realtime-events.service.js';

const DEFAULT_IDLE_TTL_SECONDS = 28_800;

/**
 * Thuật toán: Kiểm Định Danh Sách Trắng Nguồn Chéo Cho Luồng SSE Hijacked (`isAllowedSseOrigin`)
 * Mục đích: Ngăn phản chiếu `Origin` tùy ý kèm `Access-Control-Allow-Credentials: true` khi `reply.hijack()` bỏ qua middleware CORS của Fastify (V-03, N01).
 */
export function isAllowedSseOrigin(
  origin: string | undefined,
  allowedOrigins: readonly string[] | undefined,
): boolean {
  if (!origin || !allowedOrigins || allowedOrigins.length === 0) return false;
  const normalized = origin.trim().toLowerCase();
  if (!normalized || normalized === '*') return false;
  return allowedOrigins.some((candidate) => candidate.trim().toLowerCase() === normalized);
}

const ALL_SOC_EVENT_TYPES = [
  'SECURITY_ALERT_UPDATED',
  'INCIDENT_REPORT_UPDATED',
  'ACCESS_SESSION_UPDATED',
  'DETECTION_RULE_UPDATED',
] as const;

async function resolveSseSessionMetadata(
  userId: bigint,
  sessionId: string | undefined,
  fallbackRoles: readonly string[],
  config?: AppConfigService,
): Promise<{
  roles: string[];
  expiresAtMs?: number | undefined;
  allowedDeptIds?: Set<string> | null | undefined;
  allowedSocEvents?: Set<string> | undefined;
  allowedDeptIdsByEvent?: Map<string, Set<string> | null> | undefined;
}> {
  let db: ReturnType<typeof getDatabaseClient>;
  try {
    db = getDatabaseClient();
  } catch {
    // Fallback cleanly in lightweight unit tests without initialized database client
    return { roles: [...fallbackRoles] };
  }

  let roles = [...fallbackRoles];
  let expiresAtMs: number | undefined;
  let allowedDeptIds: Set<string> | null | undefined;
  let allowedSocEvents: Set<string> | undefined;
  let allowedDeptIdsByEvent: Map<string, Set<string> | null> | undefined;

  try {
    const now = new Date();
    const rawIdle =
      typeof config?.get === 'function' ? config.get('AUTH_SESSION_IDLE_TTL_SECONDS') : undefined;
    const idleTtlSeconds =
      typeof rawIdle === 'number' && Number.isFinite(rawIdle) && rawIdle > 0
        ? rawIdle
        : DEFAULT_IDLE_TTL_SECONDS;

    if (sessionId && typeof db.authSession?.findUnique === 'function') {
      const authSession = await db.authSession.findUnique({
        where: { id: sessionId },
        select: { expires_at: true, last_seen_at: true },
      });
      if (authSession) {
        const absMs = authSession.expires_at.getTime();
        const idleMs = authSession.last_seen_at.getTime() + idleTtlSeconds * 1_000;
        expiresAtMs = Math.min(absMs, idleMs);
      }
    }

    if (typeof db.userRole?.findMany === 'function') {
      const assignments = await db.userRole.findMany({
        where: {
          user_id: userId,
          valid_from: { lte: now },
          AND: [
            { OR: [{ valid_to: null }, { valid_to: { gt: now } }] },
            { OR: [{ scope_department_id: null }, { departments: { is: { is_active: true } } }] },
          ],
          roles: { is_active: true },
        },
        include: {
          roles: {
            include: {
              role_permissions: { include: { permissions: true } },
            },
          },
        },
      });

      const liveRoles = new Set<string>();
      const socEvents = new Set<string>();
      const eventGlobalFlag = new Map<string, boolean>();
      const eventScopeRoots = new Map<string, Set<bigint>>();
      let earliestRoleValidToMs: number | undefined;

      const grantSocEventScope = (eventType: string, scopeDeptId: bigint | null): void => {
        socEvents.add(eventType);
        if (scopeDeptId === null) {
          eventGlobalFlag.set(eventType, true);
          eventScopeRoots.delete(eventType);
        } else if (!eventGlobalFlag.get(eventType)) {
          let roots = eventScopeRoots.get(eventType);
          if (!roots) {
            roots = new Set<bigint>();
            eventScopeRoots.set(eventType, roots);
          }
          roots.add(scopeDeptId);
        }
      };

      for (const a of assignments) {
        if (a.valid_to) {
          const validToMs = a.valid_to.getTime();
          earliestRoleValidToMs =
            earliestRoleValidToMs === undefined
              ? validToMs
              : Math.min(earliestRoleValidToMs, validToMs);
        }
        const roleObj = a.roles;
        if (!roleObj?.code) continue;
        liveRoles.add(roleObj.code);
        const perms = (roleObj.role_permissions ?? [])
          .map((rp) => rp.permissions)
          .filter((p): p is NonNullable<typeof p> => Boolean(p));

        if (roleObj.code === 'SECURITY_OFFICER') {
          for (const evt of ALL_SOC_EVENT_TYPES) {
            grantSocEventScope(evt, a.scope_department_id);
          }
        } else {
          for (const p of perms) {
            if (p.resource_type === 'SECURITY_ALERT') {
              grantSocEventScope('SECURITY_ALERT_UPDATED', a.scope_department_id);
            } else if (p.resource_type === 'INCIDENT_REPORT') {
              grantSocEventScope('INCIDENT_REPORT_UPDATED', a.scope_department_id);
            } else if (p.resource_type === 'ACCESS_SESSION') {
              grantSocEventScope('ACCESS_SESSION_UPDATED', a.scope_department_id);
            } else if (p.resource_type === 'DETECTION_RULE') {
              grantSocEventScope('DETECTION_RULE_UPDATED', a.scope_department_id);
            }
          }
        }
      }

      roles = [...liveRoles];
      if (earliestRoleValidToMs !== undefined) {
        expiresAtMs =
          expiresAtMs === undefined
            ? earliestRoleValidToMs
            : Math.min(expiresAtMs, earliestRoleValidToMs);
      }

      if (socEvents.size > 0) {
        allowedSocEvents = socEvents;
        allowedDeptIdsByEvent = new Map<string, Set<string> | null>();

        const needsDeptExpansion = eventScopeRoots.size > 0;
        let activeDeptIdSet: Set<string> | null = null;
        const childrenByParent = new Map<string, bigint[]>();

        if (needsDeptExpansion && typeof db.department?.findMany === 'function') {
          const allDepts = await db.department.findMany({
            where: { is_active: true },
            select: { id: true, parent_id: true },
          });
          activeDeptIdSet = new Set<string>(allDepts.map((d) => d.id.toString()));
          for (const dept of allDepts) {
            if (dept.parent_id !== null) {
              const pKey = dept.parent_id.toString();
              const arr = childrenByParent.get(pKey) ?? [];
              arr.push(dept.id);
              childrenByParent.set(pKey, arr);
            }
          }
        }

        const expandActiveSubtree = (roots: ReadonlySet<bigint>): Set<string> => {
          const expanded = new Set<string>();
          const queue: bigint[] = [];
          for (const rootId of roots) {
            const key = rootId.toString();
            if (activeDeptIdSet !== null && !activeDeptIdSet.has(key)) continue;
            queue.push(rootId);
          }
          while (queue.length > 0) {
            const cur = queue.pop()!;
            const key = cur.toString();
            if (expanded.has(key)) continue;
            expanded.add(key);
            for (const childId of childrenByParent.get(key) ?? []) {
              queue.push(childId);
            }
          }
          return expanded;
        };

        let allEventsGlobal = true;
        const unionScopedDepts = new Set<string>();
        for (const evt of socEvents) {
          if (eventGlobalFlag.get(evt)) {
            allowedDeptIdsByEvent.set(evt, null);
          } else {
            allEventsGlobal = false;
            const expanded = expandActiveSubtree(eventScopeRoots.get(evt) ?? new Set());
            allowedDeptIdsByEvent.set(evt, expanded);
            for (const dId of expanded) unionScopedDepts.add(dId);
          }
        }
        allowedDeptIds = allEventsGlobal ? null : unionScopedDepts;
      }
    }
  } catch {
    // HIGH-10: Khi CSDL đã khởi tạo nhưng truy vấn phân quyền thất bại, đóng fail-closed bằng 503 để trình duyệt tự kết nối lại thay vì fallback về phạm vi toàn cục.
    throw new ServiceUnavailableException(
      'Unable to verify realtime stream authorization scope; please retry.',
    );
  }

  return {
    roles,
    ...(expiresAtMs !== undefined ? { expiresAtMs } : {}),
    ...(allowedDeptIds !== undefined ? { allowedDeptIds } : {}),
    ...(allowedSocEvents !== undefined ? { allowedSocEvents } : {}),
    ...(allowedDeptIdsByEvent !== undefined ? { allowedDeptIdsByEvent } : {}),
  };
}

@ApiTags('events')
@AllowAuthenticatedSelf()
@Controller('events')
export class RealtimeEventsController {
  constructor(
    private readonly realtime: RealtimeEventsService,
    @Optional() private readonly config?: AppConfigService,
  ) {}

  /**
   * Thuật toán: Khởi tạo luồng SSE liên tục một chiều (`text/event-stream`) gắn định danh phiên người dùng, hạn `expiresAtMs` và phạm vi `allowedDeptIds` (`BUG-063`).
   */
  @Get('stream')
  @ApiOperation({ summary: 'Subscribe to authenticated real-time Server-Sent Events stream' })
  async stream(@Req() request: FastifyRequest, @Res() reply: FastifyReply): Promise<void> {
    const principal = request.auth;
    if (!principal) {
      throw new UnauthorizedException('Authentication required.');
    }

    const origin = request.headers.origin;
    const originAllowed = isAllowedSseOrigin(origin, this.config?.corsOrigins);
    // CONFLICT-RESOLVED: Từ chối ngay mọi kết nối SSE có header Origin nằm ngoài danh sách trắng trước khi hijack socket (N01).
    if (
      origin &&
      this.config?.corsOrigins &&
      this.config.corsOrigins.length > 0 &&
      !originAllowed
    ) {
      throw new ForbiddenException('Request origin is not allowed.');
    }

    const sseMeta = await resolveSseSessionMetadata(
      principal.userId,
      principal.sessionId,
      principal.roles ?? [],
      this.config,
    );

    reply.hijack();
    const rawReq = request.raw;
    const rawRes = reply.raw;
    rawReq.setTimeout(0);
    rawReq.socket?.setTimeout(0);
    rawReq.socket?.setKeepAlive(true, 15_000);

    const headers: Record<string, string> = {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Resource-Policy': 'same-origin',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
      'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; sandbox",
      ...(this.config?.isProduction
        ? { 'Strict-Transport-Security': 'max-age=31536000; includeSubDomains' }
        : {}),
      ...(request.correlationId ? { 'X-Correlation-Id': request.correlationId } : {}),
      ...(origin && originAllowed
        ? {
            'Access-Control-Allow-Origin': origin,
            'Access-Control-Allow-Credentials': 'true',
            Vary: 'Origin',
          }
        : {}),
    };

    rawRes.writeHead(200, headers);
    rawRes.flushHeaders?.();
    rawRes.write('retry: 3000\n');
    rawRes.write(
      `event: connected\ndata: ${JSON.stringify({
        connected: true,
        timestamp: new Date().toISOString(),
      })}\n\n`,
    );

    const clientId = this.realtime.registerClient({
      userId: principal.userId.toString(),
      sessionId: principal.sessionId,
      roles: sseMeta.roles,
      ...(sseMeta.expiresAtMs !== undefined ? { expiresAtMs: sseMeta.expiresAtMs } : {}),
      ...(sseMeta.allowedDeptIds !== undefined ? { allowedDeptIds: sseMeta.allowedDeptIds } : {}),
      ...(sseMeta.allowedSocEvents !== undefined
        ? { allowedSocEvents: sseMeta.allowedSocEvents }
        : {}),
      ...(sseMeta.allowedDeptIdsByEvent !== undefined
        ? { allowedDeptIdsByEvent: sseMeta.allowedDeptIdsByEvent }
        : {}),
      writeFrame: (frame: string) => {
        if (rawRes.destroyed || rawRes.writableEnded) return false;
        try {
          rawRes.write(frame);
          return true;
        } catch {
          return false;
        }
      },
      close: () => {
        if (!rawRes.destroyed && !rawRes.writableEnded) {
          rawRes.end();
        }
      },
    });

    const cleanup = () => {
      this.realtime.unregisterClient(clientId);
    };
    rawReq.once('close', cleanup);
    rawRes.once('close', cleanup);
    rawRes.once('error', cleanup);
  }
}
