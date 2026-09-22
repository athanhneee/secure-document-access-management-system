import { ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { getDatabaseClient, withSerializableTransaction, type Prisma } from '@sda/database';
import type { AuthPrincipal, RequestContext } from '../auth/auth.types.js';
import { AuthorizationService } from '../rbac/authorization.service.js';
import { RbacAuditService } from '../rbac/rbac-audit.service.js';

@Injectable()
export class DepartmentsService {
  private readonly database = getDatabaseClient();

  constructor(
    private readonly authorization: AuthorizationService,
    private readonly audit: RbacAuditService,
  ) {}

  async list(principal: AuthPrincipal) {
    const visible = await this.authorization.visibleDepartmentIds(
      principal,
      'DEPARTMENT',
      'MANAGE',
    );
    const departments = await this.database.department.findMany({
      where: visible === null ? {} : { id: { in: visible } },
      orderBy: [{ code: 'asc' }, { id: 'asc' }],
      select: { id: true, code: true, name: true, parent_id: true, is_active: true, version: true },
    });
    return { data: departments.map((department) => this.present(department)) };
  }

  async get(principal: AuthPrincipal, id: bigint) {
    const department = await this.database.department.findUnique({
      where: { id },
      select: { id: true, code: true, name: true, parent_id: true, is_active: true, version: true },
    });
    if (
      !department ||
      !(await this.authorization.hasPermission(principal, 'DEPARTMENT', 'MANAGE', {
        targetDepartmentId: id,
      }))
    ) {
      throw new NotFoundException('Department not found.');
    }
    return this.present(department);
  }

  async create(
    principal: AuthPrincipal,
    input: { code: string; name: string; parentId?: bigint | null | undefined },
    context: RequestContext,
  ) {
    await this.authorization.assertPermission(principal, 'DEPARTMENT', 'MANAGE', {
      targetDepartmentId: input.parentId ?? null,
    });
    const department = await withSerializableTransaction(async (transaction) => {
      if (input.parentId !== null && input.parentId !== undefined) {
        const parent = await transaction.department.findFirst({
          where: { id: input.parentId, is_active: true },
        });
        if (!parent) throw new NotFoundException('Active parent department not found.');
      }
      const created = await transaction.department.create({
        data: { code: input.code, name: input.name, parent_id: input.parentId ?? null },
      });
      await this.audit.record(
        transaction,
        {
          action: 'DEPARTMENT_CREATED',
          objectType: 'DEPARTMENT',
          objectId: created.id.toString(),
          before: null,
          after: this.present(created),
        },
        principal,
        context,
      );
      return created;
    });
    return this.present(department);
  }

  async update(
    principal: AuthPrincipal,
    id: bigint,
    input: {
      expectedVersion: number;
      name?: string | undefined;
      parentId?: bigint | null | undefined;
    },
    context: RequestContext,
  ) {
    const department = await withSerializableTransaction(async (transaction) => {
      const before = await transaction.department.findUnique({ where: { id } });
      if (
        !before ||
        !(await this.authorization.hasPermission(principal, 'DEPARTMENT', 'MANAGE', {
          targetDepartmentId: id,
        }))
      ) {
        throw new NotFoundException('Department not found.');
      }
      if (input.parentId === id)
        throw new ConflictException('Department cannot be its own parent.');
      if (input.parentId !== null && input.parentId !== undefined) {
        await this.authorization.assertPermission(principal, 'DEPARTMENT', 'MANAGE', {
          targetDepartmentId: input.parentId,
        });
        const parent = await transaction.department.findFirst({
          where: { id: input.parentId, is_active: true },
        });
        if (!parent) throw new NotFoundException('Active parent department not found.');
        if (await this.isDescendant(transaction, input.parentId, id))
          throw new ConflictException('Department hierarchy cycle is not allowed.');
      }
      const changed = await transaction.department.updateMany({
        where: { id, version: input.expectedVersion },
        data: {
          ...(input.name !== undefined ? { name: input.name } : {}),
          ...(input.parentId !== undefined ? { parent_id: input.parentId } : {}),
          updated_at: new Date(),
          version: { increment: 1 },
        },
      });
      if (changed.count !== 1)
        throw new ConflictException('Department was changed by another request.');
      const after = await transaction.department.findUniqueOrThrow({ where: { id } });
      await this.audit.record(
        transaction,
        {
          action: 'DEPARTMENT_UPDATED',
          objectType: 'DEPARTMENT',
          objectId: id.toString(),
          before: this.present(before),
          after: this.present(after),
        },
        principal,
        context,
      );
      return after;
    });
    this.authorization.invalidateAll();
    return this.present(department);
  }

  async deactivate(
    principal: AuthPrincipal,
    id: bigint,
    expectedVersion: number,
    context: RequestContext,
  ) {
    const department = await withSerializableTransaction(async (transaction) => {
      const before = await transaction.department.findUnique({ where: { id } });
      if (
        !before ||
        !(await this.authorization.hasPermission(principal, 'DEPARTMENT', 'MANAGE', {
          targetDepartmentId: id,
        }))
      ) {
        throw new NotFoundException('Department not found.');
      }
      const now = new Date();
      const [activeChildren, activeUsers, activeScopes] = await Promise.all([
        transaction.department.count({ where: { parent_id: id, is_active: true } }),
        transaction.user.count({ where: { department_id: id, status: { not: 'DISABLED' } } }),
        transaction.userRole.count({
          where: {
            scope_department_id: id,
            valid_from: { lte: now },
            OR: [{ valid_to: null }, { valid_to: { gt: now } }],
          },
        }),
      ]);
      if (activeChildren + activeUsers + activeScopes > 0)
        throw new ConflictException(
          'Department still has active children, users, or scoped role assignments.',
        );
      const changed = await transaction.department.updateMany({
        where: { id, version: expectedVersion },
        data: { is_active: false, updated_at: now, version: { increment: 1 } },
      });
      if (changed.count !== 1)
        throw new ConflictException('Department was changed by another request.');
      const after = await transaction.department.findUniqueOrThrow({ where: { id } });
      await this.audit.record(
        transaction,
        {
          action: 'DEPARTMENT_DEACTIVATED',
          objectType: 'DEPARTMENT',
          objectId: id.toString(),
          before: this.present(before),
          after: this.present(after),
        },
        principal,
        context,
      );
      return after;
    });
    this.authorization.invalidateAll();
    return this.present(department);
  }

  private async isDescendant(
    transaction: Prisma.TransactionClient,
    candidate: bigint,
    root: bigint,
  ): Promise<boolean> {
    let current: bigint | null = candidate;
    const seen = new Set<bigint>();
    while (current !== null && !seen.has(current)) {
      if (current === root) return true;
      seen.add(current);
      const node: { parent_id: bigint | null } | null = await transaction.department.findUnique({
        where: { id: current },
        select: { parent_id: true },
      });
      current = node?.parent_id ?? null;
    }
    return false;
  }

  private present(department: {
    id: bigint;
    code: string;
    name: string;
    parent_id: bigint | null;
    is_active: boolean;
    version: number;
  }): Record<string, string | number | boolean | null> {
    return {
      id: department.id.toString(),
      code: department.code,
      name: department.name,
      parentId: department.parent_id?.toString() ?? null,
      isActive: department.is_active,
      version: department.version,
    };
  }
}
