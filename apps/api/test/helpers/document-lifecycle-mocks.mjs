import { DocumentsService } from '../../dist/modules/documents/documents.service.js';
import { AuthorizationCache } from '../../dist/modules/rbac/authorization-cache.js';
import { createDocumentCatalogStores } from './document-lifecycle-store.mjs';

export function createMockAudit() {
  const recorded = [];
  return {
    recorded,
    record: async (event, context) => {
      recorded.push({ ...event, context });
    },
  };
}

export function createMockAuthorization(permissions = []) {
  return {
    hasPermission: async (principal, resource, action, options = {}) => {
      return permissions.some(
        (p) =>
          p.userId === principal.userId &&
          p.resource === resource &&
          p.action === action &&
          (!options.targetDepartmentId ||
            p.scopeDepartmentId === null ||
            p.scopeDepartmentId === options.targetDepartmentId),
      );
    },
  };
}

export function createInMemoryDatabase(initialState = {}) {
  let autoId = 1000n;
  const nextId = () => ++autoId;

  const { documents, versions, classifications, models } = createDocumentCatalogStores(
    initialState,
    nextId,
  );
  const accessGrants = new Map(initialState.accessGrants ?? []);
  const accessSessions = new Map(initialState.accessSessions ?? []);
  const userAttributeAssignments = new Map(initialState.userAttributeAssignments ?? []);
  const notifications = new Map();
  const securityAlerts = new Map();

  const db = {
    ...models,
    accessGrant: {
      findFirst: async ({ where }) => {
        return (
          Array.from(accessGrants.values()).find((g) => {
            if (where.document_id && g.document_id !== where.document_id) return false;
            if (where.principal_type && g.principal_type !== where.principal_type) return false;
            if (where.principal_user_id && g.principal_user_id !== where.principal_user_id)
              return false;
            if (where.status && g.status !== where.status) return false;
            return true;
          }) ?? null
        );
      },
      findMany: async ({ where }) => {
        return Array.from(accessGrants.values()).filter((g) => {
          if (where.document_id && g.document_id !== where.document_id) return false;
          if (where.status && g.status !== where.status) return false;
          return true;
        });
      },
      create: async ({ data }) => {
        const id = data.id || `grant-${nextId()}`;
        const record = { id, ...data };
        accessGrants.set(id, record);
        return record;
      },
      update: async ({ where, data }) => {
        const grant = accessGrants.get(where.id);
        if (!grant) throw new Error('Grant not found');
        const updated = { ...grant, ...data };
        accessGrants.set(where.id, updated);
        return updated;
      },
      updateMany: async ({ where, data }) => {
        let count = 0;
        for (const [id, grant] of accessGrants.entries()) {
          if (where.document_id && grant.document_id !== where.document_id) continue;
          if (where.status && grant.status !== where.status) continue;
          accessGrants.set(id, { ...grant, ...data });
          count++;
        }
        return { count };
      },
    },
    accessSession: {
      findMany: async ({ where }) => {
        return Array.from(accessSessions.values()).filter((s) => {
          if (where.access_grant_id && s.access_grant_id !== where.access_grant_id) return false;
          if (where.status && s.status !== where.status) return false;
          return true;
        });
      },
      update: async ({ where, data }) => {
        const session = accessSessions.get(where.id);
        if (!session) throw new Error('Session not found');
        const updated = { ...session, ...data };
        accessSessions.set(where.id, updated);
        return updated;
      },
      updateMany: async ({ where, data }) => {
        let count = 0;
        for (const [id, session] of accessSessions.entries()) {
          if (where.access_grant_id && session.access_grant_id !== where.access_grant_id) continue;
          if (where.status && session.status !== where.status) continue;
          if (
            where.document_version_id?.in &&
            !where.document_version_id.in.includes(session.document_version_id)
          ) {
            continue;
          }
          accessSessions.set(id, { ...session, ...data });
          count++;
        }
        return { count };
      },
    },
    userAttributeAssignment: {
      findFirst: async ({ where }) => {
        const assignments = Array.from(userAttributeAssignments.values()).filter(
          (a) =>
            a.user_id === where.user_id && a.attribute_code === where.attribute_definitions?.code,
        );
        if (assignments.length === 0) return null;
        return {
          ...assignments[0],
          attribute_options: { numeric_rank: assignments[0].numeric_rank },
        };
      },
    },
    notification: {
      create: async ({ data }) => {
        notifications.set(data.id, data);
        return data;
      },
    },
    securityAlert: {
      create: async ({ data }) => {
        securityAlerts.set(data.id, data);
        return data;
      },
    },
    $transaction: async (fn) => fn(db),
  };

  return {
    db,
    documents,
    versions,
    classifications,
    accessGrants,
    accessSessions,
    userAttributeAssignments,
    notifications,
    securityAlerts,
  };
}

export function createDocumentsTestService(initialState = {}, permissions = []) {
  const stores = createInMemoryDatabase(initialState);
  const mockAudit = createMockAudit();
  const mockAuth = createMockAuthorization(permissions);
  const cache = new AuthorizationCache();
  const service = new DocumentsService(mockAudit, mockAuth, cache, stores.db);
  return { ...stores, mockAudit, mockAuth, cache, service };
}
