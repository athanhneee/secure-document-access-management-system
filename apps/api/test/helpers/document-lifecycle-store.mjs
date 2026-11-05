export function createDocumentCatalogStores(initialState = {}, nextId) {
  const documents = new Map(
    (initialState.documents ?? []).map(([k, v]) => [
      k,
      {
        created_at: new Date(),
        updated_at: new Date(),
        version: 0,
        ...v,
      },
    ]),
  );
  const versions = new Map(initialState.versions ?? []);
  const classifications = new Map(initialState.classifications ?? []);
  const classificationLevels = new Map(
    initialState.classificationLevels ?? [
      [1n, { id: 1n, code: 'INTERNAL', name: 'Nội bộ', rank: 1, is_active: true }],
      [2n, { id: 2n, code: 'CONFIDENTIAL', name: 'Mật', rank: 2, is_active: true }],
      [3n, { id: 3n, code: 'SECRET', name: 'Tối mật', rank: 3, is_active: true }],
      [4n, { id: 4n, code: 'TOP_SECRET', name: 'Tuyệt mật', rank: 4, is_active: true }],
    ],
  );
  const businessCategories = new Map(
    initialState.businessCategories ?? [
      [10n, { id: 10n, code: 'GENERAL_OPS', name: 'Nghiệp vụ chung', is_active: true }],
      [20n, { id: 20n, code: 'FINANCE', name: 'Tài chính', is_active: true }],
    ],
  );
  const departments = new Map(
    initialState.departments ?? [
      [100n, { id: 100n, code: 'DEPT_A', name: 'Phòng A', is_active: true }],
      [200n, { id: 200n, code: 'DEPT_INACTIVE', name: 'Phòng Inactive', is_active: false }],
    ],
  );
  const users = new Map(
    initialState.users ?? [
      [1n, { id: 1n, username: 'owner_user', status: 'ACTIVE' }],
      [2n, { id: 2n, username: 'other_user', status: 'ACTIVE' }],
      [3n, { id: 3n, username: 'low_clearance_user', status: 'ACTIVE' }],
      [4n, { id: 4n, username: 'high_clearance_user', status: 'ACTIVE' }],
      [99n, { id: 99n, username: 'disabled_user', status: 'DISABLED' }],
    ],
  );

  const models = {
    document: {
      findUnique: async ({ where }) => {
        const doc = documents.get(where.id);
        if (!doc) return null;
        const currentVersion = doc.current_version_id ? versions.get(doc.current_version_id) : null;
        const history = Array.from(classifications.values())
          .filter((c) => c.document_id === doc.id)
          .map((c) => ({
            ...c,
            classification_levels: classificationLevels.get(c.classification_level_id),
            business_categories: businessCategories.get(c.business_category_id),
          }));
        return {
          ...doc,
          users: users.get(doc.owner_id),
          departments: departments.get(doc.department_id),
          current_version: currentVersion,
          classification_history: history,
        };
      },
      findMany: async ({ where = {} } = {}) => {
        let list = Array.from(documents.values());
        if (where.status?.notIn) {
          list = list.filter((d) => !where.status.notIn.includes(d.status));
        }
        if (where.retention_until?.lte) {
          list = list.filter(
            (d) => d.retention_until && d.retention_until <= where.retention_until.lte,
          );
        }
        return list.map((doc) => ({
          ...doc,
          users: users.get(doc.owner_id),
        }));
      },
      create: async ({ data }) => {
        const record = {
          ...data,
          version: 0,
          created_at: new Date(),
          updated_at: new Date(),
        };
        documents.set(data.id, record);
        return record;
      },
      update: async ({ where, data }) => {
        const doc = documents.get(where.id);
        if (!doc) throw new Error('Document not found');
        const updated = {
          ...doc,
          ...data,
          version:
            typeof data.version?.increment === 'number'
              ? (doc.version ?? 0) + data.version.increment
              : (data.version ?? doc.version),
          updated_at: new Date(),
        };
        documents.set(where.id, updated);
        return updated;
      },
    },
    documentVersion: {
      findUnique: async ({ where }) => {
        if (where.id) return versions.get(where.id) ?? null;
        if (where.document_id_version_no) {
          const { document_id, version_no } = where.document_id_version_no;
          return (
            Array.from(versions.values()).find(
              (v) => v.document_id === document_id && v.version_no === version_no,
            ) ?? null
          );
        }
        return null;
      },
      findMany: async ({ where = {} } = {}) => {
        let list = Array.from(versions.values());
        if (where.document_id) list = list.filter((v) => v.document_id === where.document_id);
        return list;
      },
      create: async ({ data }) => {
        const id = nextId();
        const record = { id, ...data, created_at: new Date() };
        versions.set(id, record);
        return record;
      },
    },
    documentClassificationHistory: {
      findFirst: async ({ where }) => {
        const list = Array.from(classifications.values()).filter((c) => {
          if (c.document_id !== where.document_id) return false;
          if (where.effective_to === null && c.effective_to !== null) return false;
          return true;
        });
        const found = list[0];
        if (!found) return null;
        return {
          ...found,
          classification_levels: classificationLevels.get(found.classification_level_id),
          business_categories: businessCategories.get(found.business_category_id),
        };
      },
      findMany: async ({ where }) =>
        Array.from(classifications.values())
          .filter((c) => c.document_id === where.document_id)
          .map((c) => ({
            ...c,
            classification_levels: classificationLevels.get(c.classification_level_id),
            business_categories: businessCategories.get(c.business_category_id),
          })),
      create: async ({ data }) => {
        const id = nextId();
        const record = { id, ...data };
        classifications.set(id, record);
        return record;
      },
      update: async ({ where, data }) => {
        const rec = classifications.get(where.id);
        if (!rec) throw new Error('Classification record not found');
        const updated = { ...rec, ...data };
        classifications.set(where.id, updated);
        return updated;
      },
    },
    classificationLevel: {
      findUnique: async ({ where }) => classificationLevels.get(where.id) ?? null,
    },
    businessCategory: {
      findUnique: async ({ where }) => businessCategories.get(where.id) ?? null,
    },
    department: {
      findUnique: async ({ where }) => departments.get(where.id) ?? null,
    },
    user: {
      findUnique: async ({ where }) => users.get(where.id) ?? null,
    },
  };

  return { documents, versions, classifications, models };
}
