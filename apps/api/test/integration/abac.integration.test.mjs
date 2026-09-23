import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

for (const line of readFileSync(
  new URL('../../../../.local/dev.env', import.meta.url),
  'utf8',
).split(/\r?\n/u)) {
  const separator = line.indexOf('=');
  if (separator > 0) process.env[line.slice(0, separator)] ??= line.slice(separator + 1);
}

const sourceUrl = new URL(process.env.DATABASE_URL);
const adminUrl = new URL(sourceUrl);
adminUrl.pathname = '/postgres';
adminUrl.search = '';
const databaseName = `sda_abac_${randomUUID().replaceAll('-', '')}`;
const targetUrl = new URL(sourceUrl);
targetUrl.pathname = `/${databaseName}`;

let sql;
let service;
let disconnectDatabase;
let actorId;
let userId;
let documentId;
let assignmentId;
let conditionId;
let cache;

const simulationTime = new Date('2026-09-22T03:00:00.000Z');
const context = { ip: '10.10.1.8', correlationId: randomUUID() };

let dbAvailable = false;

async function isDatabaseReachable() {
  const client = new pg.Client({
    connectionString: adminUrl.toString(),
    connectionTimeoutMillis: 1000,
  });
  try {
    await client.connect();
    await client.end();
    return true;
  } catch {
    return false;
  }
}

async function adminQuery(statement) {
  const client = new pg.Client({ connectionString: adminUrl.toString() });
  await client.connect();
  try {
    await client.query(statement);
  } finally {
    await client.end();
  }
}

async function insertOne(statement, parameters = []) {
  const result = await sql.query(statement, parameters);
  return result.rows[0];
}

before(async () => {
  dbAvailable = await isDatabaseReachable();
  if (!dbAvailable) return;
  await adminQuery(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
  await adminQuery(`CREATE DATABASE "${databaseName}"`);

  const prismaCli = fileURLToPath(import.meta.resolve('prisma')).replace(
    /[\\/]build[\\/]types\.js$/u,
    '/build/index.js',
  );
  const migration = spawnSync(
    process.execPath,
    [prismaCli, 'migrate', 'deploy', '--config', 'prisma.config.ts'],
    {
      cwd: fileURLToPath(new URL('../../../../packages/database/', import.meta.url)),
      encoding: 'utf8',
      env: { ...process.env, DATABASE_URL: targetUrl.toString(), NODE_ENV: 'test' },
      shell: false,
    },
  );
  assert.equal(migration.status, 0, migration.stderr || migration.stdout);
  process.env.DATABASE_URL = targetUrl.toString();
  sql = new pg.Client({ connectionString: targetUrl.toString() });
  await sql.connect();

  const department = await insertOne(
    "INSERT INTO departments(code,name) VALUES ('ABAC_TEST','ABAC Test') RETURNING id",
  );
  const actor = await insertOne(
    "INSERT INTO users(username,email,password_hash,full_name,department_id,status) VALUES ('abac.admin','abac.admin@example.invalid','fixture','ABAC Admin',$1,'ACTIVE') RETURNING id",
    [department.id],
  );
  actorId = actor.id;
  const user = await insertOne(
    "INSERT INTO users(username,email,password_hash,full_name,department_id,status) VALUES ('abac.subject','abac.subject@example.invalid','fixture','ABAC Subject',$1,'ACTIVE') RETURNING id",
    [department.id],
  );
  userId = user.id;
  const category = await insertOne(
    "INSERT INTO business_categories(code,name,department_id) VALUES ('ABAC_CATEGORY','ABAC Category',$1) RETURNING id",
    [department.id],
  );
  const classification = await insertOne(
    "INSERT INTO classification_levels(code,name,rank,allow_download,require_watermark) VALUES ('ABAC_SECRET','ABAC Secret',2,true,true) RETURNING id",
  );
  documentId = randomUUID();
  await sql.query(
    "INSERT INTO documents(id,document_code,title,owner_id,department_id,status) VALUES ($1,'ABAC-DOC','Sensitive title must not enter audit',$2,$3,'ACTIVE')",
    [documentId, actorId, department.id],
  );
  await sql.query(
    'INSERT INTO document_classification_history(document_id,classification_level_id,business_category_id,classified_by,effective_from) VALUES ($1,$2,$3,$4,$5)',
    [documentId, classification.id, category.id, actorId, new Date('2026-01-01T00:00:00.000Z')],
  );
  const clearance = await insertOne(
    "INSERT INTO attribute_definitions(code,name,scope,value_type,is_required,created_by) VALUES ('CLEARANCE_LEVEL','Clearance','USER','ENUM',true,$1) RETURNING id",
    [actorId],
  );
  const option = await insertOne(
    "INSERT INTO attribute_options(attribute_definition_id,value_code,display_name,numeric_rank) VALUES ($1,'ABAC_HIGH','ABAC High',3) RETURNING id",
    [clearance.id],
  );
  const assignment = await insertOne(
    'INSERT INTO user_attribute_assignments(user_id,attribute_definition_id,option_id,valid_from,valid_to,assigned_by) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id',
    [
      userId,
      clearance.id,
      option.id,
      new Date('2026-01-01T00:00:00.000Z'),
      new Date('2027-01-01T00:00:00.000Z'),
      actorId,
    ],
  );
  assignmentId = assignment.id;
  const policy = await insertOne(
    "INSERT INTO policy_rules(code,name,effect,priority,target_resource,target_action,combining_algorithm,obligations,is_active,valid_from,created_by) VALUES ('ABAC_PERMIT_MFA','Permit MFA','PERMIT',100,'DOCUMENT','VIEW','DENY_OVERRIDES','[\"NO_CACHE\"]',true,'2026-01-01',$1) RETURNING id",
    [actorId],
  );
  const condition = await insertOne(
    "INSERT INTO policy_rule_conditions(policy_rule_id,context_key,operator,expected_value) VALUES ($1,'environment.mfa','EQ','true') RETURNING id",
    [policy.id],
  );
  conditionId = condition.id;

  const databaseModule = await import('@sda/database');
  ({ disconnectDatabase } = databaseModule);
  const { AbacRepository } = await import('../../dist/modules/abac/abac.repository.js');
  const { AbacAuditService } = await import('../../dist/modules/abac/abac-audit.service.js');
  const { AbacService } = await import('../../dist/modules/abac/abac.service.js');
  const config = {
    get(key) {
      if (key === 'ABAC_TRUSTED_NETWORK_CIDRS') return '10.0.0.0/8,2001:db8::/32';
      if (key === 'AUTH_AUDIT_HMAC_KEY') return 'integration-audit-key-that-is-long-enough';
      throw new Error(`Unexpected config key: ${key}`);
    },
  };
  cache = {
    values: new Map(),
    reads: [],
    async get(version) {
      this.reads.push(version);
      return this.values.get(version) ?? null;
    },
    async put(policyValue) {
      this.values.set(policyValue.version, policyValue);
    },
    async invalidate(version) {
      this.values.delete(version);
    },
  };
  service = new AbacService(new AbacRepository(config), cache, new AbacAuditService(config));
});

after(async () => {
  if (!dbAvailable) return;
  if (sql) await sql.end();
  if (disconnectDatabase) await disconnectDatabase();
  await adminQuery(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
});

test('simulation uses trusted rows, audits no document content, and cache follows policy version', async (t) => {
  if (!dbAvailable) {
    t.skip('Live PostgreSQL server not reachable at 127.0.0.1:5432 (run pnpm infra:up)');
    return;
  }
  const principal = {
    userId: BigInt(actorId),
    sessionId: randomUUID(),
    username: 'abac.admin',
    roles: ['SYSTEM_ADMIN'],
    mfa: true,
  };
  const request = {
    subjectUserId: BigInt(userId),
    resourceDocumentId: documentId,
    action: 'VIEW',
    time: simulationTime,
    ip: '10.10.1.8',
    deviceTrust: true,
    mfa: true,
    riskScore: 5,
  };
  const permit = await service.simulate(principal, request, context);
  assert.equal(permit.decision, 'PERMIT');
  assert.deepEqual(permit.obligations, [{ type: 'NO_CACHE' }]);
  const audit = await insertOne(
    "SELECT details::text AS details FROM audit_logs WHERE action='POLICY_SIMULATED' ORDER BY id DESC LIMIT 1",
  );
  assert.doesNotMatch(audit.details, /Sensitive title|content|description/u);

  const firstVersion = permit.policyVersion;
  await sql.query('UPDATE policy_rule_conditions SET expected_value=$1 WHERE id=$2', [
    false,
    conditionId,
  ]);
  const deniedAfterChange = await service.simulate(principal, request, {
    ...context,
    correlationId: randomUUID(),
  });
  assert.equal(deniedAfterChange.decision, 'DENY');
  assert.notEqual(deniedAfterChange.policyVersion, firstVersion);
  assert.ok(cache.reads.includes(firstVersion));
  assert.ok(cache.reads.includes(deniedAfterChange.policyVersion));
});

test('expired assignment is denied immediately even if a prior decision was cached', async (t) => {
  if (!dbAvailable) {
    t.skip('Live PostgreSQL server not reachable at 127.0.0.1:5432 (run pnpm infra:up)');
    return;
  }
  await sql.query('UPDATE user_attribute_assignments SET valid_to=$1 WHERE id=$2', [
    simulationTime,
    assignmentId,
  ]);

  const result = await service.simulate(
    {
      userId: BigInt(actorId),
      sessionId: randomUUID(),
      username: 'abac.admin',
      roles: ['SYSTEM_ADMIN'],
      mfa: true,
    },
    {
      subjectUserId: BigInt(userId),
      resourceDocumentId: documentId,
      action: 'VIEW',
      time: simulationTime,
      ip: '2001:db8::10',
      deviceTrust: true,
      mfa: true,
      riskScore: 5,
    },
    { ...context, correlationId: randomUUID() },
  );
  assert.equal(result.decision, 'DENY');
  assert.equal(result.reasonCode, 'MISSING_REQUIRED_ATTRIBUTE');
});
