/**
 * Module: PostgreSQL Integration Regression Tests for BUG-008 (`GET /access-sessions?search=...`)
 * Executes real SQL against PostgreSQL (live TCP or PGlite WASM) to verify searching `access_sessions`
 * with `INET` ip_address columns never throws SQLSTATE 42883 and accurately handles IPv4/IPv6,
 * partial IP prefixes, LIKE metacharacters, status filters, pagination, and department scoping.
 */
import 'reflect-metadata';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { after, before, test } from 'node:test';
import { createEphemeralDatabaseHarness } from '../helpers/postgres-integration-harness.mjs';

const dbHarness = createEphemeralDatabaseHarness('sda_sess_search', { coerceBigIntId: true });

let AccessSessionsService;
let sessionsService;
let deptAlphaId;
let deptBetaId;
let sessionIds;

before(async () => {
  const ready = await dbHarness.setup();
  if (!ready) return;

  ({ AccessSessionsService } =
    await import('../../dist/modules/access-sessions/access-sessions.service.js'));

  const { sql, insertOne, prisma } = dbHarness;

  const deptAlpha = await insertOne(
    "INSERT INTO departments(code,name) VALUES ('SOC_ALPHA','Phòng An ninh Alpha') RETURNING id",
  );
  const deptBeta = await insertOne(
    "INSERT INTO departments(code,name) VALUES ('SOC_BETA','Phòng Vận hành Beta') RETURNING id",
  );
  deptAlphaId = deptAlpha.id;
  deptBetaId = deptBeta.id;

  const alice = await insertOne(
    `INSERT INTO users(username,email,password_hash,full_name,department_id,status)
     VALUES ('alice.soc','alice.soc@corp.local','hash','Nguyễn Minh Anh',$1,'ACTIVE') RETURNING id`,
    [deptAlphaId],
  );
  const bob = await insertOne(
    `INSERT INTO users(username,email,password_hash,full_name,department_id,status)
     VALUES ('bob.ops','bob.ops@corp.local','hash','Trần Quốc Bảo',$1,'ACTIVE') RETURNING id`,
    [deptBetaId],
  );

  const classLevel = await insertOne(
    `INSERT INTO classification_levels(code,name,rank,default_view_days,allow_download,require_watermark,is_active)
     VALUES ('CONFIDENTIAL','Mật',2,7,true,true,true) RETURNING id`,
  );
  const categoryAlpha = await insertOne(
    "INSERT INTO business_categories(code,name,department_id,is_active) VALUES ('CAT_ALPHA','An ninh',$1,true) RETURNING id",
    [deptAlphaId],
  );
  const categoryBeta = await insertOne(
    "INSERT INTO business_categories(code,name,department_id,is_active) VALUES ('CAT_BETA','Vận hành',$1,true) RETURNING id",
    [deptBetaId],
  );
  const clearanceDef = await insertOne(
    "INSERT INTO attribute_definitions(code,name,scope,value_type,is_required,is_active,created_by) VALUES ('CLEARANCE_LEVEL','Clearance','USER','ENUM',true,true,$1) RETURNING id",
    [alice.id],
  );
  const clearanceOpt = await insertOne(
    "INSERT INTO attribute_options(attribute_definition_id,value_code,display_name,numeric_rank,is_active) VALUES ($1,'SECRET','Rank 3',3,true) RETURNING id",
    [clearanceDef.id],
  );
  await sql.query(
    `INSERT INTO user_attribute_assignments(user_id,attribute_definition_id,option_id,valid_from,assigned_by)
     VALUES ($1,$3,$4,now() - interval '1 hour',$1),($2,$3,$4,now() - interval '1 hour',$1)`,
    [alice.id, bob.id, clearanceDef.id, clearanceOpt.id],
  );

  const docAlphaId = randomUUID();
  const docBetaId = randomUUID();
  await sql.query(
    `INSERT INTO documents(id,document_code,title,owner_id,department_id,status,discoverable)
     VALUES
       ($1,'DOC-ALPHA-001','Báo cáo Mật Quý 4',$3,$5,'ACTIVE',true),
       ($2,'DOC-BETA-002','Kế hoạch 100% nội bộ_v2',$4,$6,'ACTIVE',true)`,
    [docAlphaId, docBetaId, alice.id, bob.id, deptAlphaId, deptBetaId],
  );

  await sql.query(
    `INSERT INTO document_classification_history(document_id,classification_level_id,business_category_id,classified_by,effective_from)
     VALUES
       ($1,$3,$4,$6,now() - interval '1 hour'),
       ($2,$3,$5,$7,now() - interval '1 hour')`,
    [docAlphaId, docBetaId, classLevel.id, categoryAlpha.id, categoryBeta.id, alice.id, bob.id],
  );

  const verAlpha = await insertOne(
    `INSERT INTO document_versions(document_id,version_no,storage_key,original_filename,mime_type,file_size_bytes,sha256_hash,encryption_key_ref,scan_status,uploaded_by)
     VALUES ($1,1,'vault/alpha.enc','alpha.pdf','application/pdf',1024,$2,'kms:dek:alpha','CLEAN',$3) RETURNING id`,
    [docAlphaId, 'a'.repeat(64), alice.id],
  );
  const verBeta = await insertOne(
    `INSERT INTO document_versions(document_id,version_no,storage_key,original_filename,mime_type,file_size_bytes,sha256_hash,encryption_key_ref,scan_status,uploaded_by)
     VALUES ($1,2,'vault/beta.enc','beta.pdf','application/pdf',2048,$2,'kms:dek:beta','CLEAN',$3) RETURNING id`,
    [docBetaId, 'b'.repeat(64), bob.id],
  );

  const grantAlphaId = randomUUID();
  const grantBetaId = randomUUID();
  await sql.query(
    `INSERT INTO access_grants(id,document_id,principal_type,principal_user_id,source,valid_from,valid_until,status,granted_by)
     VALUES
       ($1,$3,'USER',$5,'DIRECT',now() - interval '1 hour',now() + interval '7 days','ACTIVE',$5),
       ($2,$4,'USER',$6,'DIRECT',now() - interval '1 hour',now() + interval '7 days','ACTIVE',$6)`,
    [grantAlphaId, grantBetaId, docAlphaId, docBetaId, alice.id, bob.id],
  );

  sessionIds = {
    alphaActiveV4A: randomUUID(),
    alphaActiveV4B: randomUUID(),
    alphaEndedV6: randomUUID(),
    betaActiveV4: randomUUID(),
    betaTerminatedLoopback: randomUUID(),
  };

  await sql.query(
    `INSERT INTO access_sessions(id,access_grant_id,document_version_id,user_id,ip_address,user_agent,status,started_at,last_activity_at,ended_at,terminated_reason)
     VALUES
       ($1,$6,$8,$10,'10.20.30.40','Chrome/130','ACTIVE',now() - interval '5 minutes',now() - interval '1 minute',NULL,NULL),
       ($2,$6,$8,$10,'10.20.30.41','Firefox/132','ACTIVE',now() - interval '4 minutes',now() - interval '1 minute',NULL,NULL),
       ($3,$6,$8,$10,'2001:db8::1','Safari/18','ENDED',now() - interval '3 minutes',now() - interval '2 minutes',now() - interval '2 minutes','Closed by reader'),
       ($4,$7,$9,$11,'192.168.5.10','Edge/130','ACTIVE',now() - interval '2 minutes',now() - interval '30 seconds',NULL,NULL),
       ($5,$7,$9,$11,'::1','Curl/8','TERMINATED',now() - interval '1 minute',now() - interval '10 seconds',now() - interval '10 seconds','SOC terminated')`,
    [
      sessionIds.alphaActiveV4A,
      sessionIds.alphaActiveV4B,
      sessionIds.alphaEndedV6,
      sessionIds.betaActiveV4,
      sessionIds.betaTerminatedLoopback,
      grantAlphaId,
      grantBetaId,
      verAlpha.id,
      verBeta.id,
      alice.id,
      bob.id,
    ],
  );

  sessionsService = new AccessSessionsService(prisma);
});

after(async () => {
  await dbHarness.teardown();
});

test('BUG-008 PostgreSQL integration — search by username, full name, document code/title, and partial/exact IPv4 & IPv6 works without SQLSTATE 42883', async () => {
  // 1. Search by username (previously crashed with SQLSTATE 42883: inet ~~* text)
  const byUsername = await sessionsService.listSessions({ status: 'ALL', search: 'alice.soc' });
  assert.equal(byUsername.data.length, 3);
  assert.equal(byUsername.meta.total, 3);
  assert.equal(byUsername.total, 5);
  assert.equal(byUsername.activeCount, 3);

  // 2. Search by Unicode full_name (case-insensitive)
  const byFullName = await sessionsService.listSessions({ status: 'ALL', search: 'minh anh' });
  assert.equal(byFullName.data.length, 3);
  assert.ok(byFullName.data.every((s) => s.username === 'alice.soc'));

  // 3. Search by document_code & title
  const byDocCode = await sessionsService.listSessions({ status: 'ALL', search: 'doc-alpha-001' });
  assert.equal(byDocCode.data.length, 3);
  const byTitle = await sessionsService.listSessions({ status: 'ALL', search: 'báo cáo mật' });
  assert.equal(byTitle.data.length, 3);

  // 4. Partial IPv4 subnet prefix search via host(ip_address) ILIKE
  const byIpv4Prefix = await sessionsService.listSessions({ status: 'ALL', search: '10.20.30' });
  assert.equal(byIpv4Prefix.data.length, 2);
  assert.deepEqual(byIpv4Prefix.data.map((s) => s.ipAddress).sort(), [
    '10.20.30.40',
    '10.20.30.41',
  ]);

  // 5. Exact IPv4 search
  const byIpv4Exact = await sessionsService.listSessions({ status: 'ALL', search: '192.168.5.10' });
  assert.equal(byIpv4Exact.data.length, 1);
  assert.equal(byIpv4Exact.data[0].id, sessionIds.betaActiveV4);

  // 6. Partial IPv6, exact IPv6, and expanded non-canonical IPv6 equivalence
  const byIpv6Partial = await sessionsService.listSessions({ status: 'ALL', search: '2001:DB8' });
  assert.equal(byIpv6Partial.data.length, 1);
  assert.equal(byIpv6Partial.data[0].id, sessionIds.alphaEndedV6);
  assert.equal(byIpv6Partial.data[0].ipAddress, '2001:db8::1');

  const byIpv6Expanded = await sessionsService.listSessions({
    status: 'ALL',
    search: '2001:0db8:0000:0000:0000:0000:0000:0001',
  });
  assert.equal(byIpv6Expanded.data.length, 1);
  assert.equal(byIpv6Expanded.data[0].id, sessionIds.alphaEndedV6);

  const byLoopbackExpanded = await sessionsService.listSessions({
    status: 'TERMINATED',
    search: '0:0:0:0:0:0:0:1',
  });
  assert.equal(byLoopbackExpanded.data.length, 1);
  assert.equal(byLoopbackExpanded.data[0].id, sessionIds.betaTerminatedLoopback);
  assert.equal(byLoopbackExpanded.data[0].ipAddress, '::1');

  // 7. host(ip_address) strips CIDR netmask so searching "32" or "128" or "/" must NOT false-match IPs
  const noMaskFalseMatch32 = await sessionsService.listSessions({ status: 'ALL', search: '32' });
  assert.equal(noMaskFalseMatch32.data.length, 0);
  const noMaskFalseMatch128 = await sessionsService.listSessions({ status: 'ALL', search: '128' });
  assert.equal(noMaskFalseMatch128.data.length, 0);
  const noMaskFalseMatchSlash = await sessionsService.listSessions({ status: 'ALL', search: '/' });
  assert.equal(noMaskFalseMatchSlash.data.length, 0);
});

test('BUG-008 PostgreSQL integration — escapes LIKE metacharacters, resists SQL injection/NUL bytes, paginates, and isolates departments', async () => {
  // 1. LIKE wildcards are treated literally: "%" only matches title containing literal "%"
  const percentSearch = await sessionsService.listSessions({ status: 'ALL', search: '%' });
  assert.equal(percentSearch.data.length, 2);
  assert.ok(percentSearch.data.every((s) => s.documentCode === 'DOC-BETA-002'));

  const underscoreSearch = await sessionsService.listSessions({ status: 'ALL', search: 'bộ_v2' });
  assert.equal(underscoreSearch.data.length, 2);
  const underscoreNoWildcard = await sessionsService.listSessions({
    status: 'ALL',
    search: 'bộ_v9',
  });
  assert.equal(underscoreNoWildcard.data.length, 0);

  // 2. SQL injection strings, IPv6 zone indices (%eth0 rejected by PG ::inet), and NUL bytes never cause 500 or bypass filters
  const sqliSearch = await sessionsService.listSessions({
    status: 'ALL',
    search: "' OR 1=1 --",
  });
  assert.equal(sqliSearch.data.length, 0);

  const ipv6ZoneSearch = await sessionsService.listSessions({
    status: 'ALL',
    search: 'fe80::1%eth0',
  });
  assert.equal(ipv6ZoneSearch.data.length, 0);

  const nulSearch = await sessionsService.listSessions({
    status: 'ALL',
    search: 'DOC-ALPHA\u0000-001',
  });
  assert.equal(nulSearch.data.length, 3);

  // 3. Status filtering + pagination metadata with search
  const page1 = await sessionsService.listSessions({
    status: 'ACTIVE',
    search: '10.20.30',
    limit: 1,
    page: 1,
  });
  assert.equal(page1.data.length, 1);
  assert.equal(page1.meta.total, 2);
  assert.equal(page1.meta.totalPages, 2);
  assert.equal(page1.meta.hasMore, true);
  assert.equal(page1.total, 5);
  assert.equal(page1.activeCount, 3);

  const page2 = await sessionsService.listSessions({
    status: 'ACTIVE',
    search: '10.20.30',
    limit: 1,
    page: 2,
  });
  assert.equal(page2.data.length, 1);
  assert.equal(page2.meta.hasMore, false);
  assert.notEqual(page2.data[0].id, page1.data[0].id);

  // 4. Department scope isolation with search
  const socActor = {
    userId: 99n,
    sessionId: randomUUID(),
    username: 'scoped.soc',
    departmentId: deptAlphaId,
    roles: ['SECURITY_OFFICER'],
    mfa: true,
  };
  const alphaScopedService = new AccessSessionsService(dbHarness.prisma, undefined, {
    visibleDepartmentIds: async () => [deptAlphaId],
  });

  const crossDeptSearch = await alphaScopedService.listSessions(
    { status: 'ALL', search: '192.168.5.10' },
    socActor,
  );
  assert.equal(crossDeptSearch.data.length, 0);
  assert.equal(crossDeptSearch.meta.total, 0);
  assert.equal(crossDeptSearch.total, 3);
  assert.equal(crossDeptSearch.activeCount, 2);

  const inScopeSearch = await alphaScopedService.listSessions(
    { status: 'ALL', search: '10.20.30' },
    socActor,
  );
  assert.equal(inScopeSearch.data.length, 2);
  assert.equal(inScopeSearch.meta.total, 2);

  // Empty visible department list -> fail-closed 0 results
  const emptyScopeService = new AccessSessionsService(dbHarness.prisma, undefined, {
    visibleDepartmentIds: async () => [],
  });
  const emptyScopeRes = await emptyScopeService.listSessions(
    { status: 'ALL', search: 'alice' },
    socActor,
  );
  assert.equal(emptyScopeRes.data.length, 0);
  assert.equal(emptyScopeRes.meta.total, 0);
  assert.equal(emptyScopeRes.total, 0);
  assert.equal(emptyScopeRes.activeCount, 0);
});
