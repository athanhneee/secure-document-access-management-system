import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { AuthGuard } from './modules/auth/auth.guard.js';
import { AuthModule } from './modules/auth/auth.module.js';
import { AppConfigModule } from './config/config.module.js';
import { SystemHealthModule } from './modules/system-health/system-health.module.js';
import { AuthorizationGuard } from './modules/rbac/authorization.guard.js';
import { RbacModule } from './modules/rbac/rbac.module.js';
import { UsersModule } from './modules/users/users.module.js';
import { DepartmentsModule } from './modules/departments/departments.module.js';
import { AbacModule } from './modules/abac/abac.module.js';
import { DocumentsModule } from './modules/documents/documents.module.js';
import { AccessGrantsModule } from './modules/access-grants/access-grants.module.js';
import { AccessSessionsModule } from './modules/access-sessions/access-sessions.module.js';
import { WatermarksModule } from './modules/watermarks/watermarks.module.js';
import { AuditModule } from './modules/audit/audit.module.js';
import { SecurityOperationsModule } from './modules/security-operations/security-operations.module.js';
import { ReportsModule } from './modules/reports/reports.module.js';
import { NotificationsModule } from './modules/notifications/notifications.module.js';

@Module({
  imports: [
    AppConfigModule,
    AuthModule,
    RbacModule,
    AbacModule,
    UsersModule,
    DepartmentsModule,
    DocumentsModule,
    AccessGrantsModule,
    AccessSessionsModule,
    WatermarksModule,
    AuditModule,
    SecurityOperationsModule,
    ReportsModule,
    NotificationsModule,
    SystemHealthModule,
  ],
  providers: [
    { provide: APP_GUARD, useClass: AuthGuard },
    { provide: APP_GUARD, useClass: AuthorizationGuard },
  ],
})
export class AppModule {}
