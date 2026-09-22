import { SetMetadata } from '@nestjs/common';

export const REQUIRED_PERMISSION_METADATA = 'sda:required-permission';

export interface RequiredPermission {
  resource: string;
  action: string;
  global?: boolean;
}

export const RequirePermission = (resource: string, action: string, global = false) =>
  SetMetadata(REQUIRED_PERMISSION_METADATA, {
    resource,
    action,
    global,
  } satisfies RequiredPermission);
