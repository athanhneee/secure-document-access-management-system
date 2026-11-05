import { SetMetadata } from '@nestjs/common';

export const REQUIRED_PERMISSION_METADATA = 'sda:required-permission';
export const REQUIRED_ANY_PERMISSION_METADATA = 'sda:required-any-permission';
export const ALLOW_AUTHENTICATED_SELF_METADATA = 'sda:allow-authenticated-self';

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

export const RequireAnyPermission = (permissions: readonly RequiredPermission[]) =>
  SetMetadata(REQUIRED_ANY_PERMISSION_METADATA, [...permissions]);

export const AllowAuthenticatedSelf = () => SetMetadata(ALLOW_AUTHENTICATED_SELF_METADATA, true);
