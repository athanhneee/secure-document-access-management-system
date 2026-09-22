import { SetMetadata } from '@nestjs/common';

export const ALLOW_PRE_MFA_METADATA = Symbol('sda.allowPreMfa');
export const AllowPreMfa = (): MethodDecorator => SetMetadata(ALLOW_PRE_MFA_METADATA, true);
