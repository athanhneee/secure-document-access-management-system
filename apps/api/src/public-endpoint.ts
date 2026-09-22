import { SetMetadata } from '@nestjs/common';

export const PUBLIC_ENDPOINT_METADATA = Symbol('sda.publicEndpoint');

/** Use only for deliberately public routes that expose no protected data. */
export const PublicEndpoint = (): MethodDecorator => SetMetadata(PUBLIC_ENDPOINT_METADATA, true);
