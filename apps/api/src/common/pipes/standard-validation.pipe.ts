import { BadRequestException, Injectable, type PipeTransform } from '@nestjs/common';
import type { StandardSchemaV1 } from '@standard-schema/spec';
import { AppErrorCode } from '@sda/contracts';

@Injectable()
export class StandardValidationPipe implements PipeTransform {
  constructor(private readonly schema?: StandardSchemaV1) {}

  async transform(
    value: unknown,
    metadata?: { metatype?: unknown; schema?: StandardSchemaV1 },
  ): Promise<unknown> {
    const targetSchema = this.schema ?? metadata?.schema;
    if (!targetSchema) {
      return value;
    }

    const standard = targetSchema['~standard'];
    if (!standard) {
      return value;
    }

    const result = await standard.validate(value);
    if (result.issues !== undefined) {
      const details = result.issues.map((issue) => ({
        path: issue.path ? issue.path.map(String).join('.') : '',
        message: issue.message,
      }));
      throw new BadRequestException({
        errorCode: AppErrorCode.VALIDATION_FAILED,
        message: 'Validation failed for one or more fields.',
        details,
      });
    }

    return result.value;
  }
}
