import { ApiProperty } from '@nestjs/swagger';
import { IsString, MaxLength } from 'class-validator';

export class IssueHandoffDto {
  /** The destination app's origin, e.g. `https://crm.nairon.am`. */
  @ApiProperty() @IsString() @MaxLength(200) target: string;
}

export class ExchangeHandoffDto {
  @ApiProperty() @IsString() @MaxLength(64) code: string;
}
