import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsArray, IsInt, IsOptional, IsString, Min, MinLength } from 'class-validator';

export class CreateRoleDto {
  @ApiProperty() @IsString() @MinLength(1) name: string;
  @ApiProperty() @IsInt() @Min(0) level: number;
  @ApiPropertyOptional() @IsOptional() @IsInt() departmentId?: number;
}

export class UpdateRoleDto {
  @ApiPropertyOptional() @IsOptional() @IsString() @MinLength(1) name?: string;
  @ApiPropertyOptional() @IsOptional() @IsInt() @Min(0) level?: number;
  @ApiPropertyOptional() @IsOptional() @IsInt() departmentId?: number;
}

export class AssignPermissionsToRoleDto {
  @ApiProperty({ type: [String] }) @IsArray() @IsString({ each: true }) permissionNames: string[];
}

export class AssignRolesToUserDto {
  @ApiProperty({ type: [Number] }) @IsArray() @IsInt({ each: true }) roleIds: number[];
}