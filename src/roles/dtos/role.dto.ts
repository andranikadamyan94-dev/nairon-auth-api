import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsArray, IsBoolean, IsInt, IsOptional, IsString, Min, MinLength, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';

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
  @ApiPropertyOptional() @IsOptional() @IsInt() entityId?: number;
}

export class AssignRolesToUserDto {
  @ApiProperty({ type: [Number] }) @IsArray() @IsInt({ each: true }) roleIds: number[];
  @ApiPropertyOptional() @IsOptional() @IsInt() entityId?: number;
}
export class RoleMapEntryDto {
  @ApiPropertyOptional() @IsOptional() @IsInt() entityId?: number;
  @ApiProperty({ type: [Number] }) @IsArray() @IsInt({ each: true }) roleIds: number[];
}

export class AssignRoleMapDto {
  @ApiProperty({ type: [RoleMapEntryDto] })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => RoleMapEntryDto)
  assignments: RoleMapEntryDto[];
  /**
   * Set by HR when the acting user is a super-admin: the map then states the
   * super-admin assignments too, instead of leaving them untouched. HR has
   * authorized the change per entity; this service only keeps the invariants
   * (no self-removal, never the last one).
   */
  @ApiPropertyOptional() @IsOptional() @IsBoolean() manageSuperAdmin?: boolean;
  @ApiPropertyOptional() @IsOptional() @IsInt() actorId?: number;
}
