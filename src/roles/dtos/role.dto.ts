import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsArray, IsInt, IsOptional, IsString, Min, MinLength, ValidateNested } from 'class-validator';
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
}
