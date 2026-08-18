import { Body, Controller, Delete, Get, Param, ParseIntPipe, Post, Put, Query, UseGuards } from '@nestjs/common';
import { SkipThrottle } from '@nestjs/throttler';
import { InternalGuard } from '../auth/guards/internal.guard';
import { ApiTags, ApiOperation } from '@nestjs/swagger';
import { Public } from '../auth/decorators/public.decorator';
import { RolesService } from './roles.service';
import { AssignPermissionsToRoleDto, AssignRolesToUserDto, AssignRoleMapDto, CreateRoleDto, UpdateRoleDto } from './dtos/role.dto';

/**
 * Service-to-service only, like the users routes — see UsersController for why
 * the global login throttle does not belong on these.
 */
@SkipThrottle()
@UseGuards(InternalGuard)
@ApiTags('roles')
@Public()
@Controller('roles')
export class RolesController {
  constructor(private rolesService: RolesService) {}

  @Post()
  @ApiOperation({ summary: 'Create role' })
  create(@Body() dto: CreateRoleDto) {
    return this.rolesService.createRole(dto.name, dto.level, dto.departmentId);
  }

  @Get()
  @ApiOperation({ summary: 'Get all roles' })
  findAll(@Query('departmentId') departmentId?: string) {
    return this.rolesService.getAllRoles(departmentId ? Number(departmentId) : undefined);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get role by id' })
  findOne(@Param('id', ParseIntPipe) id: number, @Query('entityId') entityId?: string) {
    return this.rolesService.getRoleById(id, entityId !== undefined ? Number(entityId) : undefined);
  }

  @Put(':id')
  @ApiOperation({ summary: 'Update role' })
  update(@Param('id', ParseIntPipe) id: number, @Body() dto: UpdateRoleDto) {
    return this.rolesService.updateRole(id, dto);
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Delete role' })
  remove(@Param('id', ParseIntPipe) id: number) {
    return this.rolesService.deleteRole(id);
  }

  @Post(':id/assign-permissions')
  @ApiOperation({ summary: 'Assign permissions to role' })
  assignPermissions(@Param('id', ParseIntPipe) id: number, @Body() dto: AssignPermissionsToRoleDto) {
    return this.rolesService.assignPermissionsToRole(id, dto.permissionNames, dto.entityId ?? 0);
  }

  @Post('assign-to-user/:userId')
  @ApiOperation({ summary: 'Assign roles to user' })
  assignToUser(@Param('userId', ParseIntPipe) userId: number, @Body() dto: AssignRolesToUserDto) {
    return this.rolesService.assignRolesToUser(userId, dto.roleIds, dto.entityId ?? 0);
  }

  @Post('assign-map/:userId')
  @ApiOperation({ summary: 'Replace the user’s complete per-entity role map' })
  assignMap(@Param('userId', ParseIntPipe) userId: number, @Body() dto: AssignRoleMapDto) {
    return this.rolesService.assignRoleMapToUser(userId, dto.assignments ?? []);
  }
}