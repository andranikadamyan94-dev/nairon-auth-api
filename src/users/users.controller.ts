import { Body, Controller, Delete, Get, HttpCode, HttpStatus, Param, ParseIntPipe, Patch, Post, Query, Request, UseGuards } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { UsersService } from './users.service';
import { CreateUserDto, UpdateUserDto } from './dtos/user.dto';
import { Public } from '../auth/decorators/public.decorator';
import { SkipThrottle } from '@nestjs/throttler';
import { InternalGuard } from '../auth/guards/internal.guard';

/**
 * These routes are service-to-service only — the gateway rewrites everything
 * under its auth prefix to /api/auth/..., so nothing here is reachable from a
 * browser. The global throttler (10 requests a minute, per IP) is aimed at the
 * login endpoints; applied here it counts five back-end services sharing a
 * handful of source addresses against one small bucket, and the resolvers that
 * call these routes turn the resulting 429 into an empty user list. A members
 * page reading "no employees" is the visible end of that.
 */
@SkipThrottle()
@UseGuards(InternalGuard)
@ApiTags('users')
@Controller('users')
export class UsersController {
  constructor(private usersService: UsersService) {}

  @Public()
  @Post()
  @ApiOperation({ summary: 'Create user' })
  create(@Body() dto: CreateUserDto) {
    return this.usersService.createUser(dto);
  }

  @Public()
  @Get()
  @ApiOperation({ summary: 'Get all users' })
  findAll(
    @Query('page') page?: string,
    @Query('limit') limit?: string,
    @Query('includeInactive') includeInactive?: string,
  ) {
    return this.usersService.getAllUsers(
      page ? +page : 1,
      limit ? +limit : 100,
      includeInactive === 'true',
    );
  }

  @Public()
  @Get(':id')
  @ApiOperation({ summary: 'Get user by id' })
  findOne(@Param('id', ParseIntPipe) id: number) {
    return this.usersService.getUserById(id);
  }

  @Public()
  @Patch(':id')
  @ApiOperation({ summary: 'Update user' })
  update(@Param('id', ParseIntPipe) id: number, @Body() dto: UpdateUserDto) {
    return this.usersService.updateUser(id, dto);
  }

  @Public()
  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Delete user' })
  remove(@Param('id', ParseIntPipe) id: number) {
    return this.usersService.deleteUser(id);
  }

  @Public()
  @Post(':id/deactivate')
  @ApiOperation({ summary: 'Deactivate user — keeps the row and all history' })
  deactivate(@Param('id', ParseIntPipe) id: number) {
    return this.usersService.deactivateUser(id);
  }

  @Public()
  @Post(':id/reactivate')
  @ApiOperation({ summary: 'Reactivate a deactivated user' })
  reactivate(@Param('id', ParseIntPipe) id: number) {
    return this.usersService.reactivateUser(id);
  }

  @Post('password-reset')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Set new password (first login)' })
  resetPassword(@Request() req, @Body() body: { newPassword: string }) {
    return this.usersService.resetPassword(req.user.id, body.newPassword);
  }
}