import { Controller, Get, UseGuards } from '@nestjs/common';
import { SkipThrottle } from '@nestjs/throttler';
import { InternalGuard } from '../auth/guards/internal.guard';
import { ApiTags, ApiOperation } from '@nestjs/swagger';
import { Public } from '../auth/decorators/public.decorator';
import { PermissionsService } from './permissions.service';

/**
 * Service-to-service only, like the users routes — see UsersController for why
 * the global login throttle does not belong on these.
 */
@SkipThrottle()
@UseGuards(InternalGuard)
@ApiTags('permissions')
@Public()
@Controller('permissions')
export class PermissionsController {
  constructor(private permissionsService: PermissionsService) {}

  @Get()
  @ApiOperation({ summary: 'Get all permissions' })
  findAll() {
    return this.permissionsService.getAllPermissions();
  }
}