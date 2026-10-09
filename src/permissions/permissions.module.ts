import { Module } from '@nestjs/common';
import { PermissionsController } from './permissions.controller';
import { PermissionsService } from './permissions.service';
import { EnsurePermissionsController } from './ensure-permissions.controller';
import { EnsurePermissionsService } from './ensure-permissions.service';

@Module({
  controllers: [PermissionsController, EnsurePermissionsController],
  providers: [PermissionsService, EnsurePermissionsService],
})
export class PermissionsModule {}
