import { Module } from '@nestjs/common';
import { PermissionsController } from './permissions.controller';
import { PermissionsService } from './permissions.service';
import { AuthPrismaService } from '../prisma.service';

@Module({
  controllers: [PermissionsController],
  providers: [PermissionsService, AuthPrismaService],
})
export class PermissionsModule {}