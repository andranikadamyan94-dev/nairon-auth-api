import { Module } from '@nestjs/common';
import { RolesController } from './roles.controller';
import { RolesService } from './roles.service';
import { AuthPrismaService } from '../prisma.service';

@Module({
  controllers: [RolesController],
  providers: [RolesService, AuthPrismaService],
  exports: [RolesService],
})
export class RolesModule {}