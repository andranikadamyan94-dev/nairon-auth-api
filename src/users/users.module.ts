import { Module } from '@nestjs/common';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { AuthPrismaService } from '../prisma.service';

@Module({
  controllers: [UsersController],
  providers: [UsersService, AuthPrismaService],
  exports: [UsersService],
})
export class UsersModule {}