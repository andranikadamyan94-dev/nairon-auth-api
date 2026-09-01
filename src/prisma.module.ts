import { Global, Module } from '@nestjs/common';
import { AuthPrismaService } from './prisma.service';

/**
 * One PrismaClient for the whole app. AuthPrismaService used to be listed in
 * five modules' providers, which in Nest means five separate instances — five
 * connection pools where one suffices (the 2026-09-01 P2037 saturation showed
 * auth holding ~4x its share). Global + exported: inject it anywhere, never
 * add it to another providers array.
 */
@Global()
@Module({
  providers: [AuthPrismaService],
  exports: [AuthPrismaService],
})
export class PrismaModule {}
