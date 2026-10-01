import { Module } from '@nestjs/common';

import { AuthModule } from '../auth/auth.module';
import { HandoffCodesEnabledGuard, HandoffController } from './handoff.controller';
import { HandoffService } from './handoff.service';

/**
 * One-time cross-app sign-in codes (SSO handoff hardening, 2026-10-01).
 * Additive: login, /me, logout and OAuth are untouched. With
 * AUTH_HANDOFF_CODES_ENABLED unset both routes answer 404.
 */
@Module({
  imports: [AuthModule],
  controllers: [HandoffController],
  providers: [HandoffService, HandoffCodesEnabledGuard],
})
export class HandoffModule {}
