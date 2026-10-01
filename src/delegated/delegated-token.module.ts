import { Module } from '@nestjs/common';

import { DelegatedTokenController, DelegatedTokensEnabledGuard } from './delegated-token.controller';
import { DelegatedTokenService } from './delegated-token.service';
import {
  DelegatedWriteTokenController,
  DelegatedWriteTokensEnabledGuard,
  GoalWriteSecretGuard,
} from './delegated-write-token.controller';

/**
 * Delegated read tokens for AI goals and workflows. Additive: it uses the
 * global JwtModule and Prisma client and changes nothing about login, /me or
 * the OAuth exchange. With AUTH_DELEGATED_TOKENS_ENABLED unset the read route
 * answers 404; with AUTH_DELEGATED_WRITE_TOKENS_ENABLED unset the V3.4 write
 * route (delegated-write-token) answers 404. The two flags are independent.
 */
@Module({
  controllers: [DelegatedTokenController, DelegatedWriteTokenController],
  providers: [DelegatedTokenService, DelegatedTokensEnabledGuard, DelegatedWriteTokensEnabledGuard, GoalWriteSecretGuard],
})
export class DelegatedTokenModule {}
