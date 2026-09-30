import { Module } from '@nestjs/common';

import { DelegatedTokenController, DelegatedTokensEnabledGuard } from './delegated-token.controller';
import { DelegatedTokenService } from './delegated-token.service';

/**
 * Delegated read tokens for AI goals and workflows. Additive: it uses the
 * global JwtModule and Prisma client and changes nothing about login, /me or
 * the OAuth exchange. With AUTH_DELEGATED_TOKENS_ENABLED unset its one route
 * answers 404.
 */
@Module({
  controllers: [DelegatedTokenController],
  providers: [DelegatedTokenService, DelegatedTokensEnabledGuard],
})
export class DelegatedTokenModule {}
