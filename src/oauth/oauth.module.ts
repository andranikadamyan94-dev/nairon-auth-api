import { Module } from '@nestjs/common';

import { AuthModule } from '../auth/auth.module';
import { PrismaModule } from '../prisma.module';
import { OAuthController } from './oauth.controller';
import { OAuthService } from './oauth.service';
import { TokenExchangeController } from './token-exchange.controller';

/**
 * OAuth as an addition, not a replacement.
 *
 * It imports AuthModule rather than reimplementing any of it: the password
 * check, the deactivation rule and the JWT signing all stay where they were.
 * Removing this module would leave the rest of the service exactly as it was
 * before — which is the property that makes it safe to add.
 */
@Module({
  imports: [PrismaModule, AuthModule],
  controllers: [OAuthController, TokenExchangeController],
  providers: [OAuthService],
  exports: [OAuthService],
})
export class OAuthModule {}
