import {
  Body,
  CanActivate,
  Controller,
  ExecutionContext,
  HttpCode,
  HttpStatus,
  Injectable,
  Logger,
  NotFoundException,
  Post,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { ApiExcludeController } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { Response } from 'express';

import { Public } from '../auth/decorators/public.decorator';
import {
  delegatedWriteTokensEnabled,
  goalWriteSecret,
  goalWriteSecretMatches,
  parseDelegatedWriteTokenRequest,
} from './delegated-write-token.contract';
import { DelegatedTokenService } from './delegated-token.service';

/**
 * The rollout switch, before anything else — the secret included — so that
 * with AUTH_DELEGATED_WRITE_TOKENS_ENABLED unset the route is
 * indistinguishable from one that does not exist.
 */
@Injectable()
export class DelegatedWriteTokensEnabledGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    if (delegatedWriteTokensEnabled()) return true;
    const req = context.switchToHttp().getRequest();
    throw new NotFoundException(`Cannot ${req?.method ?? 'POST'} ${req?.originalUrl ?? req?.url ?? ''}`);
  }
}

/**
 * `x-goal-write-secret` against AI_GOALS_WRITE_TOKEN_SECRET, in constant time.
 * Deliberately NOT InternalGuard: the write identity has its own secret, and
 * the guard refuses everything when that secret is unset, blank, short, or the
 * same value as INTERNAL_SECRET (or any other secret this service holds).
 */
@Injectable()
export class GoalWriteSecretGuard implements CanActivate {
  private readonly logger = new Logger(GoalWriteSecretGuard.name);
  private static warned = false;

  canActivate(context: ExecutionContext): boolean {
    if (!goalWriteSecret()) {
      if (!GoalWriteSecretGuard.warned) {
        GoalWriteSecretGuard.warned = true;
        this.logger.error(
          'AI_GOALS_WRITE_TOKEN_SECRET is unset, shorter than 32 characters, or equal to another secret ' +
            '(INTERNAL_SECRET above all) — no delegated write token is issued.',
        );
      }
      throw new UnauthorizedException();
    }
    const req = context.switchToHttp().getRequest();
    if (!goalWriteSecretMatches(req.headers?.['x-goal-write-secret'])) throw new UnauthorizedException();
    return true;
  }
}

/**
 * POST /api/internal/delegated-write-token — ai-api only, V3.4 standing
 * approvals. Under /api/internal like the read token, which the gateway cannot
 * route to (its /api-auth prefix is rewritten to /api/auth/...).
 */
@ApiExcludeController()
@Public()
@UseGuards(DelegatedWriteTokensEnabledGuard, GoalWriteSecretGuard)
@Controller('internal')
export class DelegatedWriteTokenController {
  constructor(private readonly delegated: DelegatedTokenService) {}

  @Post('delegated-write-token')
  @HttpCode(HttpStatus.OK)
  // A standing use is at most a few a week per approval; this is a ceiling, not a budget.
  @Throttle({ default: { ttl: 60_000, limit: 60 } })
  async mint(@Body() body: unknown, @Res({ passthrough: true }) res: Response) {
    res.setHeader('Cache-Control', 'no-store');
    return this.delegated.mintWrite(parseDelegatedWriteTokenRequest(body));
  }
}
