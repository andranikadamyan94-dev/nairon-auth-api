import {
  Body,
  CanActivate,
  Controller,
  ExecutionContext,
  HttpCode,
  HttpStatus,
  Injectable,
  NotFoundException,
  Post,
  Res,
  UseGuards,
} from '@nestjs/common';
import { ApiExcludeController } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { Response } from 'express';

import { Public } from '../auth/decorators/public.decorator';
import { InternalGuard } from '../auth/guards/internal.guard';
import { delegatedTokensEnabled, parseDelegatedTokenRequest } from './delegated-token.contract';
import { DelegatedTokenService } from './delegated-token.service';

/**
 * The rollout switch, checked before anything else — including the secret —
 * so that with AUTH_DELEGATED_TOKENS_ENABLED unset the route is
 * indistinguishable from one that does not exist (same status, same body
 * Nest gives an unknown route).
 */
@Injectable()
export class DelegatedTokensEnabledGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    if (delegatedTokensEnabled()) return true;
    const req = context.switchToHttp().getRequest();
    throw new NotFoundException(`Cannot ${req?.method ?? 'POST'} ${req?.originalUrl ?? req?.url ?? ''}`);
  }
}

/**
 * POST /api/internal/delegated-token — ai-api only.
 *
 * Mounted beside the OAuth token exchange under /api/internal, which the
 * gateway cannot route to: everything under its /api-auth prefix is rewritten
 * to /api/auth/..., so this path has no public address through it. (The V3
 * draft named /api/auth/internal/goal-token, which the gateway WOULD forward.)
 *
 * `@Public()` means only "no session token": the caller is a service, and
 * InternalGuard — INTERNAL_SECRET in `x-internal-secret`, failing closed when
 * the secret is unset or blank, with no fallback value — is what
 * authenticates it.
 */
@ApiExcludeController()
@Public()
@UseGuards(DelegatedTokensEnabledGuard, InternalGuard)
@Controller('internal')
export class DelegatedTokenController {
  constructor(private readonly delegated: DelegatedTokenService) {}

  @Post('delegated-token')
  @HttpCode(HttpStatus.OK)
  // One mint per goal/workflow run, and every run of a busy organisation
  // arrives from ai-api's single address; the app-wide 10/min would throttle it.
  @Throttle({ default: { ttl: 60_000, limit: 240 } })
  async mint(@Body() body: unknown, @Res({ passthrough: true }) res: Response) {
    res.setHeader('Cache-Control', 'no-store');
    return this.delegated.mint(parseDelegatedTokenRequest(body));
  }
}
