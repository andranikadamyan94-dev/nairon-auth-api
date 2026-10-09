import { Body, Controller, HttpCode, HttpStatus, Post, UseGuards } from '@nestjs/common';
import { ApiExcludeController } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';

import { Public } from '../auth/decorators/public.decorator';
import { DirectCallOnlyGuard } from '../auth/guards/direct-call.guard';
import { InternalGuard } from '../auth/guards/internal.guard';
import { parseEnsurePermissionsRequest } from './ensure-permissions.contract';
import { EnsurePermissionsResult, EnsurePermissionsService } from './ensure-permissions.service';

/**
 * POST /api/internal/permissions/ensure — ai-api only (2026-10-09).
 *
 * Creates the "Permission" rows for AI skills (use_ai_skills, ai_skill_<slug>)
 * and never grants one: no "RolePermission" row is written. The contract is in
 * ensure-permissions.contract.ts; the answer is 200 {created, existing}.
 *
 * Who can reach it, in order:
 *
 *   1. The gateway cannot. Everything under /api-auth is rewritten to
 *      /api/auth/... (api-gateway proxy.factory.ts), so
 *      /api-auth/api/internal/permissions/ensure lands on
 *      /api/auth/api/internal/permissions/ensure, which does not exist — the
 *      same reason the delegated-token and token-exchange routes live under
 *      /api/internal.
 *   2. DirectCallOnlyGuard: any proxy forwarding header (X-Forwarded-*,
 *      Forwarded, X-Real-IP, Via) is a 403 before the secret is read, so a
 *      public vhost that proxies straight to this container still cannot use
 *      the route, nor guess the secret through it.
 *   3. InternalGuard: `x-internal-secret` must equal INTERNAL_SECRET, compared
 *      in constant time; missing, blank or wrong is a 401, and an unset secret
 *      denies everything.
 *
 * `@Public()` means only "no session token" — the caller is a service.
 */
@ApiExcludeController()
@Public()
@UseGuards(DirectCallOnlyGuard, InternalGuard)
@Controller('internal/permissions')
export class EnsurePermissionsController {
  constructor(private readonly permissions: EnsurePermissionsService) {}

  @Post('ensure')
  @HttpCode(HttpStatus.OK)
  // A skill import or switch-on sends one call; ai-api's single address must
  // not share the app-wide 10/min login bucket.
  @Throttle({ default: { ttl: 60_000, limit: 120 } })
  ensure(@Body() body: unknown): Promise<EnsurePermissionsResult> {
    return this.permissions.ensure(parseEnsurePermissionsRequest(body));
  }
}
