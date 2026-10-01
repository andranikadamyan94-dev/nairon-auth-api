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
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { ApiExcludeController } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { Request, Response } from 'express';

import { Public } from '../auth/decorators/public.decorator';
import { InternalGuard } from '../auth/guards/internal.guard';
import {
  delegatedTokensEnabled,
  delegatedWorkflowTokensEnabled,
  parseDelegatedTokenRequest,
} from './delegated-token.contract';
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
    throw routeNotFound(context.switchToHttp().getRequest());
  }
}

/** The 404 Nest gives a route that does not exist, byte for byte. */
function routeNotFound(req: { method?: string; originalUrl?: string; url?: string } | undefined): NotFoundException {
  return new NotFoundException(`Cannot ${req?.method ?? 'POST'} ${req?.originalUrl ?? req?.url ?? ''}`);
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
 *
 * Two forms (delegated-token.contract.ts has the full contract):
 *   { userId, entityId, goalId, runId?, scope: "read" }            → act.sub ai-goal
 *   { userId, entityId, workflowId, workflowVersionId,
 *     role?: "author" | "approver", runId?, scope: "read" }        → act.sub ai-workflow
 *
 * The workflow form has its own switch, AUTH_DELEGATED_WORKFLOW_TOKENS_ENABLED,
 * on top of the read flag. Which form a request is can only be known once the
 * body parses, so that switch is checked here, after the guards (flag, then
 * secret) and the parse: off, a workflow request gets the very 404 an unknown
 * route gets. Goal requests never consult it.
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
  async mint(@Body() body: unknown, @Req() req: Request, @Res({ passthrough: true }) res: Response) {
    res.setHeader('Cache-Control', 'no-store');
    const parsed = parseDelegatedTokenRequest(body);
    if (parsed.actor === 'ai-workflow' && !delegatedWorkflowTokensEnabled()) {
      // An unknown route carries no Cache-Control of ours; neither does this.
      res.removeHeader('Cache-Control');
      throw routeNotFound(req);
    }
    return this.delegated.mint(parsed);
  }
}
