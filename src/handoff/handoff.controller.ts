import {
  BadRequestException,
  Body,
  CanActivate,
  Controller,
  ExecutionContext,
  ForbiddenException,
  HttpCode,
  HttpStatus,
  Injectable,
  NotFoundException,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { Request, Response } from 'express';

import { Public } from '../auth/decorators/public.decorator';
import { COOKIE_NAME, clearStaleParentCookie, cookieOptions } from '../auth/session-cookie';
import { M } from '../constants/messages';
import { handoffCodesEnabled, isSessionPayload, normalizeTargetOrigin } from './handoff.contract';
import { ExchangeHandoffDto, IssueHandoffDto } from './handoff.dto';
import { HandoffService } from './handoff.service';

/**
 * The rollout switch, checked before the body is looked at, so with
 * AUTH_HANDOFF_CODES_ENABLED unset both routes are indistinguishable from
 * routes that do not exist — and every client falls back to the old fragment.
 */
@Injectable()
export class HandoffCodesEnabledGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    if (handoffCodesEnabled()) return true;
    const req = context.switchToHttp().getRequest();
    throw new NotFoundException(`Cannot ${req?.method ?? 'POST'} ${req?.originalUrl ?? req?.url ?? ''}`);
  }
}

/**
 * POST /api/auth/handoff           — signed-in app asks for a code for another app's origin.
 * POST /api/auth/handoff/exchange  — the destination trades the code for its session.
 *
 * Through the gateway these are /api-auth/auth/handoff and
 * /api-auth/auth/handoff/exchange; the exchange must be listed among the
 * gateway's public paths (it carries no session — that is the point).
 */
@ApiTags('auth')
@UseGuards(HandoffCodesEnabledGuard)
@Controller('auth/handoff')
export class HandoffController {
  constructor(private readonly handoff: HandoffService) {}

  @Post()
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Issue a one-time cross-app sign-in code' })
  // Per client IP, and an office sits behind one: generous, as for /me. The
  // code is 256 bits, so the limit is about load, not guessing.
  @Throttle({ default: { ttl: 60_000, limit: 120 } })
  async issue(@Req() req: Request, @Body() dto: IssueHandoffDto) {
    // The session guard has already verified the token; only a plain sign-in
    // token may be traded (see isSessionPayload).
    const payload = (req as any).user;
    if (!isSessionPayload(payload)) throw new ForbiddenException(M.auth.handoffSessionOnly);
    const target = normalizeTargetOrigin(dto.target);
    if (!target) throw new BadRequestException(M.auth.handoffTarget);
    return this.handoff.issue(payload.id, target);
  }

  @Public()
  @Post('exchange')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Exchange a one-time cross-app sign-in code for a session' })
  @Throttle({ default: { ttl: 60_000, limit: 120 } })
  async exchange(
    @Body() dto: ExchangeHandoffDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    // The browser sets Origin on this cross-origin POST and page script cannot
    // change it; it must be the origin the code was issued for.
    const origin = typeof req.headers.origin === 'string' ? req.headers.origin : undefined;
    const session = await this.handoff.exchange(dto.code, origin);
    // The same cookie login sets, so /auth/me, logout and the cross-app
    // session check behave exactly as after a password sign-in.
    clearStaleParentCookie(req, res);
    res.cookie(COOKIE_NAME, session.access_token, cookieOptions(req));
    res.setHeader('Cache-Control', 'no-store');
    return session;
  }
}
