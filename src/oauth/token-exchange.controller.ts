import { Body, Controller, HttpCode, HttpStatus, Post, Res, UseGuards } from '@nestjs/common';
import { ApiExcludeController } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { Response } from 'express';

import { Public } from '../auth/decorators/public.decorator';
import { McpExchangeGuard } from './exchange.guard';
import { OAuthError, OAuthService } from './oauth.service';

/**
 * The only door between the OAuth world and the Nairon world.
 *
 * The MCP resource receives a ChatGPT access token and cannot use it for
 * anything: it is signed with a key no Nairon service knows, and it names an
 * audience no Nairon service accepts. It brings the token here instead and
 * gets back an ordinary short-lived Nairon session JWT for the same person.
 *
 * Mounted under `/api`, because unlike everything in oauth.controller.ts this
 * is not part of any public protocol — it is one service asking another a
 * question, on the same kind of header channel the platform already uses but
 * with a secret of its own. It is deliberately not reachable through the
 * gateway: nothing routes `/api-auth/internal/*`.
 *
 * `@Public()` here means only "no Nairon session token is required", which is
 * the whole point — the caller does not have one yet. McpExchangeGuard is what
 * actually authenticates it, and unlike InternalGuard it fails closed.
 */
@ApiExcludeController()
@Public()
@UseGuards(McpExchangeGuard)
@Controller('internal/oauth')
export class TokenExchangeController {
  constructor(private readonly oauth: OAuthService) {}

  @Post('token-exchange')
  @HttpCode(HttpStatus.OK)
  // Generous, because one MCP session legitimately exchanges once per token
  // lifetime and several sessions may share a host.
  @Throttle({ default: { ttl: 60_000, limit: 240 } })
  async exchange(@Body() body: any, @Res({ passthrough: true }) res: Response) {
    res.setHeader('Cache-Control', 'no-store');
    try {
      const token = String(body?.access_token ?? '');
      if (!token) throw new OAuthError('invalid_request', 'access_token is required', 400);
      return await this.oauth.exchangeForInternalToken(token);
    } catch (error) {
      if (error instanceof OAuthError) {
        res.status(error.status);
        return { error: error.code, error_description: error.message };
      }
      res.status(500);
      return { error: 'server_error', error_description: 'Exchange failed.' };
    }
  }
}
