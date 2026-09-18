import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Query,
  Req,
  Res,
} from '@nestjs/common';
import { ApiExcludeController } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { Request, Response } from 'express';

import { Public } from '../auth/decorators/public.decorator';
import { OAuthError, OAuthService } from './oauth.service';
import { errorPage, loginPage, workspacePage } from './views';

/**
 * One already-validated redirect URI, as a CSP source expression.
 *
 * Origin and path only. CSP ignores a query string in a source and a fragment
 * is not allowed in one, so carrying either would at best be noise and at
 * worst make the policy unparseable — and the code and state are appended to
 * this URI later anyway, which CSP matches by path prefix regardless.
 *
 * Anything that is not an absolute http(s) URI yields nothing, so a malformed
 * value can only ever narrow the policy back to `'self'` — never widen it.
 */
export const cspSource = (uri?: string): string => {
  if (!uri) return '';
  try {
    const parsed = new URL(uri);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return '';
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return '';
  }
};

/**
 * The OAuth 2.1 surface ChatGPT talks to.
 *
 * Mounted at the root rather than under `/api`, because these paths are part
 * of the server's published identity: `issuer` plus `/oauth/token` has to be
 * the URL that actually answers, and a prefix nobody expects breaks discovery.
 *
 * Every route is `@Public()` — not because it is unauthenticated, but because
 * the global AuthGuard checks for a *Nairon session* token, which is precisely
 * what a person coming through here does not have yet. Authentication happens
 * inside: by password on /authorize, by PKCE and a one-time code on /token.
 */
@ApiExcludeController()
@Controller()
export class OAuthController {
  constructor(private readonly oauth: OAuthService) {}

  // ─── Discovery ────────────────────────────────────────────────────────────

  @Public()
  @Get('.well-known/oauth-authorization-server')
  metadata() {
    return this.oauth.authorizationServerMetadata();
  }

  /*
   * Some clients look for the OpenID Connect document at this path even when
   * they only want OAuth. Answering with the same metadata costs nothing and
   * saves a failed discovery round.
   */
  @Public()
  @Get('.well-known/openid-configuration')
  openidMetadata() {
    return this.oauth.authorizationServerMetadata();
  }

  // ─── Dynamic client registration ──────────────────────────────────────────

  @Public()
  @Throttle({ default: { ttl: 60_000, limit: 10 } })
  @Post('oauth/register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() body: any, @Res({ passthrough: true }) res: Response) {
    try {
      return await this.oauth.registerClient(body);
    } catch (error) {
      return this.oauthErrorBody(error, res);
    }
  }

  // ─── Authorize ────────────────────────────────────────────────────────────

  @Public()
  @Throttle({ default: { ttl: 60_000, limit: 30 } })
  @Get('oauth/authorize')
  async authorize(@Query() query: any, @Res() res: Response) {
    let request;
    try {
      request = await this.oauth.validateAuthorizeRequest(query);
    } catch (error) {
      // Before the redirect_uri is verified there is nowhere safe to redirect
      // an error to, so it is shown here instead of bounced onward.
      return this.renderError(res, error);
    }
    const client = await this.clientName(request.clientId);
    return this.html(
      res,
      loginPage({ sealed: this.oauth.sealRequest(request), clientName: client, scope: request.scope }),
      HttpStatus.OK,
      request.redirectUri,
    );
  }

  /**
   * Both steps of the flow post here: the password first, then the workspace.
   *
   * They share one handler because they share one piece of state — the sealed
   * request — and splitting them would mean carrying the person's identity
   * between two endpoints, which is a thing worth not doing.
   */
  @Public()
  @Throttle({ default: { ttl: 60_000, limit: 20 } })
  @Post('oauth/authorize')
  async authorizeSubmit(@Body() body: any, @Res() res: Response, @Req() req: Request) {
    let request;
    try {
      request = this.oauth.openRequest(String(body?.request ?? ''));
    } catch (error) {
      return this.renderError(res, error);
    }
    const clientName = await this.clientName(request.clientId);

    // Step two: a workspace was chosen. Who chose it comes from the sealed
    // ticket, never from the form — the browser can edit one and not the other.
    if (body?.consent === '1') {
      return this.finish(res, request, Number(request.userId), Number(body.entityId));
    }

    // Step one: credentials.
    let user;
    try {
      user = await this.oauth.authenticate(String(body?.email ?? ''), String(body?.password ?? ''));
    } catch {
      return this.html(
        res,
        loginPage({
          sealed: String(body.request),
          clientName,
          scope: request.scope,
          error: 'Սխալ էլ. փոստ կամ գաղտնաբառ',
          email: String(body?.email ?? ''),
        }),
        HttpStatus.UNAUTHORIZED,
        request.redirectUri,
      );
    }

    const workspaces = await this.oauth.workspacesFor(user.id);
    if (!workspaces.length) {
      return this.html(
        res,
        errorPage('Ձեր հաշվին կցված աշխատատարածք չկա։ Դիմեք ադմինիստրատորին։'),
        HttpStatus.FORBIDDEN,
      );
    }

    // One workspace is not a choice, so it is not offered as one.
    if (workspaces.length === 1) {
      return this.finish(res, request, user.id, workspaces[0].id);
    }

    // The identity travels inside a freshly sealed ticket rather than a hidden
    // form field, so the browser cannot swap it for someone else's id.
    const sealed = this.oauth.sealRequest({ ...request, ...({ userId: user.id } as any) });
    return this.html(
      res,
      workspacePage({ sealed, clientName, scope: request.scope, workspaces }),
      HttpStatus.OK,
      request.redirectUri,
    );
  }

  private async finish(res: Response, request: any, userId: number, entityId: number) {
    if (!Number.isInteger(userId) || userId <= 0) {
      return this.renderError(res, new OAuthError('invalid_request', 'sign in again'));
    }
    try {
      const { code, state } = await this.oauth.issueCode(request, userId, entityId);
      const target = new URL(request.redirectUri);
      target.searchParams.set('code', code);
      if (state) target.searchParams.set('state', state);
      return res.redirect(302, target.toString());
    } catch (error) {
      return this.renderError(res, error);
    }
  }

  // ─── Token ────────────────────────────────────────────────────────────────

  @Public()
  @Throttle({ default: { ttl: 60_000, limit: 60 } })
  @Post('oauth/token')
  @HttpCode(HttpStatus.OK)
  async token(@Body() body: any, @Res({ passthrough: true }) res: Response) {
    // RFC 6749 §5.1: token responses must never be cached anywhere.
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    try {
      if (body?.grant_type === 'authorization_code') return await this.oauth.exchangeCode(body);
      if (body?.grant_type === 'refresh_token') return await this.oauth.refresh(body);
      throw new OAuthError('unsupported_grant_type', 'unsupported grant_type');
    } catch (error) {
      return this.oauthErrorBody(error, res);
    }
  }

  @Public()
  @Post('oauth/revoke')
  @HttpCode(HttpStatus.OK)
  async revoke(@Body() body: any) {
    await this.oauth.revokeByToken(String(body?.token ?? ''));
    return {};
  }

  // ─── Helpers ──────────────────────────────────────────────────────────────

  private clientName(clientId: string): Promise<string> {
    return this.oauth.clientName(clientId);
  }

  /**
   * Where a form on this page may end up — which is not only where it posts.
   *
   * `form-action` governs the whole navigation a submit starts, redirects
   * included. Signing in posts to this origin, which `'self'` covers, and the
   * server answers 302 to the client's callback — so with `'self'` alone the
   * browser blocks that last hop and the person is left looking at a page that
   * appears to have done nothing. It had in fact done everything: the
   * authorization code was issued and the grant stored. The flow ended in
   * silence, which is the worst way for it to end.
   *
   * So a page that carries a form also names the one callback that form can
   * legitimately reach. Only the URI this request was validated against is
   * used — the value that already had to match the client's registered list
   * byte for byte, or no form would have been rendered at all. Nothing from the
   * query string reaches this header unchecked.
   *
   * The password does not follow the redirect: a 302 answering a POST is
   * fetched as a GET, so the callback receives the code in the URL and no body.
   */
  private html(res: Response, body: string, status = HttpStatus.OK, callback?: string) {
    const formAction = ["'self'", cspSource(callback)].filter(Boolean).join(' ');
    return res
      .status(status)
      .setHeader('Content-Type', 'text/html; charset=utf-8')
      .setHeader('Cache-Control', 'no-store')
      // The page carries no scripts and loads nothing; say so, so a browser
      // enforces it too.
      .setHeader(
        'Content-Security-Policy',
        `default-src 'none'; style-src 'unsafe-inline'; form-action ${formAction}; frame-ancestors 'none'`,
      )
      .send(body);
  }

  private renderError(res: Response, error: unknown) {
    const message =
      error instanceof OAuthError ? error.message : 'Something went wrong. Try again.';
    const status = error instanceof OAuthError ? error.status : 400;
    return this.html(res, errorPage(message), status);
  }

  private oauthErrorBody(error: unknown, res: Response) {
    if (error instanceof OAuthError) {
      res.status(error.status);
      return { error: error.code, error_description: error.message };
    }
    res.status(500);
    return { error: 'server_error', error_description: 'Something went wrong.' };
  }
}
