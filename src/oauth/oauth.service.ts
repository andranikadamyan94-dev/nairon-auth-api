import { BadRequestException, Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

import { AuthPrismaService } from '../prisma.service';
import { AuthService } from '../auth/auth.service';
import { jwtConstants } from '../auth/constants';
import { OAuthConfig, SUPPORTED_SCOPES, OAUTH_SCOPES, oauthConfig } from './oauth.config';
import { randomToken, sha256, verifyPkceS256 } from './oauth.crypto';
import { checkRedirectUri, matchesRegistered } from './redirect-policy';

/** An OAuth error that must reach the client as a spec-shaped body. */
export class OAuthError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status = 400,
  ) {
    super(message);
    this.name = 'OAuthError';
  }
}

export interface AuthorizeRequest {
  clientId: string;
  redirectUri: string;
  scope: string;
  state?: string;
  codeChallenge: string;
  resource?: string;
}

export interface WorkspaceChoice {
  id: number;
  name: string;
}

@Injectable()
export class OAuthService {
  private readonly logger = new Logger(OAuthService.name);
  readonly config: OAuthConfig;

  constructor(
    private readonly prisma: AuthPrismaService,
    private readonly jwt: JwtService,
    private readonly auth: AuthService,
  ) {
    this.config = oauthConfig();
  }

  // ─── Discovery ────────────────────────────────────────────────────────────

  authorizationServerMetadata() {
    const base = this.config.publicBaseUrl;
    return {
      issuer: this.config.issuer,
      authorization_endpoint: `${base}/oauth/authorize`,
      token_endpoint: `${base}/oauth/token`,
      registration_endpoint: `${base}/oauth/register`,
      revocation_endpoint: `${base}/oauth/revoke`,
      scopes_supported: SUPPORTED_SCOPES,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      // No `plain`: it is PKCE in name only.
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none'],
      // RFC 8707. The MCP resource is named in the request and bound into the
      // token, so a token minted for this resource is useless at another.
      resource_indicators_supported: true,
      service_documentation: `${base}/oauth/authorize`,
    };
  }

  /** RFC 9728, served by the resource itself but described here. */
  protectedResourceMetadata() {
    return {
      resource: this.config.mcpResource,
      authorization_servers: [this.config.issuer],
      scopes_supported: SUPPORTED_SCOPES,
      bearer_methods_supported: ['header'],
    };
  }

  // ─── Dynamic client registration (RFC 7591) ───────────────────────────────

  async registerClient(body: any) {
    const redirectUris: string[] = Array.isArray(body?.redirect_uris) ? body.redirect_uris : [];
    if (!redirectUris.length) {
      throw new OAuthError('invalid_redirect_uri', 'redirect_uris is required');
    }
    for (const uri of redirectUris) {
      const check = checkRedirectUri(uri, this.config);
      if (!check.ok) throw new OAuthError('invalid_redirect_uri', check.reason!);
    }

    const method = body?.token_endpoint_auth_method ?? 'none';
    if (method !== 'none') {
      // Public client only: a client that cannot keep a secret must not be
      // issued one, and PKCE is what authenticates the exchange instead.
      throw new OAuthError(
        'invalid_client_metadata',
        'only token_endpoint_auth_method=none is supported',
      );
    }

    const requested: string[] = (body?.scope ?? SUPPORTED_SCOPES.join(' ')).split(/\s+/);
    const unknown = requested.filter((s: string) => s && !SUPPORTED_SCOPES.includes(s));
    if (unknown.length) {
      throw new OAuthError('invalid_client_metadata', `unsupported scope: ${unknown.join(', ')}`);
    }

    const clientId = `nairon-mcp-${randomToken(12)}`;
    const registrationToken = randomToken();

    await this.prisma.oAuthClient.create({
      data: {
        id: clientId,
        clientName: String(body?.client_name ?? 'MCP client').slice(0, 200),
        redirectUris,
        grantTypes: ['authorization_code', 'refresh_token'],
        scopes: requested.filter(Boolean),
        tokenEndpointAuthMethod: 'none',
        registrationTokenHash: sha256(registrationToken),
      },
    });

    this.logger.log(`registered OAuth client ${clientId} (${redirectUris.length} redirect URIs)`);

    return {
      client_id: clientId,
      client_name: body?.client_name ?? 'MCP client',
      redirect_uris: redirectUris,
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
      scope: requested.filter(Boolean).join(' '),
      registration_access_token: registrationToken,
      registration_client_uri: `${this.config.publicBaseUrl}/oauth/register/${clientId}`,
      client_id_issued_at: Math.floor(Date.now() / 1000),
    };
  }

  // ─── Authorize ────────────────────────────────────────────────────────────

  /**
   * Validate an incoming authorize request before any credential is asked for.
   *
   * Order is the point. `redirect_uri` is checked against the registration
   * first, because every later error is reported *to* that URI; an error
   * redirected to an unverified address is an open redirector.
   */
  async validateAuthorizeRequest(query: any): Promise<AuthorizeRequest> {
    const clientId = String(query.client_id ?? '');
    const redirectUri = String(query.redirect_uri ?? '');

    const client = await this.prisma.oAuthClient.findUnique({ where: { id: clientId } });
    if (!client || client.disabledAt) {
      throw new OAuthError('invalid_client', 'unknown client_id');
    }
    if (!matchesRegistered(redirectUri, client.redirectUris)) {
      throw new OAuthError('invalid_request', 'redirect_uri does not match a registered URI');
    }

    if (query.response_type !== 'code') {
      throw new OAuthError('unsupported_response_type', 'only response_type=code is supported');
    }
    if (query.code_challenge_method !== 'S256') {
      throw new OAuthError('invalid_request', 'code_challenge_method must be S256');
    }
    const codeChallenge = String(query.code_challenge ?? '');
    if (!/^[A-Za-z0-9\-._~]{43}$/.test(codeChallenge)) {
      throw new OAuthError('invalid_request', 'code_challenge is missing or malformed');
    }

    const scope = String(query.scope ?? OAUTH_SCOPES.MCP);
    const requested = scope.split(/\s+/).filter(Boolean);
    const unknown = requested.filter((s) => !SUPPORTED_SCOPES.includes(s));
    if (unknown.length) throw new OAuthError('invalid_scope', `unsupported scope: ${unknown[0]}`);
    const notGranted = requested.filter((s) => !client.scopes.includes(s));
    if (notGranted.length) {
      throw new OAuthError('invalid_scope', `client may not request ${notGranted[0]}`);
    }

    // RFC 8707. If the client names a resource it must be ours, so a token
    // cannot be minted here for somewhere else.
    const resource = query.resource ? String(query.resource) : undefined;
    if (resource && resource.replace(/\/+$/, '') !== this.config.mcpResource) {
      throw new OAuthError('invalid_target', 'unknown resource');
    }

    return {
      clientId,
      redirectUri,
      scope: requested.join(' '),
      state: query.state ? String(query.state) : undefined,
      codeChallenge,
      resource,
    };
  }

  /**
   * Freeze a validated request into a short-lived signed blob.
   *
   * The login form posts this back rather than the original parameters, so the
   * pieces that were checked cannot be swapped between the check and the
   * consent — and no server-side session store is needed to hold them.
   */
  sealRequest(request: AuthorizeRequest & { userId?: number }): string {
    return this.jwt.sign(
      { typ: 'oauth_authz_request', ...request },
      { secret: this.config.tokenSecret, expiresIn: this.config.authzRequestTtlSec },
    );
  }

  openRequest(sealed: string): AuthorizeRequest & { userId?: number } {
    let payload: any;
    try {
      payload = this.jwt.verify(sealed, { secret: this.config.tokenSecret });
    } catch {
      throw new OAuthError('invalid_request', 'this sign-in attempt expired; start again');
    }
    if (payload?.typ !== 'oauth_authz_request') {
      throw new OAuthError('invalid_request', 'malformed request');
    }
    return {
      clientId: payload.clientId,
      redirectUri: payload.redirectUri,
      scope: payload.scope,
      state: payload.state,
      codeChallenge: payload.codeChallenge,
      resource: payload.resource,
      // Present only on the ticket re-sealed after a successful password
      // check, which is why the workspace step can trust it.
      userId: payload.userId,
    };
  }

  /** The name shown on the consent screen. A label, not a decision. */
  async clientName(clientId: string): Promise<string> {
    const client = await this.prisma.oAuthClient.findUnique({
      where: { id: clientId },
      select: { clientName: true },
    });
    return client?.clientName ?? 'MCP client';
  }

  /** The person's own credentials, checked by the code that already does it. */
  async authenticate(email: string, password: string) {
    // AuthService.signIn owns the bcrypt comparison, the deactivation rule and
    // the deliberately vague failure message. Re-implementing any of that here
    // would create a second front door with its own bugs.
    const { user } = await this.auth.signIn(email, password);
    return user as { id: number; email: string; firstName: string; lastName: string };
  }

  // ─── Workspaces ───────────────────────────────────────────────────────────

  /**
   * The workspaces this person may act in — asked of Nairon, not recomputed.
   *
   * The first version built this from UserRole.entityId, and that is simply
   * not how Nairon decides which workspaces someone may enter.
   * hr-api's entity.service.findAll resolves it from the org tree and
   * department memberships, with a scoped super-admin allowance on top; role
   * scoping does not appear in it at all. Two models would have drifted
   * immediately, and the consent screen would have offered workspaces the
   * person's own entity switcher never shows them.
   *
   * So this calls the same endpoint the switcher calls, as the person signing
   * in. The token minted for that call lasts a minute and never leaves this
   * method. No X-Entity-ID is sent: hr-api checks membership only once an
   * entity is selected, and here nothing is selected yet — that is the
   * question being asked.
   */
  async workspacesFor(userId: number): Promise<WorkspaceChoice[]> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, email: true, deactivatedAt: true },
    });
    if (!user || user.deactivatedAt) return [];

    if (!this.config.hrApiUrl) {
      this.logger.error(
        'HR_API_URL is not set — workspaces cannot be resolved, so none are offered.',
      );
      return [];
    }

    const token = this.jwt.sign(
      { id: user.id, email: user.email, src: 'oauth-consent' },
      { secret: jwtConstants.secret, expiresIn: 60 },
    );

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);
      const response = await fetch(`${this.config.hrApiUrl}/api/entities`, {
        headers: { authorization: `Bearer ${token}` },
        signal: controller.signal,
      }).finally(() => clearTimeout(timer));

      if (!response.ok) {
        this.logger.error(`hr-api refused the entity list (HTTP ${response.status})`);
        return [];
      }
      const rows = (await response.json()) as { id: number; name?: string }[];
      if (!Array.isArray(rows)) return [];
      return rows
        .filter((r) => Number.isInteger(r?.id) && r.id > 0)
        .map((r) => ({ id: r.id, name: r.name || `Workspace ${r.id}` }));
    } catch (error) {
      /*
       * Fail closed. An empty list stops the sign-in with "no workspace"; a
       * guessed list would hand someone a workspace they may not belong to,
       * which is the exact bug this method was rewritten to remove.
       */
      this.logger.error(`could not resolve workspaces: ${(error as Error).message}`);
      return [];
    }
  }

  /** Refuse an entity the person has no role in, whatever the form said. */
  async assertWorkspaceAllowed(userId: number, entityId: number): Promise<void> {
    const allowed = await this.workspacesFor(userId);
    if (!allowed.some((w) => w.id === entityId)) {
      throw new OAuthError('access_denied', 'you do not have access to that workspace', 403);
    }
  }

  // ─── Code issuance ────────────────────────────────────────────────────────

  async issueCode(
    request: AuthorizeRequest,
    userId: number,
    entityId: number,
  ): Promise<{ code: string; state?: string }> {
    await this.assertWorkspaceAllowed(userId, entityId);

    const grant = await this.prisma.oAuthGrant.create({
      data: {
        id: randomToken(16),
        userId,
        clientId: request.clientId,
        entityId,
        scope: request.scope,
      },
    });

    const code = randomToken();
    await this.prisma.oAuthAuthorizationCode.create({
      data: {
        codeHash: sha256(code),
        grantId: grant.id,
        clientId: request.clientId,
        redirectUri: request.redirectUri,
        codeChallenge: request.codeChallenge,
        codeChallengeMethod: 'S256',
        resource: request.resource ?? this.config.mcpResource,
        expiresAt: new Date(Date.now() + this.config.codeTtlSec * 1000),
      },
    });

    return { code, state: request.state };
  }

  // ─── Token endpoint ───────────────────────────────────────────────────────

  async exchangeCode(body: any) {
    const code = String(body.code ?? '');
    const clientId = String(body.client_id ?? '');
    const redirectUri = String(body.redirect_uri ?? '');
    const verifier = String(body.code_verifier ?? '');

    const record = await this.prisma.oAuthAuthorizationCode.findUnique({
      where: { codeHash: sha256(code) },
      include: { grant: true },
    });
    if (!record) throw new OAuthError('invalid_grant', 'unknown or already used code');

    // Replay of a spent code means the code leaked. The grant goes with it:
    // whoever holds the copy must not keep what it bought.
    if (record.consumedAt) {
      await this.revokeGrant(record.grantId, 'authorization code replayed');
      throw new OAuthError('invalid_grant', 'code has already been used');
    }
    if (record.expiresAt.getTime() < Date.now()) {
      throw new OAuthError('invalid_grant', 'code has expired');
    }
    if (record.clientId !== clientId) {
      throw new OAuthError('invalid_grant', 'code was issued to a different client');
    }
    if (record.redirectUri !== redirectUri) {
      throw new OAuthError('invalid_grant', 'redirect_uri does not match the one used to sign in');
    }
    if (!verifyPkceS256(verifier, record.codeChallenge)) {
      throw new OAuthError('invalid_grant', 'code_verifier does not match code_challenge');
    }
    if (record.grant.revokedAt) throw new OAuthError('invalid_grant', 'this access was revoked');

    await this.prisma.oAuthAuthorizationCode.update({
      where: { codeHash: record.codeHash },
      data: { consumedAt: new Date() },
    });

    return this.issueTokens(record.grantId);
  }

  async refresh(body: any) {
    const presented = String(body.refresh_token ?? '');
    const clientId = String(body.client_id ?? '');
    const record = await this.prisma.oAuthRefreshToken.findUnique({
      where: { tokenHash: sha256(presented) },
      include: { grant: true },
    });
    if (!record) throw new OAuthError('invalid_grant', 'unknown refresh token');

    /*
     * A refresh token presented twice is the classic signal of theft: one of
     * the two holders is not the client, and there is no way to tell which. So
     * the whole chain dies rather than the request simply failing — the
     * legitimate client re-authorizes, the thief gets nothing.
     */
    if (record.usedAt) {
      await this.revokeGrant(record.grantId, 'refresh token reused');
      throw new OAuthError('invalid_grant', 'refresh token was already used');
    }
    if (record.expiresAt.getTime() < Date.now()) {
      throw new OAuthError('invalid_grant', 'refresh token has expired');
    }
    if (record.grant.clientId !== clientId) {
      throw new OAuthError('invalid_grant', 'refresh token belongs to another client');
    }
    if (record.grant.revokedAt) throw new OAuthError('invalid_grant', 'this access was revoked');

    const issued = await this.issueTokens(record.grantId);
    await this.prisma.oAuthRefreshToken.update({
      where: { tokenHash: record.tokenHash },
      data: { usedAt: new Date(), replacedBy: sha256(issued.refresh_token) },
    });
    return issued;
  }

  private async issueTokens(grantId: string) {
    const grant = await this.prisma.oAuthGrant.findUnique({
      where: { id: grantId },
      include: { user: { select: { id: true, email: true, deactivatedAt: true } } },
    });
    if (!grant) throw new OAuthError('invalid_grant', 'unknown grant');
    if (grant.user.deactivatedAt) throw new OAuthError('invalid_grant', 'this account is inactive');

    const accessToken = this.jwt.sign(
      {
        typ: 'mcp_access',
        sub: String(grant.userId),
        gid: grant.id,
        scope: grant.scope,
        // The entity is carried for traceability only. Every consumer reads it
        // back from the grant row, so a tampered copy of this claim buys
        // nothing — and the token is signed anyway.
        ent: grant.entityId,
      },
      {
        secret: this.config.tokenSecret,
        expiresIn: this.config.accessTokenTtlSec,
        issuer: this.config.issuer,
        audience: this.config.mcpResource,
      },
    );

    const result: Record<string, unknown> = {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: this.config.accessTokenTtlSec,
      scope: grant.scope,
    };

    if (grant.scope.split(/\s+/).includes(OAUTH_SCOPES.OFFLINE)) {
      const refreshToken = randomToken();
      await this.prisma.oAuthRefreshToken.create({
        data: {
          tokenHash: sha256(refreshToken),
          grantId: grant.id,
          expiresAt: new Date(Date.now() + this.config.refreshTokenTtlSec * 1000),
        },
      });
      result.refresh_token = refreshToken;
    }

    await this.prisma.oAuthGrant.update({
      where: { id: grant.id },
      data: { lastUsedAt: new Date() },
    });

    return result as {
      access_token: string;
      token_type: string;
      expires_in: number;
      scope: string;
      refresh_token: string;
    };
  }

  async revokeGrant(grantId: string, reason: string): Promise<void> {
    await this.prisma.oAuthGrant.updateMany({
      where: { id: grantId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    this.logger.warn(`revoked OAuth grant ${grantId}: ${reason}`);
  }

  async revokeByToken(token: string): Promise<void> {
    const refresh = await this.prisma.oAuthRefreshToken.findUnique({
      where: { tokenHash: sha256(token) },
    });
    if (refresh) return this.revokeGrant(refresh.grantId, 'revocation requested');
    try {
      const payload: any = this.jwt.verify(token, {
        secret: this.config.tokenSecret,
        audience: this.config.mcpResource,
        issuer: this.config.issuer,
      });
      if (payload?.gid) await this.revokeGrant(payload.gid, 'revocation requested');
    } catch {
      // RFC 7009: an unknown token is not an error.
    }
  }

  // ─── Token exchange, for the MCP resource only ────────────────────────────

  /**
   * Turn a verified OAuth access token into a short-lived Nairon session JWT.
   *
   * This is the hinge of the whole design. The OAuth token is a credential for
   * one resource, signed with a key no domain service knows; what comes back
   * is an ordinary Nairon user token of the shape every existing guard already
   * verifies. Nothing downstream learns that OAuth was involved, and nothing
   * downstream has to change.
   *
   * The entity comes from the grant row — written when the person chose it at
   * consent — and never from the caller.
   */
  async exchangeForInternalToken(accessToken: string) {
    let payload: any;
    try {
      payload = this.jwt.verify(accessToken, {
        secret: this.config.tokenSecret,
        audience: this.config.mcpResource,
        issuer: this.config.issuer,
      });
    } catch (error) {
      const expired = (error as Error)?.name === 'TokenExpiredError';
      throw new OAuthError(
        expired ? 'expired_token' : 'invalid_token',
        expired ? 'the access token has expired' : 'the access token is not valid here',
        401,
      );
    }
    if (payload?.typ !== 'mcp_access') {
      throw new OAuthError('invalid_token', 'wrong token type', 401);
    }

    const grant = await this.prisma.oAuthGrant.findUnique({
      where: { id: String(payload.gid ?? '') },
      include: {
        user: { select: { id: true, email: true, firstName: true, lastName: true, deactivatedAt: true } },
      },
    });
    if (!grant || grant.revokedAt) {
      throw new OAuthError('invalid_token', 'this access has been revoked', 401);
    }
    if (String(grant.userId) !== String(payload.sub)) {
      throw new OAuthError('invalid_token', 'token does not match its grant', 401);
    }
    if (grant.user.deactivatedAt) {
      throw new OAuthError('invalid_token', 'this account is inactive', 401);
    }

    // Signed with the Nairon secret, in the shape login produces, so the
    // gateway and every domain guard accept it with no change whatsoever.
    const internalToken = this.jwt.sign(
      { id: grant.user.id, email: grant.user.email, src: 'mcp-oauth' },
      { secret: jwtConstants.secret, expiresIn: this.config.internalTokenTtlSec },
    );

    return {
      access_token: internalToken,
      token_type: 'Bearer',
      expires_in: this.config.internalTokenTtlSec,
      entity_id: grant.entityId,
      subject: {
        id: grant.user.id,
        email: grant.user.email,
        firstName: grant.user.firstName,
        lastName: grant.user.lastName,
      },
    };
  }
}
