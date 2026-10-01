import { ForbiddenException, Injectable, Logger, ServiceUnavailableException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { randomUUID } from 'crypto';

import { jwtConstants } from '../auth/constants';
import { AuthPrismaService } from '../prisma.service';
import {
  DELEGATED_SCOPE_READ,
  DELEGATED_TOKEN_SRC,
  DELEGATED_TOKEN_TTL_SEC,
  DelegatedActClaim,
  DelegatedTokenClaims,
  DelegatedTokenRequest,
  REQUIRED_PERMISSIONS,
  actClaimFor,
} from './delegated-token.contract';
import {
  DELEGATED_WRITE_TOKEN_TTL_SEC,
  DelegatedWriteActClaim,
  DelegatedWriteTokenClaims,
  DelegatedWriteTokenRequest,
  WRITE_REQUIRED_AI_PERMISSIONS,
  WRITE_TOOLS,
  writeScopeFor,
} from './delegated-write-token.contract';

/** Why a mint was refused. ai-api reads `reason`; every one of them means "suspend, do not retry". */
export type DelegationRefusal =
  | 'user_not_found'
  | 'user_inactive'
  | 'missing_permission'
  | 'missing_tool_permission'
  | 'no_organisation_access';

export interface DelegatedWriteTokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  scope: string;
  entity_id: number;
  act: DelegatedWriteActClaim;
}

export interface DelegatedTokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  scope: typeof DELEGATED_SCOPE_READ;
  entity_id: number;
  act: DelegatedActClaim;
}

function refuse(reason: DelegationRefusal, extra: Record<string, unknown> = {}): never {
  throw new ForbiddenException({ statusCode: 403, error: 'delegation_refused', reason, ...extra });
}

/**
 * Mints the delegated read token, re-reading the person every time.
 *
 * Three questions, all asked fresh, and a refusal on any of them:
 *   1. Is the account still there and active?
 *   2. Does the person still hold the AI rights, literally, in that organisation?
 *   3. Does Nairon still let the person into that organisation at all?
 *
 * The third is asked of hr-api — the endpoint the entity switcher uses — and
 * not recomputed here, for the reason OAuthService.workspacesFor documents:
 * membership comes from the org tree and department placements, and a second
 * model in this service would drift from it. Unlike the consent screen,
 * though, "hr-api did not answer" is kept apart from "not a member": the
 * first is a 503 (retry the run later), only the second suspends a goal.
 */
@Injectable()
export class DelegatedTokenService {
  private readonly logger = new Logger(DelegatedTokenService.name);

  constructor(
    private readonly prisma: AuthPrismaService,
    private readonly jwt: JwtService,
  ) {}

  async mint(req: DelegatedTokenRequest): Promise<DelegatedTokenResponse> {
    const act = actClaimFor(req);
    const label = `user=${req.userId} entity=${req.entityId} act=${act.sub}`;

    const user = await this.prisma.user.findUnique({
      where: { id: req.userId },
      select: { id: true, email: true, deactivatedAt: true },
    });
    if (!user) return this.refused(label, 'user_not_found');
    if (user.deactivatedAt) return this.refused(label, 'user_inactive');

    const held = await this.permissionNames(user.id, req.entityId);
    const missing = REQUIRED_PERMISSIONS[req.actor].filter((p) => !held.has(p));
    if (missing.length) return this.refused(label, 'missing_permission', { missing });

    const organisations = await this.organisationsOf(user.id, user.email);
    if (!organisations.includes(req.entityId)) return this.refused(label, 'no_organisation_access');

    const claims: DelegatedTokenClaims = {
      id: user.id,
      email: user.email,
      sub: String(user.id),
      entityId: req.entityId,
      scope: DELEGATED_SCOPE_READ,
      act,
      src: DELEGATED_TOKEN_SRC,
    };
    const jti = randomUUID();
    // The same key and algorithm as a login token (JwtModule's HS256 with
    // JWT_SECRET); only the lifetime is set here, and it is five minutes.
    const token = await this.jwt.signAsync(claims, {
      secret: jwtConstants.secret,
      expiresIn: DELEGATED_TOKEN_TTL_SEC,
      jwtid: jti,
    });

    // Never the token itself.
    this.logger.log(`delegated token minted ${label} jti=${jti}`);
    return {
      access_token: token,
      token_type: 'Bearer',
      expires_in: DELEGATED_TOKEN_TTL_SEC,
      scope: DELEGATED_SCOPE_READ,
      entity_id: req.entityId,
      act,
    };
  }

  /**
   * The V3.4 write identity: one standing approval, one tool, one organisation,
   * two minutes (delegated-write-token.contract.ts). The same three questions
   * as a read mint, asked fresh, plus two:
   *   4. the AI write and standing-approval switches, literally;
   *   5. the business right the tool's own domain route accepts, literally.
   * Super admin stands in for none of them. Any "no" is `delegation_refused`,
   * which ai-api reads as "revoke this approval" — never a retry.
   */
  async mintWrite(req: DelegatedWriteTokenRequest): Promise<DelegatedWriteTokenResponse> {
    const scope = writeScopeFor(req.tool, req.approvalId);
    const act: DelegatedWriteActClaim = { sub: 'ai-goal', goalId: req.goalId, runId: req.runId, approvalId: req.approvalId };
    const label = `user=${req.userId} entity=${req.entityId} act=ai-goal:write tool=${req.tool} approval=${req.approvalId}`;

    const user = await this.prisma.user.findUnique({
      where: { id: req.userId },
      select: { id: true, email: true, deactivatedAt: true },
    });
    if (!user) return this.refused(label, 'user_not_found');
    if (user.deactivatedAt) return this.refused(label, 'user_inactive');

    const held = await this.permissionNames(user.id, req.entityId);
    const missing = WRITE_REQUIRED_AI_PERMISSIONS.filter((p) => !held.has(p));
    if (missing.length) return this.refused(label, 'missing_permission', { missing });
    const toolRights = WRITE_TOOLS[req.tool]?.anyOf;
    // parse already refused an unknown tool; a missing entry here is still a no, never a pass.
    if (!toolRights) return this.refused(label, 'missing_tool_permission');
    if (toolRights.length && !toolRights.some((p) => held.has(p))) {
      return this.refused(label, 'missing_tool_permission', { anyOf: [...toolRights] });
    }

    const organisations = await this.organisationsOf(user.id, user.email);
    if (!organisations.includes(req.entityId)) return this.refused(label, 'no_organisation_access');

    const claims: DelegatedWriteTokenClaims = {
      id: user.id,
      email: user.email,
      sub: String(user.id),
      entityId: req.entityId,
      scope,
      act,
      src: DELEGATED_TOKEN_SRC,
    };
    const jti = randomUUID();
    const token = await this.jwt.signAsync(claims, {
      secret: jwtConstants.secret,
      expiresIn: DELEGATED_WRITE_TOKEN_TTL_SEC,
      jwtid: jti,
    });

    // Never the token itself.
    this.logger.log(`delegated WRITE token minted ${label} jti=${jti}`);
    return {
      access_token: token,
      token_type: 'Bearer',
      expires_in: DELEGATED_WRITE_TOKEN_TTL_SEC,
      scope,
      entity_id: req.entityId,
      act,
    };
  }

  private refused(label: string, reason: DelegationRefusal, extra: Record<string, unknown> = {}): never {
    this.logger.warn(`delegated token refused ${label} reason=${reason}`);
    return refuse(reason, extra);
  }

  /**
   * The person's grants in one organisation.
   *
   * The rule crm-api, hr-api and ai-api all use: an assignment applies when
   * its entity is this one or 0 (everywhere), and a role's grant applies when
   * its entity is this one or 0. Super admin is deliberately not consulted —
   * it stands in for business rights, not for enrolment in the assistant.
   */
  private async permissionNames(userId: number, entityId: number): Promise<Set<string>> {
    const assignments = await this.prisma.userRole.findMany({
      where: { userId, entityId: { in: [0, entityId] } },
      select: {
        role: {
          select: {
            permissions: {
              where: { entityId: { in: [0, entityId] } },
              select: { permission: { select: { name: true } } },
            },
          },
        },
      },
    });
    const names = new Set<string>();
    for (const a of assignments) {
      for (const rp of a.role?.permissions ?? []) {
        const name = rp.permission?.name;
        if (name && name !== '_entity_configured_') names.add(name);
      }
    }
    return names;
  }

  /**
   * The organisations the person may enter, as hr-api answers the entity
   * switcher. Asked as the person with a one-minute token that never leaves
   * this method (the pattern OAuthService.workspacesFor established).
   */
  private async organisationsOf(userId: number, email: string): Promise<number[]> {
    const base = process.env.HR_API_URL?.trim().replace(/\/+$/, '');
    if (!base) {
      this.logger.error('HR_API_URL is not set — organisation membership cannot be checked, so no delegated token is issued.');
      throw new ServiceUnavailableException({ statusCode: 503, error: 'membership_unavailable' });
    }

    const probe = this.jwt.sign(
      { id: userId, email, src: 'ai-delegated-membership' },
      { secret: jwtConstants.secret, expiresIn: 60 },
    );

    let rows: unknown;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);
      const response = await fetch(`${base}/api/entities`, {
        headers: { authorization: `Bearer ${probe}` },
        signal: controller.signal,
      }).finally(() => clearTimeout(timer));
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      rows = await response.json();
    } catch (error) {
      this.logger.error(`organisation membership lookup failed: ${(error as Error).message}`);
      throw new ServiceUnavailableException({ statusCode: 503, error: 'membership_unavailable' });
    }

    if (!Array.isArray(rows)) {
      throw new ServiceUnavailableException({ statusCode: 503, error: 'membership_unavailable' });
    }
    return rows
      .map((r: any) => r?.id)
      .filter((id): id is number => Number.isInteger(id) && id > 0);
  }
}
