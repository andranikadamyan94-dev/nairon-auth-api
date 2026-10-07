import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { M } from '../constants/messages';
import { JwtService } from '@nestjs/jwt';
import { AuthPrismaService } from '../prisma.service';
import * as bcrypt from 'bcryptjs';
import { AI_DOCK_PERMISSIONS } from '../permissions/permissions.service';
import {
  ONE_TIME_PASSWORD_SESSION_TTL_SEC,
  isOneTimePasswordToken,
  oneTimePasswordSessionsEnabled,
} from './one-time-password';

/**
 * The session's capability marker for the AI dock (2026-10-06): `user.aiDockPermissions: true` while the catalogue
 * holds all nine dock rows (migration 20261006120000_ai_dock_permissions, and the start-up seed). With it the dock
 * reads the nine literally — a role with one unticked has that control off. Without it (an older auth-api, or the
 * rows missing) the dock keeps every control on, as before.
 */
export const AI_DOCK_MARKER = 'aiDockPermissions';

/** The user record every session response carries: roles, their permissions. */
const USER_SESSION_INCLUDE = {
  roles: {
    include: {
      role: {
        include: {
          permissions: { include: { permission: true } },
        },
      },
    },
  },
} as const;

@Injectable()
export class AuthService {
  constructor(
    private prisma: AuthPrismaService,
    private jwtService: JwtService,
  ) {}

  /** Once all nine rows are seen they stay (rows are never removed); until then, re-read at most every 60 s. */
  private dockCatalogue: { present: boolean; checkedAt: number } | null = null;

  async aiDockCatalogue(): Promise<boolean> {
    const now = Date.now();
    if (this.dockCatalogue && (this.dockCatalogue.present || now - this.dockCatalogue.checkedAt < 60_000)) {
      return this.dockCatalogue.present;
    }
    try {
      const count = await this.prisma.permission.count({ where: { name: { in: [...AI_DOCK_PERMISSIONS] } } });
      this.dockCatalogue = { present: count === AI_DOCK_PERMISSIONS.length, checkedAt: now };
      return this.dockCatalogue.present;
    } catch {
      // Never fails a sign-in: no marker is the old behaviour (every dock control on), and the next call asks again.
      return false;
    }
  }

  /**
   * Every session response: the token and the user, plus — when the catalogue is there — `aiDockPermissions: true`
   * at the top level (beside access_token) and on `user`, a strict boolean. Absent otherwise, never `false`.
   */
  private async session<T extends object>(access_token: string, payload: T) {
    if (!(await this.aiDockCatalogue())) return { access_token, user: payload };
    return { access_token, [AI_DOCK_MARKER]: true as const, user: { ...payload, [AI_DOCK_MARKER]: true as const } };
  }

  /**
   * The session token for this account. With ONE_TIME_PASSWORD_SESSIONS on, an
   * account in one-time-password state gets `otp: true` and one hour
   * (one-time-password.ts); every other session is exactly as before.
   */
  private async sessionToken(user: { id: number; email: string; isOneTimePassword?: boolean | null }) {
    if (oneTimePasswordSessionsEnabled() && user.isOneTimePassword === true) {
      return this.jwtService.signAsync(
        { id: user.id, email: user.email, otp: true },
        { expiresIn: ONE_TIME_PASSWORD_SESSION_TTL_SEC },
      );
    }
    return this.jwtService.signAsync({ id: user.id, email: user.email });
  }

  async signIn(email: string, pass: string) {
    const user = await this.prisma.user.findFirst({
      where: { email: email.toLowerCase().trim() },
      include: USER_SESSION_INCLUDE,
    });
    if (!user || !bcrypt.compareSync(pass, user.password)) {
      throw new BadRequestException(M.auth.invalidCredentials);
    }
    // Checked after the password so a wrong password on a deactivated account
    // still reads as bad credentials — the message must not tell an outsider
    // which addresses are real accounts.
    if (user.deactivatedAt) {
      throw new UnauthorizedException(M.auth.deactivated);
    }
    const { password, ...payload } = user;
    // No admin claim in the token: super-admin (level-0 role) is entity-scoped,
    // so every service resolves it per request against the selected entity.
    return this.session(await this.sessionToken(user), payload);
  }

  async getMe(token: string) {
    try {
      const decoded = await this.jwtService.verifyAsync(token);
      const user = await this.prisma.user.findUnique({
        where: { id: decoded.id },
        include: USER_SESSION_INCLUDE,
      });
      // A token issued before deactivation stays cryptographically valid for
      // its full 30 days, so the check has to happen here on every restore.
      if (!user || user.deactivatedAt) throw new UnauthorizedException();
      // A one-time-password session ends when the account leaves that state:
      // it is never upgraded, so the person signs in again with the password
      // they have just set. Judged whatever the flag says — a marked token
      // exists only if the flag was on when it was minted.
      if (isOneTimePasswordToken(decoded) && user.isOneTimePassword !== true) throw new UnauthorizedException();
      // And an unmarked session of an account that is in that state — one
      // from before the flag, or from before an admin set a one-time password
      // — ends too: signing in again gives the restricted session.
      if (oneTimePasswordSessionsEnabled() && !isOneTimePasswordToken(decoded) && user.isOneTimePassword === true) {
        throw new UnauthorizedException();
      }
      const { password, ...payload } = user;
      return await this.session(token, payload);
    } catch {
      throw new UnauthorizedException();
    }
  }

  /**
   * A fresh session for a person already proven by other means — the
   * cross-app handoff code (handoff/). Same shape and same token claims as
   * signIn; null for an unknown or deactivated account.
   */
  async sessionForUser(id: number) {
    const user = await this.prisma.user.findUnique({
      where: { id },
      include: USER_SESSION_INCLUDE,
    });
    if (!user || user.deactivatedAt) return null;
    const { password, ...payload } = user;
    // The same rule as signIn: a handoff never turns a one-time-password
    // account into a full session in the next app.
    return this.session(await this.sessionToken(user), payload);
  }
}
